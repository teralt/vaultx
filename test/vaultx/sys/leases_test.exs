defmodule Vaultx.Sys.LeasesTest do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Sys.Leases
  alias Vaultx.Base.Error

  # Sample lease lookup response from Vault
  @lease_lookup_response %{
    "id" => "aws/creds/deploy/abcd-1234",
    "issue_time" => "2025-01-01T12:00:00Z",
    "expire_time" => "2025-01-01T13:00:00Z",
    "last_renewal_time" => "2025-01-01T12:30:00Z",
    "renewable" => true,
    "ttl" => 1800
  }

  # Sample lease renewal response from Vault
  @lease_renewal_response %{
    "lease_id" => "aws/creds/deploy/abcd-1234",
    "renewable" => true,
    "lease_duration" => 3600
  }

  # Sample lease list response from Vault
  @lease_list_response %{
    "data" => %{
      "keys" => ["aws/creds/deploy/abcd-1234", "aws/creds/deploy/efgh-5678"]
    }
  }

  describe "lookup/2" do
    test "returns lease information successfully" do
      expect_post(200, @lease_lookup_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/leases/lookup")
        assert body["lease_id"] == "aws/creds/deploy/abcd-1234"
      end)

      assert {:ok, lease} = Leases.lookup("aws/creds/deploy/abcd-1234")
      assert lease.id == "aws/creds/deploy/abcd-1234"
      assert lease.issue_time == "2025-01-01T12:00:00Z"
      assert lease.expire_time == "2025-01-01T13:00:00Z"
      assert lease.last_renewal_time == "2025-01-01T12:30:00Z"
      assert lease.renewable == true
      assert lease.ttl == 1800
    end

    test "returns error for non-existent lease" do
      expect_post(404, %{"errors" => ["lease not found"]})

      assert {:error, %Error{type: :not_found}} = Leases.lookup("non-existent")
    end

    test "wraps network errors" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{type: :unknown_error}} = Leases.lookup("aws/creds/deploy/abcd-1234")
    end
  end

  describe "renew/3" do
    test "renews lease successfully with increment" do
      expect_post(200, @lease_renewal_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/leases/renew")
        assert body["lease_id"] == "aws/creds/deploy/abcd-1234"
        assert body["increment"] == 3600
      end)

      assert {:ok, renewal} = Leases.renew("aws/creds/deploy/abcd-1234", 3600)
      assert renewal.lease_id == "aws/creds/deploy/abcd-1234"
      assert renewal.renewable == true
      assert renewal.lease_duration == 3600
    end

    test "renews lease successfully with default increment" do
      expect_post(200, @lease_renewal_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/leases/renew")
        assert body["lease_id"] == "aws/creds/deploy/abcd-1234"
        # default increment
        assert body["increment"] == 0
      end)

      assert {:ok, renewal} = Leases.renew("aws/creds/deploy/abcd-1234")
      assert renewal.lease_id == "aws/creds/deploy/abcd-1234"
    end

    test "returns error for non-existent lease" do
      expect_post(404, %{"errors" => ["lease not found"]})

      assert {:error, %Error{type: :not_found}} = Leases.renew("non-existent-lease")
    end

    test "wraps network errors" do
      stub_request_raw(:post, %Req.TransportError{reason: :econnrefused})

      assert {:error, %Error{type: :unknown_error}} = Leases.renew("aws/creds/deploy/abcd-1234")
    end
  end

  describe "revoke/2" do
    test "revokes lease successfully" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/leases/revoke")
        assert body["lease_id"] == "aws/creds/deploy/abcd-1234"
      end)

      assert :ok = Leases.revoke("aws/creds/deploy/abcd-1234")
    end

    test "handles successful revocation with 200 status" do
      expect_post(200, %{})

      assert :ok = Leases.revoke("aws/creds/deploy/abcd-1234")
    end

    test "revokes lease synchronously" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/leases/revoke")
        assert body["lease_id"] == "aws/creds/deploy/abcd-1234"
        assert body["sync"] == true
      end)

      assert :ok = Leases.revoke("aws/creds/deploy/abcd-1234", sync: true)
    end

    test "wraps network errors" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{type: :unknown_error}} = Leases.revoke("aws/creds/deploy/abcd-1234")
    end
  end

  describe "list/2" do
    test "lists leases by prefix successfully" do
      expect_get(200, @lease_list_response, fn url, _body, _opts ->
        assert String.contains?(url, "sys/leases/lookup/aws/creds/deploy")
        assert String.contains?(url, "list=true")
      end)

      assert {:ok, leases} = Leases.list("aws/creds/deploy/")
      assert leases == ["aws/creds/deploy/abcd-1234", "aws/creds/deploy/efgh-5678"]
    end

    test "handles empty lease list" do
      expect_get(200, %{"data" => %{"keys" => []}})

      assert {:ok, leases} = Leases.list("empty/prefix/")
      assert leases == []
    end

    test "handles missing keys field (empty result)" do
      expect_get(200, %{"data" => %{}})

      assert {:ok, leases} = Leases.list("empty/prefix/")
      assert leases == []
    end

    test "handles 404 status (no leases found)" do
      expect_get(404, %{"errors" => ["no leases found"]})

      assert {:ok, leases} = Leases.list("nonexistent/prefix/")
      assert leases == []
    end

    test "wraps network errors" do
      stub_request_raw(:get, %Req.TransportError{reason: :econnrefused})

      assert {:error, %Error{type: :unknown_error}} = Leases.list("aws/creds/deploy/")
    end
  end

  describe "revoke_prefix/2" do
    test "revokes leases by prefix successfully (async by default)" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/leases/revoke-prefix/aws/creds/deploy")
        # no sync parameter when async
        assert body == %{}
      end)

      assert :ok = Leases.revoke_prefix("aws/creds/deploy/")
    end

    test "revokes leases synchronously" do
      expect_post(200, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/leases/revoke-prefix/aws/creds/deploy")
        assert body["sync"] == true
      end)

      assert :ok = Leases.revoke_prefix("aws/creds/deploy/", sync: true)
    end

    test "revokes leases synchronously with explicit true" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/leases/revoke-prefix/aws/creds/deploy")
        assert body["sync"] == true
      end)

      # Test with explicit sync: true to cover the build_sync_payload function
      assert :ok = Leases.revoke_prefix("aws/creds/deploy/", sync: true)
    end

    test "revokes leases asynchronously with explicit false" do
      expect_post(200, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/leases/revoke-prefix/aws/creds/deploy")
        # no sync parameter when async
        assert body == %{}
      end)

      # Test with explicit sync: false to cover all branches
      assert :ok = Leases.revoke_prefix("aws/creds/deploy/", sync: false)
    end

    test "revokes leases with nil sync option" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/leases/revoke-prefix/aws/creds/deploy")
        # nil sync should result in no sync parameter (default false)
        assert body == %{}
      end)

      # Test with nil sync to cover the default case
      assert :ok = Leases.revoke_prefix("aws/creds/deploy/", sync: nil)
    end

    test "wraps network errors" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{type: :unknown_error}} = Leases.revoke_prefix("aws/creds/deploy/")
    end
  end

  describe "revoke_force/2" do
    test "force revokes leases by prefix successfully" do
      expect_post(204, %{}, fn url, _body, _opts ->
        assert String.contains?(url, "sys/leases/revoke-force/aws/creds/deploy")
      end)

      assert :ok = Leases.revoke_force("aws/creds/deploy/")
    end

    test "wraps network errors" do
      stub_request_raw(:post, %Req.TransportError{reason: :econnrefused})

      assert {:error, %Error{type: :unknown_error}} = Leases.revoke_force("aws/creds/deploy/")
    end
  end

  describe "tidy/1" do
    test "performs tidy operation successfully" do
      expect_post(204, %{}, fn url, _body, _opts ->
        assert String.contains?(url, "sys/leases/tidy")
      end)

      assert :ok = Leases.tidy()
    end

    test "wraps network errors" do
      stub_request_raw(:post, %Req.TransportError{reason: :econnrefused})

      assert {:error, %Error{type: :unknown_error}} = Leases.tidy()
    end
  end

  describe "edge cases and error handling" do
    test "handles missing fields in lease lookup response" do
      minimal_response = %{
        "id" => "test-lease",
        "renewable" => false
      }

      expect_post(200, minimal_response)

      assert {:ok, lease} = Leases.lookup("test-lease")
      assert lease.id == "test-lease"
      assert lease.renewable == false
      # default value
      assert lease.issue_time == ""
      # default value
      assert lease.expire_time == ""
      # default value
      assert lease.ttl == 0
    end

    test "handles nil values in lease response" do
      response_with_nils =
        Map.merge(@lease_lookup_response, %{
          "issue_time" => nil,
          "expire_time" => nil,
          "last_renewal_time" => nil
        })

      expect_post(200, response_with_nils)

      assert {:ok, lease} = Leases.lookup("aws/creds/deploy/abcd-1234")
      assert lease.issue_time == nil
      assert lease.expire_time == nil
      assert lease.last_renewal_time == nil
    end

    test "handles lease IDs with special characters" do
      lease_id = "aws/creds/my-app/deploy-v1.0"

      expect_post(200, %{@lease_lookup_response | "id" => lease_id}, fn _url, body, _opts ->
        assert body["lease_id"] == lease_id
      end)

      assert {:ok, lease} = Leases.lookup(lease_id)
      assert lease.id == lease_id
    end
  end

  describe "options handling" do
    test "passes through timeout option" do
      expect_post(200, @lease_lookup_response, fn _url, _body, opts ->
        assert opts[:timeout] == 60_000
      end)

      assert {:ok, _lease} = Leases.lookup("aws/creds/deploy/abcd-1234", timeout: 60_000)
    end

    test "passes through retry options" do
      expect_post(200, @lease_renewal_response, fn _url, _body, opts ->
        assert opts[:retry_attempts] == 3
      end)

      assert {:ok, _renewal} = Leases.renew("aws/creds/deploy/abcd-1234", 3600, retry_attempts: 3)
    end
  end
end
