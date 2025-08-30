defmodule Vaultx.Sys.InitTest do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Sys.Init
  alias Vaultx.Base.Error

  # Sample initialization response from Vault
  @init_response %{
    "keys" => [
      "abcd1234567890abcdef1234567890abcdef12",
      "efgh5678901234567890abcdef1234567890ab",
      "ijkl9012345678901234567890abcdef123456",
      "mnop3456789012345678901234567890abcdef",
      "qrst7890123456789012345678901234567890"
    ],
    "keys_base64" => [
      "YWJjZDEyMzQ1Njc4OTBhYmNkZWYxMjM0NTY3ODkwYWJjZGVmMTI=",
      "ZWZnaDU2Nzg5MDEyMzQ1Njc4OTBhYmNkZWYxMjM0NTY3ODkwYWI=",
      "aWprbDkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTBhYmNkZWYxMjM0NTY=",
      "bW5vcDM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTBhYmNkZWY=",
      "cXJzdDc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTA="
    ],
    "root_token" => "hvs.1234567890abcdef1234567890abcdef"
  }

  # Sample initialization response with recovery keys (Enterprise)
  @init_response_with_recovery Map.merge(@init_response, %{
                                 "recovery_keys" => [
                                   "recovery1234567890abcdef1234567890ab",
                                   "recovery5678901234567890abcdef123456",
                                   "recovery9012345678901234567890abcdef"
                                 ],
                                 "recovery_keys_base64" => [
                                   "cmVjb3ZlcnkxMjM0NTY3ODkwYWJjZGVmMTIzNDU2Nzg5MGFi",
                                   "cmVjb3Zlcnk1Njc4OTAxMjM0NTY3ODkwYWJjZGVmMTIzNDU2",
                                   "cmVjb3Zlcnk5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwYWJjZGVm"
                                 ]
                               })

  # Sample status responses
  @status_initialized %{"initialized" => true}
  @status_uninitialized %{"initialized" => false}

  describe "initialize/2" do
    test "initializes Vault with basic options" do
      expect_post(200, @init_response, fn _url, body, _opts ->
        assert body["secret_shares"] == 5
        assert body["secret_threshold"] == 3
        refute Map.has_key?(body, "pgp_keys")
        refute Map.has_key?(body, "root_token_pgp_key")
      end)

      opts = %{
        secret_shares: 5,
        secret_threshold: 3
      }

      assert {:ok, result} = Init.initialize(opts)
      assert length(result.keys) == 5
      assert length(result.keys_base64) == 5
      assert result.root_token == "hvs.1234567890abcdef1234567890abcdef"
      refute Map.has_key?(result, :recovery_keys)
    end

    test "initializes Vault with PGP encryption" do
      pgp_keys = [
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\nkey1\n-----END PGP PUBLIC KEY BLOCK-----",
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\nkey2\n-----END PGP PUBLIC KEY BLOCK-----",
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\nkey3\n-----END PGP PUBLIC KEY BLOCK-----"
      ]

      root_token_pgp_key =
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\nroot\n-----END PGP PUBLIC KEY BLOCK-----"

      expect_post(200, @init_response, fn _url, body, _opts ->
        assert body["secret_shares"] == 3
        assert body["secret_threshold"] == 2
        assert body["pgp_keys"] == pgp_keys
        assert body["root_token_pgp_key"] == root_token_pgp_key
      end)

      opts = %{
        secret_shares: 3,
        secret_threshold: 2,
        pgp_keys: pgp_keys,
        root_token_pgp_key: root_token_pgp_key
      }

      assert {:ok, result} = Init.initialize(opts)
      assert length(result.keys) == 5
      assert result.root_token == "hvs.1234567890abcdef1234567890abcdef"
    end

    test "initializes Vault with recovery keys (Enterprise)" do
      expect_post(200, @init_response_with_recovery, fn _url, body, _opts ->
        assert body["secret_shares"] == 5
        assert body["secret_threshold"] == 3
        assert body["recovery_shares"] == 3
        assert body["recovery_threshold"] == 2
      end)

      opts = %{
        secret_shares: 5,
        secret_threshold: 3,
        recovery_shares: 3,
        recovery_threshold: 2
      }

      assert {:ok, result} = Init.initialize(opts)
      assert length(result.keys) == 5
      assert length(result.recovery_keys) == 3
      assert length(result.recovery_keys_base64) == 3
    end

    test "returns error for missing required fields" do
      # Missing secret_shares
      opts = %{secret_threshold: 3}
      assert {:error, %Error{type: :invalid_parameter}} = Init.initialize(opts)

      # Missing secret_threshold
      opts = %{secret_shares: 5}
      assert {:error, %Error{type: :invalid_parameter}} = Init.initialize(opts)

      # Missing both
      opts = %{}
      assert {:error, %Error{type: :invalid_parameter}} = Init.initialize(opts)
    end

    test "validates threshold constraints" do
      # secret_shares too low
      opts = %{secret_shares: 0, secret_threshold: 1}
      assert {:error, %Error{type: :invalid_parameter}} = Init.initialize(opts)

      # secret_threshold too low
      opts = %{secret_shares: 5, secret_threshold: 0}
      assert {:error, %Error{type: :invalid_parameter}} = Init.initialize(opts)

      # threshold exceeds shares
      opts = %{secret_shares: 3, secret_threshold: 5}
      assert {:error, %Error{type: :invalid_parameter}} = Init.initialize(opts)
    end

    test "validates PGP keys count" do
      # Wrong number of PGP keys
      opts = %{
        secret_shares: 5,
        secret_threshold: 3,
        # Should be 5 keys
        pgp_keys: ["key1", "key2"]
      }

      assert {:error, %Error{type: :invalid_parameter}} = Init.initialize(opts)

      # Invalid PGP keys format
      opts = %{
        secret_shares: 3,
        secret_threshold: 2,
        pgp_keys: "not_a_list"
      }

      assert {:error, %Error{type: :invalid_parameter}} = Init.initialize(opts)
    end

    test "handles server errors" do
      expect_post(400, %{"errors" => ["Vault is already initialized"]})

      opts = %{
        secret_shares: 5,
        secret_threshold: 3
      }

      assert {:error, %Error{type: :server_error}} = Init.initialize(opts)
    end

    test "handles network errors" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      opts = %{
        secret_shares: 5,
        secret_threshold: 3
      }

      assert {:error, %Error{type: :unknown_error}} = Init.initialize(opts)
    end

    test "passes timeout option to HTTP layer" do
      expect_post(200, @init_response, fn _url, _body, opts ->
        assert opts[:timeout] == 60_000
      end)

      init_opts = %{
        secret_shares: 5,
        secret_threshold: 3
      }

      assert {:ok, _result} = Init.initialize(init_opts, timeout: 60_000)
    end
  end

  describe "status/1" do
    test "returns initialized status when Vault is initialized" do
      expect_get(200, @status_initialized)

      assert {:ok, status} = Init.status()
      assert status.initialized == true
    end

    test "returns uninitialized status when Vault is not initialized" do
      expect_get(200, @status_uninitialized)

      assert {:ok, status} = Init.status()
      assert status.initialized == false
    end

    test "handles server errors" do
      expect_get(500, %{"errors" => ["Internal server error"]})

      assert {:error, %Error{type: :server_error}} = Init.status()
    end

    test "handles network errors" do
      stub_request_raw(:get, %Req.TransportError{reason: :connection_refused})

      assert {:error, %Error{type: :unknown_error}} = Init.status()
    end

    test "passes timeout option to HTTP layer" do
      expect_get(200, @status_initialized, fn _url, _body, opts ->
        assert opts[:timeout] == 30_000
      end)

      assert {:ok, _status} = Init.status(timeout: 30_000)
    end
  end

  describe "edge cases and error handling" do
    test "handles empty response body gracefully" do
      expect_post(200, %{})

      opts = %{
        secret_shares: 5,
        secret_threshold: 3
      }

      assert {:ok, result} = Init.initialize(opts)
      assert result.keys == []
      assert result.keys_base64 == []
      assert result.root_token == ""
    end

    test "handles missing fields in response" do
      minimal_response = %{
        "keys" => ["key1", "key2"],
        "root_token" => "hvs.token"
      }

      expect_post(200, minimal_response)

      opts = %{
        secret_shares: 2,
        secret_threshold: 1
      }

      assert {:ok, result} = Init.initialize(opts)
      assert result.keys == ["key1", "key2"]
      # Default empty list
      assert result.keys_base64 == []
      assert result.root_token == "hvs.token"
    end

    test "handles nil values in status response" do
      response_with_nil = %{"initialized" => nil}

      expect_get(200, response_with_nil)

      assert {:ok, status} = Init.status()
      # nil becomes false
      assert status.initialized == false
    end
  end

  describe "request building" do
    test "includes extra fields in request body" do
      expect_post(200, @init_response, fn _url, body, _opts ->
        assert body["secret_shares"] == 3
        assert body["secret_threshold"] == 2
        assert body["stored_shares"] == 1
        assert body["recovery_shares"] == 3
        assert body["recovery_threshold"] == 2
      end)

      opts = %{
        secret_shares: 3,
        secret_threshold: 2,
        stored_shares: 1,
        recovery_shares: 3,
        recovery_threshold: 2
      }

      assert {:ok, _result} = Init.initialize(opts)
    end
  end
end
