defmodule Vaultx.ClientTest do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Client
  alias Vaultx.Base.Error

  describe "authenticate/2 (current placeholder)" do
    test "all methods return not_implemented" do
      for method <- [:app_role, :jwt, :aws, :token, :unsupported] do
        assert {:error, %Error{type: :not_implemented}} = Client.authenticate(method, %{})
      end
    end
  end

  describe "read/2" do
    test "KV v2 response shape (data.data)" do
      expect_get(200, %{"data" => %{"data" => %{"u" => "a"}}})

      assert {:ok, %{"u" => "a"}} = Client.read("secret/data/p")
    end

    test "KV v1 response shape (data)" do
      expect_get(200, %{"data" => %{"u" => "a"}})

      assert {:ok, %{"u" => "a"}} = Client.read("secret/p")
    end

    test "direct map body branch (cover fallback)" do
      expect_get(200, %{"k" => "v"})

      assert {:ok, %{"k" => "v"}} = Client.read("secret/direct")
    end

    test "non-2xx maps to not_found" do
      expect_get(404, %{"errors" => ["path not found"]})

      assert {:error, %Error{type: :not_found}} = Client.read("p")
    end

    test "invalid path -> invalid_request or message" do
      assert {:error, err} = Client.read(123)

      assert (is_binary(err) and String.contains?(err, "Path")) or
               match?(%Error{type: :invalid_request}, err)
    end

    test "network error branch" do
      stub_request(:get, :network_error, "down")

      assert {:error, %Error{type: :network_error}} = Client.read("p", retry_attempts: 0)
    end
  end

  describe "write/3" do
    test "KV v2 payload + CAS" do
      expect_post(200, %{"data" => %{"version" => 2}}, fn _url, decoded, _opts ->
        assert decoded["data"]["u"] == "a"
        assert decoded["options"]["cas"] == 2
      end)

      assert :ok = Client.write("secret/data/p", %{"u" => "a"}, cas: 2)
    end

    test "KV v1 payload (no options)" do
      expect_post(200, %{"data" => %{"version" => 1}}, fn _url, body, _opts ->
        assert is_map(body)
      end)

      assert :ok = Client.write("secret/p", %{"k" => "v"})
    end

    test "validates data is map" do
      assert {:error, %Error{type: :invalid_request}} = Client.write("p", "bad")
    end

    test "write error path (covers error logging)" do
      stub_request(:post, :network_error, "Connection failed")

      assert {:error, %Error{type: :network_error}} = Client.write("p", %{"k" => "v"})
    end
  end

  describe "delete/2" do
    test "success 204" do
      expect_delete(204, %{})

      assert :ok = Client.delete("p")
    end

    test "delete network error branch (covers delete Logger.error)" do
      stub_request(:delete, :network_error, "down")

      assert {:error, %Error{type: :network_error}} = Client.delete("p")
    end

    test "non-2xx -> not_found" do
      expect_delete(400, %{"errors" => ["cannot delete"]})

      assert {:error, %Error{type: :not_found}} = Client.delete("p")
    end
  end

  describe "list/2" do
    test "LIST nested keys" do
      expect_get(200, %{"data" => %{"keys" => ["a", "b"]}}, &assert_list_method/3)

      assert {:ok, ["a", "b"]} = Client.list("p/")
    end

    test "LIST flat keys" do
      expect_get(200, %{"data" => ["a", "b"]}, &assert_list_method/3)

      assert {:ok, ["a", "b"]} = Client.list("p/")
    end
  end

  describe "health/1" do
    test "ok + error" do
      expect_get(200, %{"ok" => true})

      assert {:ok, %{"ok" => true}} = Client.health()

      expect_get(503, %{"errors" => ["down"]})

      assert {:error, %Error{type: :server_error}} = Client.health()
    end

    stub_request(:get, :network_error, "down")

    assert {:error, %Error{type: :network_error}} = Client.health()
  end

  describe "seal_status/1" do
    test "ok + server + network errors" do
      expect_get(200, %{"sealed" => false})

      assert {:ok, %{"sealed" => false}} = Client.seal_status()

      expect_get(500, %{"errors" => ["internal"]})

      assert {:error, %Error{type: :server_error}} = Client.seal_status()

      stub_request(:get, :network_error, "fail")

      assert {:error, %Error{type: :network_error}} = Client.seal_status()
    end
  end

  describe "Error.user_message/1 edge branches" do
    test "http_error without vault_errors -> generic http message" do
      err = Error.new(:http_error, "low-level http failure", vault_errors: [])
      assert Error.user_message(err) == "HTTP protocol error occurred."
    end

    test "first vault error bubbles when exists" do
      err = Error.new(:server_error, "boom", vault_errors: ["first", "second"])
      assert Error.user_message(err) == "first"
    end

    test "fallback to message for other combos" do
      err = Error.new(:unknown_error, "opaque")
      assert Error.user_message(err) == "opaque"
    end
  end

  describe "Error.recoverable?/1 edge branches" do
    test "unknown atom -> false" do
      assert Error.recoverable?(:nonexistent_tag) == false
    end

    test "explicit mapping true/false are respected" do
      assert Error.recoverable?(:timeout)
      refute Error.recoverable?(:invalid_request)
      assert Error.recoverable?(:http_error)
    end
  end

  describe "additional coverage for client/http" do
    test "list error branch (covers list Logger.error)" do
      stub_request(:get, :network_error, "down")

      assert {:error, %Error{type: :network_error}} = Client.list("p/")
    end

    test "health success via data envelope (covers first success clause)" do
      expect_get_enveloped(200, %{"initialized" => true})

      assert {:ok, %{"initialized" => true}} = Client.health()
    end

    test "unexpected 2xx shape -> error branch (covers health Logger.error alt path)" do
      expect_get(200, "weird-body")

      assert {:error, %Error{type: :server_error}} = Client.health()
    end

    test "seal_status success via data envelope (covers first success clause)" do
      expect_get_enveloped(200, %{"sealed" => false})

      assert {:ok, %{"sealed" => false}} = Client.seal_status()
    end

    test "KV v2 write without CAS (covers formatted return)" do
      expect_post(200, %{"data" => %{"version" => 1}}, fn _url, decoded, _opts ->
        assert decoded["data"]["k"] == "v"
        refute Map.has_key?(decoded, "options")
      end)

      assert :ok = Client.write("secret/data/p", %{"k" => "v"})
    end

    test "HTTP retry path (1 attempt, minimal delay)" do
      stub_request(:get, :network_error, "down")

      # This will trigger one retry in HTTP layer
      assert {:error, %Error{type: :network_error}} =
               Client.read("p", retry_attempts: 1, retry_delay: 1)
    end
  end
end
