defmodule Vaultx.Sys.UnsealTest do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Sys.Unseal
  alias Vaultx.Base.Error

  # Sample unseal status responses
  @sealed_status %{
    "sealed" => true,
    "t" => 3,
    "n" => 5,
    "progress" => 1,
    "version" => "1.15.0"
  }

  @unsealed_status %{
    "sealed" => false,
    "t" => 3,
    "n" => 5,
    "progress" => 3,
    "version" => "1.15.0",
    "cluster_name" => "vault-cluster",
    "cluster_id" => "12345678-1234-1234-1234-123456789012"
  }

  @reset_status %{
    "sealed" => true,
    "t" => 3,
    "n" => 5,
    "progress" => 0,
    "version" => "1.15.0"
  }

  describe "submit_key/2" do
    test "submits unseal key successfully while sealed" do
      expect_post(200, @sealed_status, fn url, body, _opts ->
        assert String.contains?(url, "sys/unseal")
        assert body["key"] == "test-key-123"
        assert body["reset"] == false
        assert body["migrate"] == false
      end)

      assert {:ok, status} = Unseal.submit_key("test-key-123")
      assert status.sealed == true
      assert status.t == 3
      assert status.n == 5
      assert status.progress == 1
      assert status.version == "1.15.0"
    end

    test "submits final key and unseals vault" do
      expect_post(200, @unsealed_status, fn url, body, _opts ->
        assert String.contains?(url, "sys/unseal")
        assert body["key"] == "final-key-456"
      end)

      assert {:ok, status} = Unseal.submit_key("final-key-456")
      assert status.sealed == false
      assert status.progress == 3
      assert status.cluster_name == "vault-cluster"
      assert status.cluster_id == "12345678-1234-1234-1234-123456789012"
    end

    test "submits key with reset flag" do
      expect_post(200, @reset_status, fn url, body, _opts ->
        assert String.contains?(url, "sys/unseal")
        assert body["key"] == "reset-key-789"
        assert body["reset"] == true
        assert body["migrate"] == false
      end)

      assert {:ok, status} = Unseal.submit_key("reset-key-789", reset: true)
      assert status.sealed == true
      assert status.progress == 0
    end

    test "submits key with migrate flag" do
      expect_post(200, @sealed_status, fn url, body, _opts ->
        assert String.contains?(url, "sys/unseal")
        assert body["key"] == "migrate-key-abc"
        assert body["reset"] == false
        assert body["migrate"] == true
      end)

      assert {:ok, status} = Unseal.submit_key("migrate-key-abc", migrate: true)
      assert status.sealed == true
    end

    test "submits key with both reset and migrate flags" do
      expect_post(200, @reset_status, fn url, body, _opts ->
        assert String.contains?(url, "sys/unseal")
        assert body["key"] == "complex-key-def"
        assert body["reset"] == true
        assert body["migrate"] == true
      end)

      assert {:ok, _status} = Unseal.submit_key("complex-key-def", reset: true, migrate: true)
    end

    test "handles invalid key errors" do
      expect_post(400, %{"errors" => ["invalid key"]})

      assert {:error, %Error{} = error} = Unseal.submit_key("invalid-key")
      assert error.type == :server_error
      assert String.contains?(error.message, "Failed to submit unseal key")
    end

    test "handles network errors" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{} = error} = Unseal.submit_key("test-key")
      assert error.type == :unknown_error
    end

    test "handles empty key string" do
      expect_post(200, @sealed_status, fn _url, body, _opts ->
        assert body["key"] == ""
      end)

      assert {:ok, _status} = Unseal.submit_key("")
    end

    test "handles unicode characters in key" do
      unicode_key = "测试密钥🔐"

      expect_post(200, @sealed_status, fn _url, body, _opts ->
        assert body["key"] == unicode_key
      end)

      assert {:ok, _status} = Unseal.submit_key(unicode_key)
    end
  end

  describe "reset/1" do
    test "resets unseal process successfully" do
      expect_post(200, @reset_status, fn url, body, _opts ->
        assert String.contains?(url, "sys/unseal")
        assert body["reset"] == true
        refute Map.has_key?(body, "key")
      end)

      assert {:ok, status} = Unseal.reset()
      assert status.sealed == true
      assert status.progress == 0
    end

    test "handles reset errors" do
      expect_post(500, %{"errors" => ["internal server error"]})

      assert {:error, %Error{} = error} = Unseal.reset()
      assert error.type == :server_error
      assert String.contains?(error.message, "Failed to reset unseal process")
    end

    test "handles network errors during reset" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{} = error} = Unseal.reset()
      assert error.type == :unknown_error
    end

    test "passes custom options" do
      expect_post(200, @reset_status, fn _url, _body, opts ->
        assert opts[:timeout] == 30_000
      end)

      assert {:ok, _status} = Unseal.reset(timeout: 30_000)
    end
  end

  describe "submit_keys/2" do
    test "submits multiple keys until unsealed" do
      keys = ["key1", "key2", "key3"]

      # First key - progress 1
      expect_post(200, %{@sealed_status | "progress" => 1}, fn _url, body, _opts ->
        assert body["key"] == "key1"
      end)

      # Second key - progress 2
      expect_post(200, %{@sealed_status | "progress" => 2}, fn _url, body, _opts ->
        assert body["key"] == "key2"
      end)

      # Third key - unsealed
      expect_post(200, @unsealed_status, fn _url, body, _opts ->
        assert body["key"] == "key3"
      end)

      assert {:ok, final_status} = Unseal.submit_keys(keys)
      assert final_status.sealed == false
      assert final_status.progress == 3
    end

    test "submits all keys even when unsealed early with stop_on_unseal: false" do
      keys = ["key1", "key2", "key3"]

      # First key - unsealed immediately
      expect_post(200, @unsealed_status, fn _url, body, _opts ->
        assert body["key"] == "key1"
      end)

      # Second key - still unsealed
      expect_post(200, @unsealed_status, fn _url, body, _opts ->
        assert body["key"] == "key2"
      end)

      # Third key - still unsealed
      expect_post(200, @unsealed_status, fn _url, body, _opts ->
        assert body["key"] == "key3"
      end)

      assert {:ok, final_status} = Unseal.submit_keys(keys, stop_on_unseal: false)
      assert final_status.sealed == false
    end

    test "stops early when unsealed with default behavior" do
      keys = ["key1", "key2", "key3"]

      # First key - progress 1
      expect_post(200, %{@sealed_status | "progress" => 1}, fn _url, body, _opts ->
        assert body["key"] == "key1"
      end)

      # Second key - unsealed (should stop here)
      expect_post(200, @unsealed_status, fn _url, body, _opts ->
        assert body["key"] == "key2"
      end)

      # Third key should not be called

      assert {:ok, final_status} = Unseal.submit_keys(keys)
      assert final_status.sealed == false
    end

    test "handles error during batch submission" do
      keys = ["key1", "key2", "key3"]

      # First key - success
      expect_post(200, %{@sealed_status | "progress" => 1}, fn _url, body, _opts ->
        assert body["key"] == "key1"
      end)

      # Second key - error
      expect_post(400, %{"errors" => ["invalid key"]}, fn _url, body, _opts ->
        assert body["key"] == "key2"
      end)

      # Third key should not be called

      assert {:error, %Error{} = error} = Unseal.submit_keys(keys)
      assert error.type == :server_error
    end

    test "handles empty key list" do
      assert {:ok, nil} = Unseal.submit_keys([])
    end

    test "handles single key in list" do
      expect_post(200, @unsealed_status, fn _url, body, _opts ->
        assert body["key"] == "single-key"
      end)

      assert {:ok, status} = Unseal.submit_keys(["single-key"])
      assert status.sealed == false
    end

    test "passes migrate flag to all key submissions" do
      keys = ["key1", "key2"]

      Enum.each(keys, fn key ->
        expect_post(200, @sealed_status, fn _url, body, _opts ->
          assert body["key"] == key
          assert body["migrate"] == true
        end)
      end)

      assert {:ok, _status} = Unseal.submit_keys(keys, migrate: true)
    end
  end

  describe "edge cases and error scenarios" do
    test "handles malformed response structure" do
      malformed_response = %{
        "sealed" => "not_boolean",
        "t" => "not_integer",
        "progress" => nil
      }

      expect_post(200, malformed_response)

      assert {:ok, status} = Unseal.submit_key("test-key")
      # Should handle gracefully even with malformed data
      assert status.sealed == "not_boolean"
      assert status.t == "not_integer"
      assert status.progress == nil
    end

    test "handles missing fields in response" do
      minimal_response = %{
        "sealed" => true,
        "version" => "1.15.0"
      }

      expect_post(200, minimal_response)

      assert {:ok, status} = Unseal.submit_key("test-key")
      assert status.sealed == true
      assert status.version == "1.15.0"
      assert status.t == nil
    end

    test "handles various HTTP error codes" do
      error_codes = [400, 401, 403, 404, 500, 502, 503]

      Enum.each(error_codes, fn code ->
        expect_post(code, %{"errors" => ["error #{code}"]})

        assert {:error, %Error{} = error} = Unseal.submit_key("test-key")
        assert error.type == :server_error
        assert String.contains?(error.message, "HTTP #{code}")
      end)
    end

    test "handles very long key strings" do
      long_key = String.duplicate("a", 10000)

      expect_post(200, @sealed_status, fn _url, body, _opts ->
        assert body["key"] == long_key
      end)

      assert {:ok, _status} = Unseal.submit_key(long_key)
    end

    test "handles special characters in keys" do
      special_key = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~"

      expect_post(200, @sealed_status, fn _url, body, _opts ->
        assert body["key"] == special_key
      end)

      assert {:ok, _status} = Unseal.submit_key(special_key)
    end
  end

  describe "integration scenarios" do
    test "complete unseal workflow" do
      keys = ["key1", "key2", "key3"]

      # Step 1: Reset to start fresh
      expect_post(200, @reset_status, fn url, body, _opts ->
        assert String.contains?(url, "sys/unseal")
        assert body["reset"] == true
      end)

      assert {:ok, reset_status} = Unseal.reset()
      assert reset_status.progress == 0

      # Step 2: Submit keys one by one
      expect_post(200, %{@sealed_status | "progress" => 1}, fn _url, body, _opts ->
        assert body["key"] == "key1"
      end)

      expect_post(200, %{@sealed_status | "progress" => 2}, fn _url, body, _opts ->
        assert body["key"] == "key2"
      end)

      expect_post(200, @unsealed_status, fn _url, body, _opts ->
        assert body["key"] == "key3"
      end)

      assert {:ok, final_status} = Unseal.submit_keys(keys)
      assert final_status.sealed == false
      assert final_status.cluster_name == "vault-cluster"
    end

    test "migration unseal workflow" do
      migration_keys = ["migrate-key1", "migrate-key2", "migrate-key3"]

      migration_keys
      |> Enum.with_index(1)
      |> Enum.each(fn {key, progress} ->
        response =
          if progress == 3 do
            @unsealed_status
          else
            %{@sealed_status | "progress" => progress}
          end

        expect_post(200, response, fn _url, body, _opts ->
          assert body["key"] == key
          assert body["migrate"] == true
        end)
      end)

      assert {:ok, final_status} = Unseal.submit_keys(migration_keys, migrate: true)
      assert final_status.sealed == false
    end

    test "partial unseal then reset workflow" do
      # Step 1: Submit partial keys
      expect_post(200, %{@sealed_status | "progress" => 1}, fn _url, body, _opts ->
        assert body["key"] == "partial-key1"
      end)

      assert {:ok, partial_status} = Unseal.submit_key("partial-key1")
      assert partial_status.progress == 1

      expect_post(200, %{@sealed_status | "progress" => 2}, fn _url, body, _opts ->
        assert body["key"] == "partial-key2"
      end)

      assert {:ok, partial_status2} = Unseal.submit_key("partial-key2")
      assert partial_status2.progress == 2

      # Step 2: Reset progress
      expect_post(200, @reset_status, fn _url, body, _opts ->
        assert body["reset"] == true
      end)

      assert {:ok, reset_status} = Unseal.reset()
      assert reset_status.progress == 0
    end
  end
end
