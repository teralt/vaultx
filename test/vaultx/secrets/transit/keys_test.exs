defmodule Vaultx.Secrets.Transit.KeysTest do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Secrets.Transit.Keys
  alias Vaultx.Base.Error

  describe "create/3" do
    test "creates key with default type successfully" do
      expect_post(200, %{}, fn url, body, _opts ->
        assert String.contains?(url, "transit/keys/my-key")
        assert body["type"] == "aes256-gcm96"
      end)

      assert :ok = Keys.create("my-key")
    end

    test "creates key with custom type successfully" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "transit/keys/my-key")
        assert body["type"] == "ed25519"
      end)

      assert :ok = Keys.create("my-key", "ed25519")
    end

    test "creates key with options successfully" do
      expect_post(200, %{}, fn url, body, _opts ->
        assert String.contains?(url, "transit/keys/derived-key")
        assert body["type"] == "aes256-gcm96"
        assert body["derived"] == true
        assert body["convergent_encryption"] == true
        assert body["exportable"] == false
      end)

      assert :ok =
               Keys.create("derived-key", "aes256-gcm96",
                 derived: true,
                 convergent_encryption: true,
                 exportable: false
               )
    end

    test "creates key with all options" do
      expect_post(200, %{}, fn url, body, _opts ->
        assert String.contains?(url, "transit/keys/full-key")
        assert body["type"] == "rsa-2048"
        assert body["derived"] == false
        assert body["convergent_encryption"] == false
        assert body["exportable"] == true
        assert body["allow_plaintext_backup"] == true
        assert body["auto_rotate_period"] == "24h"
        assert body["key_size"] == 2048
      end)

      assert :ok =
               Keys.create("full-key", "rsa-2048",
                 derived: false,
                 convergent_encryption: false,
                 exportable: true,
                 allow_plaintext_backup: true,
                 auto_rotate_period: "24h",
                 key_size: 2048
               )
    end

    test "creates managed key with managed key options" do
      expect_post(200, %{}, fn url, body, _opts ->
        assert String.contains?(url, "transit/keys/managed-key")
        assert body["type"] == "managed_key"
        assert body["managed_key_name"] == "my-managed-key"
        assert body["managed_key_id"] == "12345678-1234-1234-1234-123456789012"
      end)

      assert :ok =
               Keys.create("managed-key", "managed_key",
                 managed_key_name: "my-managed-key",
                 managed_key_id: "12345678-1234-1234-1234-123456789012"
               )
    end

    test "creates key with custom mount path" do
      expect_post(200, %{}, fn url, body, _opts ->
        assert String.contains?(url, "encryption/keys/my-key")
        assert body["type"] == "aes256-gcm96"
      end)

      assert :ok = Keys.create("my-key", "aes256-gcm96", mount_path: "encryption")
    end

    test "handles 400 error response" do
      expect_post(400, %{"errors" => ["invalid key type"]})

      assert {:error, %Error{}} = Keys.create("my-key", "invalid-type")
    end

    test "handles network error" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{type: :network_error}} = Keys.create("my-key")
    end

    test "ignores invalid options" do
      expect_post(200, %{}, fn url, body, _opts ->
        assert String.contains?(url, "transit/keys/my-key")
        assert body["type"] == "aes256-gcm96"
        # Invalid options should be filtered out
        refute Map.has_key?(body, "invalid_option")
        refute Map.has_key?(body, "another_invalid")
      end)

      assert :ok =
               Keys.create("my-key", "aes256-gcm96",
                 invalid_option: "should be ignored",
                 another_invalid: 123
               )
    end
  end

  describe "read/2" do
    test "reads key information successfully" do
      key_data = %{
        "name" => "my-key",
        "type" => "aes256-gcm96",
        "derived" => false,
        "exportable" => false,
        "allow_plaintext_backup" => false,
        "keys" => %{"1" => 1_234_567_890},
        "min_decryption_version" => 1,
        "min_encryption_version" => 1,
        "deletion_allowed" => false,
        "supports_encryption" => true,
        "supports_decryption" => true,
        "supports_derivation" => false,
        "supports_signing" => false,
        "imported" => false,
        "auto_rotate_period" => "0"
      }

      expect_get(200, %{"data" => key_data}, fn url, _body, _opts ->
        assert String.contains?(url, "transit/keys/my-key")
      end)

      assert {:ok, key_info} = Keys.read("my-key")
      assert key_info.name == "my-key"
      assert key_info.type == "aes256-gcm96"
      assert key_info.derived == false
      assert key_info.supports_encryption == true
    end

    test "reads key with custom mount path" do
      key_data = %{
        "name" => "my-key",
        "type" => "ed25519",
        "supports_signing" => true
      }

      expect_get(200, %{"data" => key_data}, fn url, _body, _opts ->
        assert String.contains?(url, "encryption/keys/my-key")
      end)

      assert {:ok, key_info} = Keys.read("my-key", mount_path: "encryption")
      assert key_info.name == "my-key"
      assert key_info.type == "ed25519"
    end

    test "handles key not found" do
      expect_get(404, %{"errors" => ["key not found"]})

      assert {:error, %Error{type: :key_not_found}} = Keys.read("nonexistent-key")
    end

    test "handles read failure with other status codes" do
      expect_get(400, %{"errors" => ["read failed"]})

      assert {:error, %Error{}} = Keys.read("my-key")
    end

    test "handles malformed response data" do
      expect_get(200, %{"data" => "invalid"})

      assert {:ok, key_info} = Keys.read("my-key")
      # Should return empty key info for malformed data
      assert key_info.name == ""
      assert key_info.type == ""
    end

    test "handles missing data field" do
      expect_get(200, %{})

      assert {:ok, key_info} = Keys.read("my-key")
      # Should return empty key info for missing data
      assert key_info.name == ""
      assert key_info.type == ""
    end

    test "handles network error" do
      stub_request_raw(:get, %Req.TransportError{reason: :econnrefused})

      assert {:error, %Error{type: :network_error}} = Keys.read("my-key")
    end
  end

  describe "update_config/3" do
    test "updates key configuration successfully" do
      config = %{
        "deletion_allowed" => true,
        "min_encryption_version" => 2
      }

      expect_post(200, %{}, fn url, body, _opts ->
        assert String.contains?(url, "transit/keys/my-key/config")
        assert body == config
      end)

      assert :ok = Keys.update_config("my-key", config)
    end

    test "updates key configuration with custom mount path" do
      config = %{"auto_rotate_period" => "24h"}

      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "encryption/keys/my-key/config")
        assert body == config
      end)

      assert :ok = Keys.update_config("my-key", config, mount_path: "encryption")
    end

    test "handles key not found for config update" do
      expect_post(404, %{"errors" => ["key not found"]})

      assert {:error, %Error{type: :key_not_found}} = Keys.update_config("nonexistent-key", %{})
    end

    test "handles invalid configuration" do
      expect_post(400, %{"errors" => ["invalid configuration"]})

      assert {:error, %Error{}} = Keys.update_config("my-key", %{"invalid" => "config"})
    end

    test "handles network error" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{type: :network_error}} = Keys.update_config("my-key", %{})
    end
  end

  describe "rotate/2" do
    test "rotates key successfully" do
      expect_post(200, %{}, fn url, body, _opts ->
        assert String.contains?(url, "transit/keys/my-key/rotate")
        assert body == %{}
      end)

      assert :ok = Keys.rotate("my-key")
    end

    test "rotates key with custom mount path" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "encryption/keys/my-key/rotate")
        assert body == %{}
      end)

      assert :ok = Keys.rotate("my-key", mount_path: "encryption")
    end

    test "handles key not found for rotation" do
      expect_post(404, %{"errors" => ["key not found"]})

      assert {:error, %Error{type: :key_not_found}} = Keys.rotate("nonexistent-key")
    end

    test "handles rotation failure" do
      expect_post(400, %{"errors" => ["rotation not allowed"]})

      assert {:error, %Error{}} = Keys.rotate("my-key")
    end

    test "handles network error" do
      stub_request_raw(:post, %Req.TransportError{reason: :econnrefused})

      assert {:error, %Error{type: :network_error}} = Keys.rotate("my-key")
    end
  end

  describe "delete/2" do
    test "deletes key successfully" do
      expect_delete(200, %{}, fn url, _body, _opts ->
        assert String.contains?(url, "transit/keys/my-key")
      end)

      assert :ok = Keys.delete("my-key")
    end

    test "deletes key with custom mount path" do
      expect_delete(204, %{}, fn url, _body, _opts ->
        assert String.contains?(url, "encryption/keys/my-key")
      end)

      assert :ok = Keys.delete("my-key", mount_path: "encryption")
    end

    test "handles key not found for deletion" do
      expect_delete(404, %{"errors" => ["key not found"]})

      assert {:error, %Error{type: :key_not_found}} = Keys.delete("nonexistent-key")
    end

    test "handles deletion not allowed" do
      expect_delete(400, %{"errors" => ["deletion not allowed"]})

      assert {:error, %Error{}} = Keys.delete("my-key")
    end

    test "handles network error" do
      stub_request_raw(:delete, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{type: :network_error}} = Keys.delete("my-key")
    end
  end

  describe "list/1" do
    test "lists keys successfully" do
      expect_get(200, %{"data" => %{"keys" => ["key1", "key2", "key3"]}}, fn url, _body, _opts ->
        assert String.contains?(url, "transit/keys")
      end)

      assert {:ok, keys} = Keys.list()
      assert keys == ["key1", "key2", "key3"]
    end

    test "lists keys with custom mount path" do
      expect_get(200, %{"data" => %{"keys" => ["key1"]}}, fn url, _body, _opts ->
        assert String.contains?(url, "encryption/keys")
      end)

      assert {:ok, keys} = Keys.list(mount_path: "encryption")
      assert keys == ["key1"]
    end

    test "handles no keys found (404)" do
      expect_get(404, %{"errors" => ["no keys found"]})

      assert {:ok, keys} = Keys.list()
      assert keys == []
    end

    test "handles empty keys list" do
      expect_get(200, %{"data" => %{}})

      assert {:ok, keys} = Keys.list()
      assert keys == []
    end

    test "handles malformed response" do
      expect_get(200, %{"data" => %{"keys" => "invalid"}})

      assert {:ok, keys} = Keys.list()
      assert keys == []
    end

    test "handles list failure with other status codes" do
      expect_get(400, %{"errors" => ["list failed"]})

      assert {:error, %Error{}} = Keys.list()
    end

    test "handles network error" do
      stub_request_raw(:get, %Req.TransportError{reason: :econnrefused})

      assert {:error, %Error{type: :network_error}} = Keys.list()
    end
  end
end
