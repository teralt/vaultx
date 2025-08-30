defmodule Vaultx.Sys.MountsTest do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Sys.Mounts
  alias Vaultx.Base.Error

  # Sample mounts response from Vault
  @mounts_response %{
    "data" => %{
      "secret/" => %{
        "accessor" => "kv_accessor_123",
        "config" => %{
          "default_lease_ttl" => 0,
          "force_no_cache" => false,
          "max_lease_ttl" => 0
        },
        "description" => "key/value secret storage",
        "external_entropy_access" => false,
        "local" => false,
        "options" => %{"version" => "2"},
        "plugin_version" => "",
        "running_plugin_version" => "v1.20.0+builtin.vault",
        "running_sha256" => "",
        "seal_wrap" => false,
        "type" => "kv",
        "uuid" => "kv-uuid-123"
      },
      "sys/" => %{
        "accessor" => "system_accessor_456",
        "config" => %{
          "default_lease_ttl" => 0,
          "force_no_cache" => false,
          "max_lease_ttl" => 0,
          "passthrough_request_headers" => ["Accept"]
        },
        "description" => "system endpoints used for control, policy and debugging",
        "external_entropy_access" => false,
        "local" => false,
        "options" => nil,
        "plugin_version" => "",
        "running_plugin_version" => "v1.20.0+builtin.vault",
        "running_sha256" => "",
        "seal_wrap" => true,
        "type" => "system",
        "uuid" => "system-uuid-456"
      }
    }
  }

  # Sample single mount response
  @single_mount_response %{
    "accessor" => "kv_accessor_789",
    "config" => %{
      "default_lease_ttl" => 3600,
      "force_no_cache" => false,
      "max_lease_ttl" => 7200
    },
    "description" => "My custom KV store",
    "external_entropy_access" => false,
    "local" => false,
    "options" => %{"version" => "2"},
    "plugin_version" => "",
    "running_plugin_version" => "v1.20.0+builtin.vault",
    "running_sha256" => "",
    "seal_wrap" => false,
    "type" => "kv",
    "uuid" => "custom-kv-uuid-789"
  }

  describe "list/1" do
    test "returns all mounted secrets engines successfully" do
      expect_get(200, @mounts_response, fn url, _body, _opts ->
        assert String.contains?(url, "sys/mounts")
      end)

      assert {:ok, mounts} = Mounts.list()

      # Check secret/ mount
      secret_mount = mounts["secret/"]
      assert secret_mount.type == "kv"
      assert secret_mount.accessor == "kv_accessor_123"
      assert secret_mount.description == "key/value secret storage"
      assert secret_mount.options == %{"version" => "2"}
      assert secret_mount.seal_wrap == false
      assert secret_mount.local == false

      # Check sys/ mount
      sys_mount = mounts["sys/"]
      assert sys_mount.type == "system"
      assert sys_mount.accessor == "system_accessor_456"
      assert sys_mount.seal_wrap == true
      assert is_nil(sys_mount.options)
    end

    test "handles empty mounts response" do
      empty_response = %{"data" => %{}}
      expect_get(200, empty_response)

      assert {:ok, mounts} = Mounts.list()
      assert mounts == %{}
    end

    test "handles network errors" do
      stub_request_raw(:get, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{} = error} = Mounts.list()
      assert error.type == :unknown_error
    end

    test "handles server errors" do
      expect_get(500, %{"errors" => ["internal server error"]})

      assert {:error, %Error{} = error} = Mounts.list()
      assert error.type == :server_error
    end
  end

  describe "enable/3" do
    test "enables a new secrets engine successfully" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/mounts/my-kv")
        assert body["type"] == "kv"
        assert body["description"] == "My KV store"
        assert body["config"]["default_lease_ttl"] == "1h"
        assert body["options"]["version"] == "2"
      end)

      mount_opts = %{
        type: "kv",
        description: "My KV store",
        config: %{
          default_lease_ttl: "1h",
          max_lease_ttl: "24h"
        },
        options: %{
          version: "2"
        }
      }

      assert {:ok, _response} = Mounts.enable("my-kv", mount_opts)
    end

    test "enables secrets engine with minimal options" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/mounts/simple-kv")
        assert body["type"] == "kv"
        refute Map.has_key?(body, "description")
        refute Map.has_key?(body, "config")
      end)

      mount_opts = %{type: "kv"}
      assert {:ok, _response} = Mounts.enable("simple-kv", mount_opts)
    end

    test "handles enable errors" do
      expect_post(400, %{"errors" => ["mount already exists"]})

      mount_opts = %{type: "kv"}
      assert {:error, %Error{} = error} = Mounts.enable("existing-mount", mount_opts)
      assert error.type == :server_error
    end

    test "handles enable network errors" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      mount_opts = %{type: "kv"}
      assert {:error, %Error{} = error} = Mounts.enable("network-error-mount", mount_opts)
      assert error.type == :unknown_error
    end
  end

  describe "disable/2" do
    test "disables a secrets engine successfully" do
      expect_delete(204, %{}, fn url, _body, _opts ->
        assert String.contains?(url, "sys/mounts/my-kv")
      end)

      assert {:ok, _response} = Mounts.disable("my-kv")
    end

    test "handles disable errors" do
      expect_delete(400, %{"errors" => ["mount does not exist"]})

      assert {:error, %Error{} = error} = Mounts.disable("nonexistent-mount")
      assert error.type == :server_error
    end

    test "handles disable network errors" do
      stub_request_raw(:delete, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{} = error} = Mounts.disable("network-error-mount")
      assert error.type == :unknown_error
    end
  end

  describe "get/2" do
    test "gets mount configuration successfully" do
      expect_get(200, @single_mount_response, fn url, _body, _opts ->
        assert String.contains?(url, "sys/mounts/my-kv")
      end)

      assert {:ok, mount} = Mounts.get("my-kv")
      assert mount.type == "kv"
      assert mount.accessor == "kv_accessor_789"
      assert mount.description == "My custom KV store"
      assert mount.config["default_lease_ttl"] == 3600
      assert mount.config["max_lease_ttl"] == 7200
      assert mount.options == %{"version" => "2"}
    end

    test "handles get mount errors" do
      expect_get(404, %{"errors" => ["mount not found"]})

      assert {:error, %Error{} = error} = Mounts.get("nonexistent-mount")
      assert error.type == :server_error
    end

    test "handles get mount network errors" do
      stub_request_raw(:get, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{} = error} = Mounts.get("network-error-mount")
      assert error.type == :unknown_error
    end
  end

  describe "tune/3" do
    test "tunes mount configuration successfully" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/mounts/secret/tune")
        assert body["default_lease_ttl"] == 3600
        assert body["max_lease_ttl"] == 7200
        assert body["description"] == "Updated description"
      end)

      tune_opts = %{
        default_lease_ttl: 3600,
        max_lease_ttl: 7200,
        description: "Updated description"
      }

      assert {:ok, _response} = Mounts.tune("secret", tune_opts)
    end

    test "handles tune errors" do
      expect_post(400, %{"errors" => ["invalid configuration"]})

      tune_opts = %{default_lease_ttl: -1}
      assert {:error, %Error{} = error} = Mounts.tune("secret", tune_opts)
      assert error.type == :server_error
    end

    test "handles tune network errors" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      tune_opts = %{default_lease_ttl: 3600}
      assert {:error, %Error{} = error} = Mounts.tune("network-error", tune_opts)
      assert error.type == :unknown_error
    end
  end

  describe "remount/3" do
    test "remounts secrets engine successfully" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/remount")
        assert body["from"] == "old-path"
        assert body["to"] == "new-path"
      end)

      assert {:ok, _response} = Mounts.remount("old-path", "new-path")
    end

    test "handles remount errors" do
      expect_post(400, %{"errors" => ["source mount does not exist"]})

      assert {:error, %Error{} = error} = Mounts.remount("nonexistent", "new-path")
      assert error.type == :server_error
    end

    test "handles remount network errors" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{} = error} = Mounts.remount("old-path", "new-path")
      assert error.type == :unknown_error
    end
  end

  describe "edge cases" do
    test "handles mount with deprecation status" do
      mount_with_deprecation = Map.put(@single_mount_response, "deprecation_status", "supported")
      expect_get(200, mount_with_deprecation)

      assert {:ok, mount} = Mounts.get("deprecated-mount")
      assert mount.deprecation_status == "supported"
    end

    test "handles mount without deprecation status" do
      expect_get(200, @single_mount_response)

      assert {:ok, mount} = Mounts.get("normal-mount")
      refute Map.has_key?(mount, :deprecation_status)
    end

    test "handles mount with null values" do
      mount_with_nulls = %{
        "accessor" => "accessor_123",
        "config" => nil,
        "description" => nil,
        "external_entropy_access" => false,
        "local" => false,
        "options" => nil,
        "plugin_version" => nil,
        "running_plugin_version" => nil,
        "running_sha256" => nil,
        "seal_wrap" => false,
        "type" => "kv",
        "uuid" => "uuid_123"
      }

      expect_get(200, mount_with_nulls)

      assert {:ok, mount} = Mounts.get("null-mount")
      assert mount.config == %{}
      assert mount.description == ""
      assert is_nil(mount.options)
      assert mount.plugin_version == ""
    end

    test "handles enable with all optional fields" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/mounts/full-mount")
        assert body["type"] == "kv"
        assert body["description"] == "Full mount"
        assert body["local"] == true
        assert body["seal_wrap"] == true
        assert body["external_entropy_access"] == true
      end)

      mount_opts = %{
        type: "kv",
        description: "Full mount",
        config: %{default_lease_ttl: 3600},
        options: %{version: "2"},
        local: true,
        seal_wrap: true,
        external_entropy_access: true
      }

      assert {:ok, _response} = Mounts.enable("full-mount", mount_opts)
    end
  end
end
