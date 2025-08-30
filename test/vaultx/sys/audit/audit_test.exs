defmodule Vaultx.Sys.AuditTest do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Sys.Audit
  alias Vaultx.Base.Error

  # Sample audit devices response
  @audit_devices_response %{
    "file" => %{
      "type" => "file",
      "description" => "Store logs in a file",
      "options" => %{
        "file_path" => "/var/log/vault.log",
        "format" => "json",
        "hmac_accessor" => true,
        "log_raw" => false
      }
    },
    "syslog" => %{
      "type" => "syslog",
      "description" => "Send logs to syslog",
      "options" => %{
        "facility" => "AUTH",
        "tag" => "vault",
        "format" => "json"
      }
    },
    "socket" => %{
      "type" => "socket",
      "description" => "Stream logs to socket",
      "options" => %{
        "address" => "127.0.0.1:9090",
        "socket_type" => "tcp",
        "format" => "json"
      }
    }
  }

  # Empty audit devices response
  @empty_audit_response %{}

  describe "list/1" do
    test "returns all enabled audit devices successfully" do
      expect_get(200, @audit_devices_response, fn url, _body, _opts ->
        assert String.contains?(url, "sys/audit")
      end)

      assert {:ok, devices} = Audit.list()

      # Check file audit device
      file_device = devices["file"]
      assert file_device.type == "file"
      assert file_device.description == "Store logs in a file"
      assert file_device.options["file_path"] == "/var/log/vault.log"
      assert file_device.options["format"] == "json"
      assert file_device.options["hmac_accessor"] == true

      # Check syslog audit device
      syslog_device = devices["syslog"]
      assert syslog_device.type == "syslog"
      assert syslog_device.description == "Send logs to syslog"
      assert syslog_device.options["facility"] == "AUTH"
      assert syslog_device.options["tag"] == "vault"

      # Check socket audit device
      socket_device = devices["socket"]
      assert socket_device.type == "socket"
      assert socket_device.description == "Stream logs to socket"
      assert socket_device.options["address"] == "127.0.0.1:9090"
      assert socket_device.options["socket_type"] == "tcp"
    end

    test "handles empty audit devices response" do
      expect_get(200, @empty_audit_response)

      assert {:ok, devices} = Audit.list()
      assert devices == %{}
    end

    test "handles server errors" do
      expect_get(500, %{"errors" => ["internal server error"]})

      assert {:error, %Error{} = error} = Audit.list()
      assert error.type == :server_error
      assert String.contains?(error.message, "Failed to list audit devices")
    end

    test "handles network errors" do
      stub_request_raw(:get, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{} = error} = Audit.list()
      assert error.type == :unknown_error
    end
  end

  describe "enable/3" do
    test "enables file audit device successfully" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/audit/file-audit")
        assert body["type"] == "file"
        assert body["description"] == "File-based audit logging"
        assert body["options"]["file_path"] == "/var/log/vault/audit.log"
        assert body["options"]["format"] == "json"
      end)

      config = %{
        type: "file",
        description: "File-based audit logging",
        options: %{
          file_path: "/var/log/vault/audit.log",
          format: "json",
          hmac_accessor: true
        }
      }

      assert {:ok, response} = Audit.enable("file-audit", config)
      assert response.status == 204
    end

    test "enables syslog audit device successfully" do
      expect_post(200, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/audit/syslog-audit")
        assert body["type"] == "syslog"
        assert body["options"]["facility"] == "AUTH"
        assert body["options"]["tag"] == "vault"
      end)

      config = %{
        type: "syslog",
        description: "System log audit device",
        options: %{
          facility: "AUTH",
          tag: "vault",
          format: "json"
        }
      }

      assert {:ok, response} = Audit.enable("syslog-audit", config)
      assert response.status == 200
    end

    test "enables socket audit device successfully" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/audit/socket-audit")
        assert body["type"] == "socket"
        assert body["options"]["address"] == "127.0.0.1:9090"
        assert body["options"]["socket_type"] == "tcp"
      end)

      config = %{
        type: "socket",
        description: "Network socket audit device",
        options: %{
          address: "127.0.0.1:9090",
          socket_type: "tcp"
        }
      }

      assert {:ok, _response} = Audit.enable("socket-audit", config)
    end

    test "enables audit device with enterprise features" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/audit/enterprise-audit")
        assert body["type"] == "file"
        assert body["options"]["filter"] == "operation == \"read\""
        assert body["options"]["exclude"] == "request.data.password"
        assert body["options"]["fallback"] == true
        assert body["local"] == true
      end)

      config = %{
        type: "file",
        description: "Enterprise audit device",
        options: %{
          file_path: "/var/log/vault/enterprise.log",
          filter: "operation == \"read\"",
          exclude: "request.data.password",
          fallback: true
        },
        local: true
      }

      assert {:ok, _response} = Audit.enable("enterprise-audit", config)
    end

    test "enables audit device with minimal configuration" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/audit/minimal-audit")
        assert body["type"] == "file"
        refute Map.has_key?(body, "description")
        refute Map.has_key?(body, "options")
      end)

      config = %{type: "file"}
      assert {:ok, _response} = Audit.enable("minimal-audit", config)
    end

    test "handles enable errors" do
      expect_post(400, %{"errors" => ["audit device already exists"]})

      config = %{type: "file"}
      assert {:error, %Error{} = error} = Audit.enable("existing-audit", config)
      assert error.type == :server_error
      assert String.contains?(error.message, "Failed to enable audit device")
    end

    test "handles network errors during enable" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      config = %{type: "file"}
      assert {:error, %Error{} = error} = Audit.enable("network-error", config)
      assert error.type == :unknown_error
    end
  end

  describe "disable/2" do
    test "disables audit device successfully" do
      expect_delete(204, %{}, fn url, _body, _opts ->
        assert String.contains?(url, "sys/audit/file-audit")
      end)

      assert {:ok, response} = Audit.disable("file-audit")
      assert response.status == 204
    end

    test "handles disable errors" do
      expect_delete(404, %{"errors" => ["audit device not found"]})

      assert {:error, %Error{} = error} = Audit.disable("nonexistent-audit")
      assert error.type == :server_error
      assert String.contains?(error.message, "Failed to disable audit device")
    end

    test "handles network errors during disable" do
      stub_request_raw(:delete, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{} = error} = Audit.disable("network-error")
      assert error.type == :unknown_error
    end
  end

  describe "edge cases and special configurations" do
    test "handles audit device with null description" do
      response_with_null = %{
        "test" => %{
          "type" => "file",
          "description" => nil,
          "options" => %{
            "file_path" => "/tmp/test.log"
          }
        }
      }

      expect_get(200, response_with_null)

      assert {:ok, devices} = Audit.list()
      test_device = devices["test"]
      assert test_device.type == "file"
      assert test_device.description == ""
      assert test_device.options["file_path"] == "/tmp/test.log"
    end

    test "handles audit device with null options" do
      response_with_null_options = %{
        "test" => %{
          "type" => "syslog",
          "description" => "Test syslog",
          "options" => nil
        }
      }

      expect_get(200, response_with_null_options)

      assert {:ok, devices} = Audit.list()
      test_device = devices["test"]
      assert test_device.type == "syslog"
      assert test_device.description == "Test syslog"
      assert test_device.options == %{}
    end

    test "enables audit device with all common options" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/audit/full-config")
        options = body["options"]
        assert options["elide_list_responses"] == true
        assert options["format"] == "jsonx"
        assert options["hmac_accessor"] == false
        assert options["log_raw"] == true
        assert options["prefix"] == "VAULT-AUDIT:"
      end)

      config = %{
        type: "file",
        description: "Full configuration audit device",
        options: %{
          file_path: "/var/log/vault/full.log",
          elide_list_responses: true,
          format: "jsonx",
          hmac_accessor: false,
          log_raw: true,
          prefix: "VAULT-AUDIT:"
        }
      }

      assert {:ok, _response} = Audit.enable("full-config", config)
    end

    test "handles special characters in audit device path" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/audit/my-app_v1.0")
        assert body["type"] == "file"
      end)

      config = %{type: "file"}
      assert {:ok, _response} = Audit.enable("my-app_v1.0", config)
    end

    test "handles unicode characters in configuration" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/audit/测试-audit")
        assert body["description"] == "测试审计设备"
        assert body["options"]["file_path"] == "/var/log/测试.log"
      end)

      config = %{
        type: "file",
        description: "测试审计设备",
        options: %{
          file_path: "/var/log/测试.log"
        }
      }

      assert {:ok, _response} = Audit.enable("测试-audit", config)
    end
  end

  describe "integration scenarios" do
    test "complete audit device lifecycle" do
      # Step 1: List devices (empty initially)
      expect_get(200, @empty_audit_response)
      assert {:ok, devices} = Audit.list()
      assert devices == %{}

      # Step 2: Enable a new audit device
      expect_post(204, %{})

      config = %{
        type: "file",
        description: "Test audit device",
        options: %{file_path: "/tmp/test-audit.log"}
      }

      assert {:ok, _} = Audit.enable("test-audit", config)

      # Step 3: List devices (should include new device)
      devices_with_new = %{
        "test-audit" => %{
          "type" => "file",
          "description" => "Test audit device",
          "options" => %{"file_path" => "/tmp/test-audit.log"}
        }
      }

      expect_get(200, devices_with_new)
      assert {:ok, devices} = Audit.list()
      assert Map.has_key?(devices, "test-audit")

      # Step 4: Disable the audit device
      expect_delete(204, %{})
      assert {:ok, _} = Audit.disable("test-audit")
    end

    test "multiple audit devices management" do
      # Enable multiple audit devices
      expect_post(204, %{})
      file_config = %{type: "file", options: %{file_path: "/tmp/file.log"}}
      assert {:ok, _} = Audit.enable("file-audit", file_config)

      expect_post(204, %{})
      syslog_config = %{type: "syslog", options: %{facility: "AUTH"}}
      assert {:ok, _} = Audit.enable("syslog-audit", syslog_config)

      # List all devices
      expect_get(200, @audit_devices_response)
      assert {:ok, devices} = Audit.list()
      # file, syslog, socket
      assert map_size(devices) == 3

      # Disable one device
      expect_delete(204, %{})
      assert {:ok, _} = Audit.disable("file-audit")
    end
  end
end
