defmodule Vaultx.Sys.Audit do
  @moduledoc """
  HashiCorp Vault audit device management operations.

  This module provides comprehensive audit device management capabilities for Vault,
  allowing you to list, enable, and disable audit devices with full configuration
  support for all audit device types and enterprise features.

  ## Audit Device Management Features

  ### Core Operations
  - List Devices: Retrieve all enabled audit devices
  - Enable Device: Create new audit devices with full configuration
  - Disable Device: Remove existing audit devices

  ### Supported Audit Device Types
  - File: Log audit entries to files with rotation support
  - Socket: Stream audit entries to network sockets
  - Syslog: Send audit entries to system logging facilities

  ### Configuration Options
  - Format Control: JSON and XML output formats
  - Security Settings: HMAC accessor hashing and raw logging
  - Performance: List response eliding and custom prefixes
  - Enterprise Features: Filtering, exclusion, and fallback devices

  ### Enterprise Features
  - Audit Filtering: Advanced filtering rules for audit entries
  - Audit Exclusion: Remove sensitive fields from audit logs
  - Fallback Devices: Designated fallback audit devices
  - Local Devices: Replication-aware audit device configuration

  ## Important Security Notes

  Security Requirements
  - All audit operations require `sudo` capability
  - Audit devices must be enabled before use
  - Multiple audit devices can be enabled simultaneously

  Disable Considerations
  - Disabling an audit device prevents HMAC value comparison
  - Re-enabling at the same path creates a new salt for hashing
  - Consider backup audit devices before disabling

  ## API Compliance

  Fully implements HashiCorp Vault Audit API:
  - [Audit API](https://developer.hashicorp.com/vault/api-docs/system/audit)
  - [Audit Devices](https://developer.hashicorp.com/vault/docs/audit)

  ## Usage Examples

  ### List Enabled Audit Devices

      {:ok, devices} = Vaultx.Sys.Audit.list()
      devices["file"].type #=> "file"
      devices["file"].options["file_path"] #=> "/var/log/vault.log"

  ### Enable File Audit Device

      {:ok, _} = Vaultx.Sys.Audit.enable("file-audit", %{
        type: "file",
        description: "File-based audit logging",
        options: %{
          file_path: "/var/log/vault/audit.log",
          format: "json"
        }
      })

  ### Enable Syslog Audit Device

      {:ok, _} = Vaultx.Sys.Audit.enable("syslog-audit", %{
        type: "syslog",
        description: "System log audit device",
        options: %{
          facility: "AUTH",
          tag: "vault"
        }
      })

  ### Enable Socket Audit Device

      {:ok, _} = Vaultx.Sys.Audit.enable("socket-audit", %{
        type: "socket",
        description: "Network socket audit device",
        options: %{
          address: "127.0.0.1:9090",
          socket_type: "tcp"
        }
      })

  ### Enterprise Filtering and Exclusion

      {:ok, _} = Vaultx.Sys.Audit.enable("filtered-audit", %{
        type: "file",
        options: %{
          file_path: "/var/log/vault/filtered.log",
          filter: "operation == \"read\"",
          exclude: "request.data.password"
        }
      })

  ### Disable Audit Device

      {:ok, _} = Vaultx.Sys.Audit.disable("file-audit")

  ## Audit Device Configuration

  ### Common Configuration Options
  - `elide_list_responses`: Elide list response bodies (default: false)
  - `format`: Output format - "json" or "jsonx" (default: "json")
  - `hmac_accessor`: Enable token accessor hashing (default: true)
  - `log_raw`: Log sensitive information without hashing (default: false)
  - `prefix`: Custom string prefix for log lines

  ### Enterprise Configuration Options
  - `exclude`: Field exclusion rules for sensitive data
  - `fallback`: Designate as fallback audit device
  - `filter`: Audit entry filtering expressions
  - `local`: Local-only device for replication scenarios
  """

  alias Vaultx.Base.{Error, Logger, Telemetry}
  alias Vaultx.Transport.HTTP
  alias Vaultx.Types

  @typedoc """
  Audit device configuration options.
  """
  @type audit_options :: %{
          optional(:elide_list_responses) => boolean(),
          optional(:exclude) => String.t(),
          optional(:fallback) => boolean(),
          optional(:filter) => String.t(),
          optional(:format) => String.t(),
          optional(:hmac_accessor) => boolean(),
          optional(:log_raw) => boolean(),
          optional(:prefix) => String.t(),
          optional(atom()) => any()
        }

  @typedoc """
  Audit device enable configuration.
  """
  @type audit_config :: %{
          :type => String.t(),
          optional(:description) => String.t(),
          optional(:options) => audit_options(),
          optional(:local) => boolean()
        }

  @typedoc """
  Audit device information structure.
  """
  @type audit_info :: %{
          :type => String.t(),
          :description => String.t(),
          :options => map()
        }

  @doc """
  Lists all enabled audit devices.

  Returns a map of audit device paths to their configuration details.
  Only enabled audit devices are returned.

  ## Examples

      {:ok, devices} = Vaultx.Sys.Audit.list()
      devices["file"].type #=> "file"
      devices["file"].description #=> "Store logs in a file"

  """
  @spec list(Types.options()) :: {:ok, %{String.t() => audit_info()}} | {:error, Error.t()}
  def list(opts \\ []) do
    path = "sys/audit"

    metadata = %{operation: :list_audit_devices}
    Logger.debug("Listing enabled audit devices", metadata)
    Telemetry.operation_start(metadata)

    start_time = System.monotonic_time()

    case HTTP.get(path, opts) do
      {:ok, %{status: 200, body: devices}} ->
        duration = System.monotonic_time() - start_time

        parsed_devices = parse_audit_devices(devices)

        Logger.info(
          "Successfully listed audit devices",
          Map.put(metadata, :count, map_size(parsed_devices))
        )

        Telemetry.operation_success(duration, metadata)

        {:ok, parsed_devices}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:server_error, "Failed to list audit devices: HTTP #{status}",
            details: %{status: status, body: body}
          )

        Logger.error("Failed to list audit devices", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Error listing audit devices", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Enables a new audit device at the specified path.

  ## Parameters

  - `path` - The path where the audit device will be enabled
  - `config` - Audit device configuration including type and options

  ## Examples

      # Enable file audit device
      {:ok, _} = Vaultx.Sys.Audit.enable("file-audit", %{
        type: "file",
        description: "File-based audit logging",
        options: %{
          file_path: "/var/log/vault/audit.log"
        }
      })

      # Enable syslog audit device
      {:ok, _} = Vaultx.Sys.Audit.enable("syslog-audit", %{
        type: "syslog",
        options: %{
          facility: "AUTH",
          tag: "vault"
        }
      })

  """
  @spec enable(String.t(), audit_config(), Types.options()) ::
          {:ok, Types.response()} | {:error, Error.t()}
  def enable(path, config, opts \\ []) do
    api_path = "sys/audit/#{path}"

    metadata = %{
      operation: :enable_audit_device,
      path: path,
      type: Map.get(config, :type)
    }

    Logger.debug("Enabling audit device", metadata)
    Telemetry.operation_start(metadata)

    start_time = System.monotonic_time()

    case HTTP.post(api_path, config, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        duration = System.monotonic_time() - start_time

        Logger.info("Successfully enabled audit device", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, %{status: status}}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:server_error, "Failed to enable audit device: HTTP #{status}",
            details: %{status: status, body: body}
          )

        Logger.error("Failed to enable audit device", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Failed to enable audit device", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Disables the audit device at the specified path.

  ## Parameters

  - `path` - The path of the audit device to disable

  ## Important Notes

  Once an audit device is disabled, you will no longer be able to HMAC values
  for comparison with entries in the audit logs. This is true even if you
  re-enable the audit device at the same path, as a new salt will be created.

  ## Examples

      {:ok, _} = Vaultx.Sys.Audit.disable("file-audit")

  """
  @spec disable(String.t(), Types.options()) :: {:ok, Types.response()} | {:error, Error.t()}
  def disable(path, opts \\ []) do
    api_path = "sys/audit/#{path}"

    metadata = %{operation: :disable_audit_device, path: path}
    Logger.debug("Disabling audit device", metadata)
    Telemetry.operation_start(metadata)

    start_time = System.monotonic_time()

    case HTTP.delete(api_path, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        duration = System.monotonic_time() - start_time

        Logger.info("Successfully disabled audit device", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, %{status: status}}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:server_error, "Failed to disable audit device: HTTP #{status}",
            details: %{status: status, body: body}
          )

        Logger.error("Failed to disable audit device", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Failed to disable audit device", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  # Private helper functions

  defp parse_audit_devices(devices) when is_map(devices) do
    devices
    |> Enum.filter(fn {_path, device_data} -> is_map(device_data) end)
    |> Enum.into(%{}, fn {path, device_data} ->
      {path, parse_audit_info(device_data)}
    end)
  end

  # Fallback function for malformed audit device data - defensive programming
  # coveralls-ignore-next-line
  defp parse_audit_devices(_devices), do: %{}

  defp parse_audit_info(device_data) when is_map(device_data) do
    %{
      type: device_data["type"],
      description: device_data["description"] || "",
      options: device_data["options"] || %{}
    }
  end

  # Fallback function for non-map audit device data - defensive programming
  # coveralls-ignore-next-line
  defp parse_audit_info(_device_data), do: %{type: "unknown", description: "", options: %{}}
end
