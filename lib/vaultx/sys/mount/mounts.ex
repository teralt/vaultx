defmodule Vaultx.Sys.Mounts do
  @moduledoc """
  Comprehensive HashiCorp Vault secrets engine mount management.

  This module provides enterprise-grade mount management capabilities for Vault
  secrets engines, supporting all mount operations including creation, configuration,
  tuning, and removal of secrets engines with comprehensive enterprise features.

  ## Mount Management Features

  ### Core Operations
  - List Mounts: Retrieve all mounted secrets engines
  - Enable Mount: Create new secrets engine mounts
  - Disable Mount: Remove existing secrets engine mounts
  - Get Mount: Retrieve specific mount configuration
  - Tune Mount: Modify mount configuration parameters

  ### Configuration Management
  - TTL Configuration: Default and maximum lease TTL settings
  - Caching Control: Force no-cache and performance tuning
  - Audit Configuration: HMAC key management for audit devices
  - Plugin Management: Plugin version and runtime configuration
  - Security Settings: Seal wrap and entropy access control

  ### Enterprise Features
  - Namespace Support: Multi-tenant mount management
  - Local Mounts: Replication-aware mount configuration
  - Managed Keys: Enterprise key management integration
  - Delegated Auth: Authentication delegation configuration

  ## API Compliance

  Fully implements HashiCorp Vault Mounts API:
  - [Mounts API](https://developer.hashicorp.com/vault/api-docs/system/mounts)
  - [Mount Migration](https://developer.hashicorp.com/vault/docs/concepts/mount-migration)

  ## Usage Examples

  ### List All Mounts

      {:ok, mounts} = Vaultx.Sys.Mounts.list()
      mounts["secret/"].type #=> "kv"
      mounts["secret/"].config.max_lease_ttl #=> 0

  ### Enable New Secrets Engine

      {:ok, _} = Vaultx.Sys.Mounts.enable("my-kv", %{
        type: "kv",
        description: "My KV store",
        config: %{
          default_lease_ttl: "1h",
          max_lease_ttl: "24h"
        },
        options: %{
          version: "2"
        }
      })

  ### Get Mount Configuration

      {:ok, mount} = Vaultx.Sys.Mounts.get("secret")
      mount.type #=> "kv"
      mount.config.max_lease_ttl #=> 0

  ### Tune Mount Configuration

      {:ok, _} = Vaultx.Sys.Mounts.tune("secret", %{
        default_lease_ttl: 3600,
        max_lease_ttl: 7200,
        description: "Updated description"
      })

  ### Disable Secrets Engine

      {:ok, _} = Vaultx.Sys.Mounts.disable("my-kv")

  ## Security Considerations

  - Mount operations require appropriate Vault policies
  - Disabling mounts revokes all associated secrets and leases
  - Use force disable only in recovery situations
  - Monitor mount changes through audit logs
  - Consider replication implications for local mounts
  """

  alias Vaultx.Base.{Error, Logger, Telemetry}
  alias Vaultx.Transport.HTTP
  alias Vaultx.Types

  @typedoc """
  Mount configuration options.
  """
  @type mount_config :: %{
          optional(:default_lease_ttl) => String.t() | non_neg_integer(),
          optional(:max_lease_ttl) => String.t() | non_neg_integer(),
          optional(:force_no_cache) => boolean(),
          optional(:audit_non_hmac_request_keys) => [String.t()],
          optional(:audit_non_hmac_response_keys) => [String.t()],
          optional(:listing_visibility) => String.t(),
          optional(:passthrough_request_headers) => [String.t()],
          optional(:allowed_response_headers) => [String.t()],
          optional(:plugin_version) => String.t(),
          optional(:allowed_managed_keys) => [String.t()],
          optional(:delegated_auth_accessors) => [String.t()],
          optional(:identity_token_key) => String.t()
        }

  @typedoc """
  Mount enable options.
  """
  @type mount_enable_opts :: %{
          :type => String.t(),
          optional(:description) => String.t(),
          optional(:config) => mount_config(),
          optional(:options) => map(),
          optional(:local) => boolean(),
          optional(:seal_wrap) => boolean(),
          optional(:external_entropy_access) => boolean()
        }

  @typedoc """
  Mount information structure.
  """
  @type mount_info :: %{
          :accessor => String.t(),
          :config => map(),
          :description => String.t(),
          :external_entropy_access => boolean(),
          :local => boolean(),
          :options => map() | nil,
          :plugin_version => String.t(),
          :running_plugin_version => String.t(),
          :running_sha256 => String.t(),
          :seal_wrap => boolean(),
          :type => String.t(),
          :uuid => String.t(),
          optional(:deprecation_status) => String.t()
        }

  @doc """
  Lists all mounted secrets engines.

  Returns a map of mount paths to their configuration details.

  ## Examples

      {:ok, mounts} = Vaultx.Sys.Mounts.list()
      mounts["secret/"].type #=> "kv"

  """
  @spec list(Types.options()) :: {:ok, %{String.t() => mount_info()}} | {:error, Error.t()}
  def list(opts \\ []) do
    path = "sys/mounts"

    metadata = %{operation: :list_mounts}
    Logger.debug("Listing mounted secrets engines", metadata)
    Telemetry.operation_start(metadata)

    start_time = System.monotonic_time()

    case HTTP.get(path, opts) do
      {:ok, %{status: 200, body: %{"data" => mounts}}} ->
        duration = System.monotonic_time() - start_time

        parsed_mounts = parse_mounts_response(mounts)

        Logger.info(
          "Successfully listed mounts",
          Map.put(metadata, :count, map_size(parsed_mounts))
        )

        Telemetry.operation_success(duration, metadata)

        {:ok, parsed_mounts}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:server_error, "Failed to list mounts: HTTP #{status}",
            details: %{status: status, body: body}
          )

        Logger.error("Failed to list mounts", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Error listing mounts", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Enables a new secrets engine at the specified path.

  ## Parameters

  - `path` - The mount path for the secrets engine
  - `mount_opts` - Mount configuration options

  ## Examples

      {:ok, _} = Vaultx.Sys.Mounts.enable("my-kv", %{
        type: "kv",
        description: "My KV store",
        options: %{version: "2"}
      })

  """
  @spec enable(String.t(), mount_enable_opts(), Types.options()) ::
          {:ok, Types.response()} | {:error, Error.t()}
  def enable(path, mount_opts, opts \\ []) do
    api_path = "sys/mounts/#{path}"

    request_body = build_enable_request(mount_opts)

    metadata = %{
      operation: :enable_mount,
      path: path,
      type: Map.get(mount_opts, :type)
    }

    Logger.debug("Enabling secrets engine", metadata)
    Telemetry.operation_start(metadata)

    start_time = System.monotonic_time()

    case HTTP.post(api_path, request_body, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        duration = System.monotonic_time() - start_time

        Logger.info("Successfully enabled secrets engine", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, %{status: status}}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:server_error, "Failed to enable secrets engine: HTTP #{status}",
            details: %{status: status, body: body}
          )

        Logger.error("Failed to enable secrets engine", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Failed to enable secrets engine", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Disables the secrets engine at the specified path.

  ## Parameters

  - `path` - The mount path to disable

  ## Examples

      {:ok, _} = Vaultx.Sys.Mounts.disable("my-kv")

  """
  @spec disable(String.t(), Types.options()) ::
          {:ok, Types.response()} | {:error, Error.t()}
  def disable(path, opts \\ []) do
    api_path = "sys/mounts/#{path}"

    metadata = %{operation: :disable_mount, path: path}
    Logger.debug("Disabling secrets engine", metadata)
    Telemetry.operation_start(metadata)

    start_time = System.monotonic_time()

    case HTTP.delete(api_path, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        duration = System.monotonic_time() - start_time

        Logger.info("Successfully disabled secrets engine", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, %{status: status}}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:server_error, "Failed to disable secrets engine: HTTP #{status}",
            details: %{status: status, body: body}
          )

        Logger.error("Failed to disable secrets engine", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Failed to disable secrets engine", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Gets the configuration of a specific secrets engine.

  ## Parameters

  - `path` - The mount path to retrieve

  ## Examples

      {:ok, mount} = Vaultx.Sys.Mounts.get("secret")
      mount.type #=> "kv"

  """
  @spec get(String.t(), Types.options()) :: {:ok, mount_info()} | {:error, Error.t()}
  def get(path, opts \\ []) do
    api_path = "sys/mounts/#{path}"

    metadata = %{operation: :get_mount, path: path}
    Logger.debug("Getting mount configuration", metadata)
    Telemetry.operation_start(metadata)

    start_time = System.monotonic_time()

    case HTTP.get(api_path, opts) do
      {:ok, %{status: 200, body: response}} ->
        duration = System.monotonic_time() - start_time

        mount_info = parse_mount_info(response)

        Logger.info("Successfully retrieved mount configuration", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, mount_info}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:server_error, "Failed to get mount configuration: HTTP #{status}",
            details: %{status: status, body: body}
          )

        Logger.error("Failed to get mount configuration", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Failed to get mount configuration", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  # Private helper functions

  defp parse_mounts_response(mounts) do
    Enum.into(mounts, %{}, fn {path, mount_data} ->
      {path, parse_mount_info(mount_data)}
    end)
  end

  defp parse_mount_info(mount_data) do
    %{
      accessor: mount_data["accessor"],
      config: mount_data["config"] || %{},
      description: mount_data["description"] || "",
      external_entropy_access: mount_data["external_entropy_access"] || false,
      local: mount_data["local"] || false,
      options: mount_data["options"],
      plugin_version: mount_data["plugin_version"] || "",
      running_plugin_version: mount_data["running_plugin_version"] || "",
      running_sha256: mount_data["running_sha256"] || "",
      seal_wrap: mount_data["seal_wrap"] || false,
      type: mount_data["type"],
      uuid: mount_data["uuid"]
    }
    |> maybe_add_deprecation_status(mount_data)
  end

  defp maybe_add_deprecation_status(mount_info, mount_data) do
    case mount_data["deprecation_status"] do
      nil -> mount_info
      status -> Map.put(mount_info, :deprecation_status, status)
    end
  end

  defp build_enable_request(mount_opts) do
    base_request = %{
      type: Map.fetch!(mount_opts, :type)
    }

    base_request
    |> maybe_add_field(:description, mount_opts)
    |> maybe_add_field(:config, mount_opts)
    |> maybe_add_field(:options, mount_opts)
    |> maybe_add_field(:local, mount_opts)
    |> maybe_add_field(:seal_wrap, mount_opts)
    |> maybe_add_field(:external_entropy_access, mount_opts)
  end

  @doc """
  Tunes configuration parameters for a mounted secrets engine.

  ## Parameters

  - `path` - The mount path to tune
  - `tune_opts` - Tuning configuration options

  ## Examples

      {:ok, _} = Vaultx.Sys.Mounts.tune("secret", %{
        default_lease_ttl: 3600,
        max_lease_ttl: 7200,
        description: "Updated description"
      })

  """
  @spec tune(String.t(), mount_config(), Types.options()) ::
          {:ok, Types.response()} | {:error, Error.t()}
  def tune(path, tune_opts, opts \\ []) do
    api_path = "sys/mounts/#{path}/tune"

    metadata = %{operation: :tune_mount, path: path}
    Logger.debug("Tuning mount configuration", metadata)
    Telemetry.operation_start(metadata)

    start_time = System.monotonic_time()

    case HTTP.post(api_path, tune_opts, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        duration = System.monotonic_time() - start_time

        Logger.info("Successfully tuned mount configuration", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, %{status: status}}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:server_error, "Failed to tune mount configuration: HTTP #{status}",
            details: %{status: status, body: body}
          )

        Logger.error("Failed to tune mount configuration", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Failed to tune mount configuration", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Moves an existing mount to a new path.

  This operation is also known as "remount" and allows moving a secrets engine
  from one path to another. All secrets and leases are preserved during the move.

  ## Parameters

  - `from_path` - The current mount path
  - `to_path` - The new mount path

  ## Examples

      {:ok, _} = Vaultx.Sys.Mounts.remount("old-path", "new-path")

  """
  @spec remount(String.t(), String.t(), Types.options()) ::
          {:ok, Types.response()} | {:error, Error.t()}
  def remount(from_path, to_path, opts \\ []) do
    api_path = "sys/remount"

    request_body = %{
      from: from_path,
      to: to_path
    }

    metadata = %{
      operation: :remount,
      from_path: from_path,
      to_path: to_path
    }

    Logger.debug("Remounting secrets engine", metadata)
    Telemetry.operation_start(metadata)

    start_time = System.monotonic_time()

    case HTTP.post(api_path, request_body, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        duration = System.monotonic_time() - start_time

        Logger.info("Successfully remounted secrets engine", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, %{status: status}}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:server_error, "Failed to remount secrets engine: HTTP #{status}",
            details: %{status: status, body: body}
          )

        Logger.error("Failed to remount secrets engine", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Failed to remount secrets engine", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  defp maybe_add_field(request, field, opts) do
    case Map.get(opts, field) do
      nil -> request
      value -> Map.put(request, field, value)
    end
  end
end
