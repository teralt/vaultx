defmodule Vaultx.Sys.SealStatus do
  @moduledoc """
  HashiCorp Vault seal status operations.

  This module provides seal status checking capabilities for Vault, allowing you
  to retrieve detailed information about the current seal state, configuration,
  and operational status without requiring authentication.

  ## Seal Status Features

  ### Core Information
  - Seal State: Whether Vault is currently sealed or unsealed
  - Configuration: Threshold and total key shares information
  - Progress: Current unsealing progress when partially unsealed
  - Version Info: Vault version and build information
  - Cluster Info: Cluster name and ID when unsealed

  ### Operational Details
  - Storage Type: Backend storage configuration
  - Seal Type: Shamir, auto-seal, or other seal mechanisms
  - Migration Status: Whether seal migration is in progress
  - Recovery Seal: Recovery seal configuration status
  - Cluster Status: High availability and cluster information

  ## Important Notes

  Unauthenticated Endpoint
  - No authentication required to check seal status
  - Safe to call from monitoring and health check systems
  - Does not expose sensitive information

  High Availability Information
  - Cluster information only available when unsealed
  - Different nodes may report different status during transitions
  - Use for cluster health monitoring and automation

  ## API Compliance

  Fully implements HashiCorp Vault Seal Status API:
  - [Seal Status API](https://developer.hashicorp.com/vault/api-docs/system/seal-status)
  - [Vault Concepts](https://developer.hashicorp.com/vault/docs/concepts/seal)

  ## Usage Examples

  ### Basic Status Check

      {:ok, status} = Vaultx.Sys.SealStatus.get()

      if status.sealed do
        IO.puts("Vault is sealed - progress: \#{status.progress}/\#{status.t}")
      else
        IO.puts("Vault is unsealed - cluster: \#{status.cluster_name}")
      end

  ### Monitoring Integration

      case Vaultx.Sys.SealStatus.get() do
        {:ok, status} ->
          if status.sealed do
            # Alert: Vault is sealed
            send_alert("Vault is sealed")
          end
        {:error, _} ->
          # Alert: Cannot reach Vault
          send_alert("Vault unreachable")
      end

  ### Wait for Unseal

      {:ok, status} = Vaultx.Sys.SealStatus.wait_for_unseal(timeout: 300_000)
      IO.puts("Vault is now unsealed!")

  ## Status Information

  The seal status response includes:

  ### Always Present
  - `sealed`: Boolean indicating if Vault is sealed
  - `t`: Threshold number of keys required to unseal
  - `n`: Total number of key shares
  - `progress`: Current number of keys submitted
  - `version`: Vault version string
  - `build_date`: Build timestamp
  - `storage_type`: Storage backend type
  - `type`: Seal type (shamir, auto, etc.)

  ### When Unsealed
  - `cluster_name`: Name of the Vault cluster
  - `cluster_id`: Unique cluster identifier

  ### Additional Fields
  - `initialized`: Whether Vault has been initialized
  - `migration`: Whether seal migration is in progress
  - `recovery_seal`: Recovery seal status
  - `removed_from_cluster`: Cluster membership status
  - `nonce`: Current operation nonce
  """

  alias Vaultx.Base.{Error, Logger, Telemetry}
  alias Vaultx.Transport.HTTP
  alias Vaultx.Types

  @typedoc """
  Seal status information.
  """
  @type seal_status :: %{
          :sealed => boolean(),
          :t => integer(),
          :n => integer(),
          :progress => integer(),
          :version => String.t(),
          :build_date => String.t(),
          :storage_type => String.t(),
          :type => String.t(),
          :initialized => boolean(),
          :migration => boolean(),
          :recovery_seal => boolean(),
          :removed_from_cluster => boolean(),
          :nonce => String.t(),
          optional(:cluster_name) => String.t(),
          optional(:cluster_id) => String.t()
        }

  @doc """
  Get the current seal status of the Vault.

  This endpoint returns the seal status of the Vault. This is an unauthenticated
  endpoint that can be used for monitoring and health checking.

  ## Parameters

  - `opts` - Request options (optional)

  ## Returns

  Returns `{:ok, seal_status()}` with current seal status,
  or `{:error, Error.t()}` on failure.

  ## Examples

      {:ok, status} = Vaultx.Sys.SealStatus.get()

      IO.puts("Sealed: \#{status.sealed}")
      IO.puts("Version: \#{status.version}")
      IO.puts("Storage: \#{status.storage_type}")

      if status.sealed do
        IO.puts("Progress: \#{status.progress}/\#{status.t}")
      else
        IO.puts("Cluster: \#{status.cluster_name}")
      end

  """
  @spec get(Types.options()) :: {:ok, seal_status()} | {:error, Error.t()}
  def get(opts \\ []) do
    path = "sys/seal-status"

    metadata = %{operation: :get_seal_status}
    Logger.debug("Getting seal status", metadata)
    Telemetry.operation_start(metadata)

    start_time = System.monotonic_time()

    case HTTP.get(path, opts) do
      {:ok, %{status: 200, body: body}} ->
        duration = System.monotonic_time() - start_time

        status = parse_seal_status(body)

        Logger.info(
          "Successfully retrieved seal status",
          Map.merge(metadata, %{
            sealed: status.sealed,
            version: status.version,
            storage_type: status.storage_type
          })
        )

        Telemetry.operation_success(duration, metadata)

        {:ok, status}

      {:ok, %{status: status_code, body: body}} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:server_error, "Failed to get seal status: HTTP #{status_code}",
            details: %{status: status_code, body: body}
          )

        Logger.error("Failed to get seal status", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Error getting seal status", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Check if the Vault is currently sealed.

  This is a convenience function that returns a simple boolean
  indicating the seal state.

  ## Parameters

  - `opts` - Request options (optional)

  ## Returns

  Returns `{:ok, boolean()}` where true means sealed,
  or `{:error, Error.t()}` on failure.

  ## Examples

      case Vaultx.Sys.SealStatus.is_sealed?() do
        {:ok, true} -> IO.puts("Vault is sealed")
        {:ok, false} -> IO.puts("Vault is unsealed")
        {:error, error} -> IO.puts("Error: \#{error.message}")
      end

  """
  @spec is_sealed?(Types.options()) :: {:ok, boolean()} | {:error, Error.t()}
  def is_sealed?(opts \\ []) do
    case get(opts) do
      {:ok, status} -> {:ok, status.sealed}
      {:error, error} -> {:error, error}
    end
  end

  @doc """
  Check if the Vault is currently unsealed.

  This is a convenience function that returns a simple boolean
  indicating if the Vault is ready for operations.

  ## Parameters

  - `opts` - Request options (optional)

  ## Returns

  Returns `{:ok, boolean()}` where true means unsealed and ready,
  or `{:error, Error.t()}` on failure.

  ## Examples

      case Vaultx.Sys.SealStatus.is_unsealed?() do
        {:ok, true} -> IO.puts("Vault is ready")
        {:ok, false} -> IO.puts("Vault is sealed")
        {:error, error} -> IO.puts("Error: \#{error.message}")
      end

  """
  @spec is_unsealed?(Types.options()) :: {:ok, boolean()} | {:error, Error.t()}
  def is_unsealed?(opts \\ []) do
    case get(opts) do
      {:ok, status} -> {:ok, not status.sealed}
      {:error, error} -> {:error, error}
    end
  end

  @doc """
  Wait for the Vault to become unsealed.

  This function polls the seal status until the Vault becomes unsealed
  or the timeout is reached.

  ## Parameters

  - `opts` - Options for the wait operation
    - `:timeout` - Maximum time to wait in milliseconds (default: 60_000)
    - `:interval` - Polling interval in milliseconds (default: 1_000)
    - Other HTTP request options

  ## Returns

  Returns `{:ok, seal_status()}` when Vault becomes unsealed,
  or `{:error, Error.t()}` on timeout or failure.

  ## Examples

      # Wait up to 5 minutes for unseal
      {:ok, status} = Vaultx.Sys.SealStatus.wait_for_unseal(timeout: 300_000)
      IO.puts("Vault is now unsealed!")

      # Custom polling interval
      {:ok, status} = Vaultx.Sys.SealStatus.wait_for_unseal(
        timeout: 120_000,
        interval: 2_000
      )

  """
  @spec wait_for_unseal(Types.options()) :: {:ok, seal_status()} | {:error, Error.t()}
  def wait_for_unseal(opts \\ []) do
    timeout = Keyword.get(opts, :timeout, 60_000)
    interval = Keyword.get(opts, :interval, 1_000)

    metadata = %{
      operation: :wait_for_unseal,
      timeout: timeout,
      interval: interval
    }

    Logger.debug("Waiting for Vault to unseal", metadata)

    end_time = System.monotonic_time(:millisecond) + timeout

    wait_loop(end_time, interval, opts, metadata)
  end

  @doc """
  Get unsealing progress information.

  This function returns detailed progress information for the current
  unsealing process.

  ## Parameters

  - `opts` - Request options (optional)

  ## Returns

  Returns `{:ok, progress_info}` with progress details,
  or `{:error, Error.t()}` on failure.

  ## Examples

      {:ok, progress} = Vaultx.Sys.SealStatus.get_unseal_progress()
      IO.puts("Progress: \#{progress.current}/\#{progress.required}")
      IO.puts("Remaining: \#{progress.remaining}")

  """
  @spec get_unseal_progress(Types.options()) ::
          {:ok, %{current: integer(), required: integer(), remaining: integer()}}
          | {:error, Error.t()}
  def get_unseal_progress(opts \\ []) do
    case get(opts) do
      {:ok, status} ->
        progress_info = %{
          current: status.progress,
          required: status.t,
          remaining: max(0, status.t - status.progress)
        }

        {:ok, progress_info}

      {:error, error} ->
        {:error, error}
    end
  end

  # Private helper functions

  defp wait_loop(end_time, interval, opts, metadata) do
    current_time = System.monotonic_time(:millisecond)

    if current_time >= end_time do
      error = Error.new(:timeout, "Timeout waiting for Vault to unseal")
      Logger.error("Timeout waiting for unseal", Map.put(metadata, :error, error))
      {:error, error}
    else
      case get(opts) do
        {:ok, status} ->
          if status.sealed do
            Logger.debug(
              "Vault still sealed, continuing to wait",
              Map.put(metadata, :progress, status.progress)
            )

            Process.sleep(interval)
            wait_loop(end_time, interval, opts, metadata)
          else
            Logger.info("Vault unsealed successfully", metadata)
            {:ok, status}
          end

        {:error, error} ->
          Logger.error("Error while waiting for unseal", Map.put(metadata, :error, error))
          {:error, error}
      end
    end
  end

  defp parse_seal_status(body) when is_map(body) do
    %{
      sealed: body["sealed"],
      t: body["t"],
      n: body["n"],
      progress: body["progress"],
      version: body["version"],
      build_date: body["build_date"] || "",
      storage_type: body["storage_type"] || "",
      type: body["type"] || "",
      initialized: body["initialized"] || false,
      migration: body["migration"] || false,
      recovery_seal: body["recovery_seal"] || false,
      removed_from_cluster: body["removed_from_cluster"] || false,
      nonce: body["nonce"] || ""
    }
    |> maybe_add_cluster_info(body)
  end

  defp parse_seal_status(_body) do
    # Handle malformed response by returning minimal valid structure
    %{
      sealed: true,
      t: 0,
      n: 0,
      progress: 0,
      version: "",
      build_date: "",
      storage_type: "",
      type: "",
      initialized: false,
      migration: false,
      recovery_seal: false,
      removed_from_cluster: false,
      nonce: ""
    }
  end

  defp maybe_add_cluster_info(status, body) do
    status
    |> maybe_put(:cluster_name, body["cluster_name"])
    |> maybe_put(:cluster_id, body["cluster_id"])
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)
end
