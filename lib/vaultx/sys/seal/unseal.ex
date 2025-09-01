defmodule Vaultx.Sys.Unseal do
  @moduledoc """
  HashiCorp Vault unseal operations.

  This module provides unseal capabilities for Vault, allowing you to submit
  unseal keys to progress the unsealing process. Vault uses Shamir's Secret
  Sharing to require a threshold number of key shares to unseal.

  ## Unseal Operations

  ### Core Functionality
  - Submit Unseal Key: Provide a single unseal key share
  - Reset Process: Clear previously submitted keys and restart
  - Migration Support: Handle seal migration between Shamir and auto-seal
  - Progress Tracking: Monitor unsealing progress

  ### Unsealing Process
  - Threshold-based: Requires minimum number of key shares
  - Progressive: Each key submission advances progress
  - Stateful: Maintains progress across multiple submissions
  - Secure: Keys are processed and discarded immediately

  ## Important Security Notes

  Restricted Endpoint
  - Must be called from the root namespace
  - No authentication required (Vault is sealed)
  - Keys are sensitive and should be handled securely

  Key Management
  - Each key can only be used once per unseal attempt
  - Keys should be distributed among trusted operators
  - Reset clears all previously submitted keys

  Migration Considerations
  - Migration flag must be consistent across all key submissions
  - Used for transitioning between Shamir and auto-seal
  - Requires careful coordination during migration

  ## API Compliance

  Fully implements HashiCorp Vault Unseal API:
  - [Unseal API](https://developer.hashicorp.com/vault/api-docs/system/unseal)
  - [Vault Concepts](https://developer.hashicorp.com/vault/docs/concepts/seal)

  ## Usage Examples

  ### Submit Unseal Key

      {:ok, status} = Vaultx.Sys.Unseal.submit_key("abcd1234...")

      if status.sealed do
        IO.puts("Progress: \#{status.progress}/\#{status.t}")
      else
        IO.puts("Vault unsealed successfully!")
      end

  ### Reset Unseal Process

      {:ok, status} = Vaultx.Sys.Unseal.reset()
      IO.puts("Unseal process reset, progress: \#{status.progress}")

  ### Migration Unseal

      {:ok, status} = Vaultx.Sys.Unseal.submit_key("abcd1234...", migrate: true)

  ### Batch Unseal Operation

      keys = ["key1", "key2", "key3"]
      {:ok, final_status} = Vaultx.Sys.Unseal.submit_keys(keys)

  ## Unseal Status Response

  The unseal operations return status information:

  - `sealed`: Whether Vault is still sealed
  - `t`: Threshold number of keys required
  - `n`: Total number of key shares
  - `progress`: Number of keys submitted so far
  - `version`: Vault version
  - `cluster_name`: Cluster name (when unsealed)
  - `cluster_id`: Cluster ID (when unsealed)

  ## Error Handling

  Common error scenarios:
  - Invalid or malformed keys
  - Duplicate key submission
  - Network connectivity issues
  - Vault configuration problems
  """

  alias Vaultx.Base.{Error, Logger, Telemetry}
  alias Vaultx.Transport.HTTP
  alias Vaultx.Types

  @typedoc """
  Unseal status information.
  """
  @type unseal_status :: %{
          :sealed => boolean(),
          :t => integer(),
          :n => integer(),
          :progress => integer(),
          :version => String.t(),
          optional(:cluster_name) => String.t(),
          optional(:cluster_id) => String.t()
        }

  @doc """
  Submit an unseal key to progress the unsealing process.

  This endpoint is used to enter a single root key share to progress the
  unsealing of the Vault. If the threshold number of root key shares is reached,
  Vault will attempt to unseal. Otherwise, this API must be called multiple
  times until that threshold is met.

  ## Parameters

  - `key` - A single root key share (required unless reset is true)
  - `opts` - Options for the unseal operation
    - `:reset` - Discard previously-provided keys and reset (default: false)
    - `:migrate` - Used for seal migration between Shamir and auto-seal (default: false)
    - Other HTTP request options

  ## Returns

  Returns `{:ok, unseal_status()}` with current unseal status,
  or `{:error, Error.t()}` on failure.

  ## Examples

      # Submit a single unseal key
      {:ok, status} = Vaultx.Sys.Unseal.submit_key("abcd1234...")

      # Check if more keys are needed
      if status.sealed do
        IO.puts("Need \#{status.t - status.progress} more keys")
      else
        IO.puts("Vault is now unsealed!")
      end

      # Submit key with migration flag
      {:ok, status} = Vaultx.Sys.Unseal.submit_key("abcd1234...", migrate: true)

  """
  @spec submit_key(String.t(), Types.options()) :: {:ok, unseal_status()} | {:error, Error.t()}
  def submit_key(key, opts \\ []) when is_binary(key) do
    path = "sys/unseal"

    reset = Keyword.get(opts, :reset, false)
    migrate = Keyword.get(opts, :migrate, false)

    request_body = %{
      key: key,
      reset: reset,
      migrate: migrate
    }

    metadata = %{
      operation: :submit_unseal_key,
      reset: reset,
      migrate: migrate
    }

    Logger.debug("Submitting unseal key", metadata)
    Telemetry.operation_start(metadata)

    start_time = System.monotonic_time()

    case HTTP.post(path, request_body, opts) do
      {:ok, %{status: 200, body: body}} ->
        duration = System.monotonic_time() - start_time

        status = parse_unseal_status(body)

        Logger.info(
          "Successfully submitted unseal key",
          Map.merge(metadata, %{
            sealed: status.sealed,
            progress: status.progress,
            threshold: status.t
          })
        )

        Telemetry.operation_success(duration, metadata)

        {:ok, status}

      {:ok, %{status: status_code, body: body}} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:server_error, "Failed to submit unseal key: HTTP #{status_code}",
            details: %{status: status_code, body: body}
          )

        Logger.error("Failed to submit unseal key", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Error submitting unseal key", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Reset the unseal process by discarding previously submitted keys.

  This operation clears all previously submitted unseal keys and resets
  the progress counter to zero.

  ## Parameters

  - `opts` - Request options (optional)

  ## Returns

  Returns `{:ok, unseal_status()}` with reset status,
  or `{:error, Error.t()}` on failure.

  ## Examples

      {:ok, status} = Vaultx.Sys.Unseal.reset()
      IO.puts("Unseal process reset, progress: \#{status.progress}")

  """
  @spec reset(Types.options()) :: {:ok, unseal_status()} | {:error, Error.t()}
  def reset(opts \\ []) do
    path = "sys/unseal"

    request_body = %{reset: true}

    metadata = %{operation: :reset_unseal_process}
    Logger.debug("Resetting unseal process", metadata)
    Telemetry.operation_start(metadata)

    start_time = System.monotonic_time()

    case HTTP.post(path, request_body, opts) do
      {:ok, %{status: 200, body: body}} ->
        duration = System.monotonic_time() - start_time

        status = parse_unseal_status(body)

        Logger.info(
          "Successfully reset unseal process",
          Map.merge(metadata, %{progress: status.progress})
        )

        Telemetry.operation_success(duration, metadata)

        {:ok, status}

      {:ok, %{status: status_code, body: body}} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:server_error, "Failed to reset unseal process: HTTP #{status_code}",
            details: %{status: status_code, body: body}
          )

        Logger.error("Failed to reset unseal process", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Error resetting unseal process", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Submit multiple unseal keys in sequence.

  This is a convenience function that submits multiple keys one by one
  until the Vault is unsealed or all keys are exhausted.

  ## Parameters

  - `keys` - List of unseal key shares
  - `opts` - Options for the unseal operations
    - `:migrate` - Used for seal migration (default: false)
    - `:stop_on_unseal` - Stop when Vault is unsealed (default: true)
    - Other HTTP request options

  ## Returns

  Returns `{:ok, unseal_status()}` with final status,
  or `{:error, Error.t()}` on failure.

  ## Examples

      keys = ["key1", "key2", "key3"]
      {:ok, final_status} = Vaultx.Sys.Unseal.submit_keys(keys)

      if final_status.sealed do
        IO.puts("Still need \#{final_status.t - final_status.progress} more keys")
      else
        IO.puts("Vault successfully unsealed!")
      end

  """
  @spec submit_keys([String.t()], Types.options()) :: {:ok, unseal_status()} | {:error, Error.t()}
  def submit_keys(keys, opts \\ []) when is_list(keys) do
    stop_on_unseal = Keyword.get(opts, :stop_on_unseal, true)

    metadata = %{
      operation: :submit_multiple_unseal_keys,
      key_count: length(keys),
      stop_on_unseal: stop_on_unseal
    }

    Logger.debug("Submitting multiple unseal keys", metadata)

    keys
    |> Enum.reduce_while({:ok, nil}, fn key, {:ok, _status} ->
      case submit_key(key, opts) do
        {:ok, new_status} ->
          if stop_on_unseal and not new_status.sealed do
            Logger.info(
              "Vault unsealed, stopping key submission",
              Map.put(metadata, :final_progress, new_status.progress)
            )

            {:halt, {:ok, new_status}}
          else
            {:cont, {:ok, new_status}}
          end

        {:error, error} ->
          {:halt, {:error, error}}
      end
    end)
  end

  # Private helper functions

  defp parse_unseal_status(body) do
    %{
      sealed: body["sealed"],
      t: body["t"],
      n: body["n"],
      progress: body["progress"],
      version: body["version"]
    }
    |> maybe_add_cluster_info(body)
  end

  defp maybe_add_cluster_info(status, body) do
    status
    |> maybe_put(:cluster_name, body["cluster_name"])
    |> maybe_put(:cluster_id, body["cluster_id"])
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)
end
