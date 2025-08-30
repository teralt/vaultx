defmodule Vaultx.Secrets.KV.V1 do
  @moduledoc """
  HashiCorp Vault KV v1 secrets engine implementation.

  This module provides a complete implementation of the KV v1 secrets engine,
  offering simple, direct key-value storage without versioning complexity.
  KV v1 is ideal for straightforward secret storage where versioning and
  metadata are not required.

  ## Key Characteristics

  - Simplicity: Direct key-value storage without versioning overhead
  - Performance: Minimal API calls and storage requirements
  - Legacy Support: Compatible with older Vault installations
  - Immediate Operations: All changes are immediate and permanent
  - Direct Access: Simple path-based secret access

  ## API Compliance

  Fully implements HashiCorp Vault KV v1 API:
  - [KV v1 API Documentation](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v1)

  ## HTTP Endpoints

  KV v1 uses direct mount paths without data prefixes:

  - `GET /{mount}/{path}` - Read secret data
  - `POST /{mount}/{path}` - Write secret data
  - `DELETE /{mount}/{path}` - Delete secret permanently
  - `LIST /{mount}/{path}` - List secret keys

  ## Usage Examples

      # Read a secret
      {:ok, secret} = Vaultx.Secrets.KV.V1.read("myapp/config", mount_path: "secret")

      # Write a secret
      :ok = Vaultx.Secrets.KV.V1.write("myapp/config", %{"key" => "value"}, mount_path: "secret")

      # Delete a secret
      :ok = Vaultx.Secrets.KV.V1.delete("myapp/config", mount_path: "secret")

      # List secrets
      {:ok, keys} = Vaultx.Secrets.KV.V1.list("myapp/", mount_path: "secret")

  ## Configuration

      # Enable KV v1 engine
      vault secrets enable -version=1 -path=kv-v1 kv

  ## Limitations

  - No versioning support
  - No metadata support
  - No soft delete (deletion is permanent)
  - No check-and-set operations
  - No undelete or destroy operations

  ## Migration

  When migrating from KV v1 to KV v2, consider:

  - KV v2 stores data under `/data/` path
  - KV v2 provides versioning and metadata
  - Migration tools are available in Vault CLI
  """

  @behaviour Vaultx.Secrets.KV.Behaviour

  alias Vaultx.Base.{Error, Logger, Security, Telemetry}
  alias Vaultx.Transport.HTTP
  alias Vaultx.Types

  @default_mount_path "secret"

  def read(path, opts \\ []) do
    with :ok <- validate_path(path),
         :ok <- validate_opts(opts) do
      mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

      metadata = %{
        engine: :kv,
        version: 1,
        operation: :read,
        path: path,
        mount_path: mount_path
      }

      Logger.debug("Reading KV v1 secret", metadata)
      Telemetry.operation_start(metadata)

      start_time = System.monotonic_time()

      case HTTP.get("/v1/#{mount_path}/#{path}", opts) do
        {:ok, %{status: 200, body: %{"data" => data}}} ->
          duration = System.monotonic_time() - start_time

          secret_data = %Types.SecretData{
            data: data,
            metadata: nil,
            version: nil,
            created_time: nil,
            deletion_time: nil,
            destroyed: false
          }

          Logger.debug(
            "Successfully read KV v1 secret",
            Map.put(metadata, :data_keys, Map.keys(data))
          )

          Telemetry.operation_success(duration, metadata)

          {:ok, secret_data}

        {:ok, %{status: 404}} ->
          duration = System.monotonic_time() - start_time
          error = Error.new(:not_found, "Secret not found at path: #{path}")

          Logger.debug("KV v1 secret not found", Map.put(metadata, :error, error))
          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}

        {:ok, %{status: status, body: body}} ->
          duration = System.monotonic_time() - start_time

          error =
            Error.new(:server_error, "Unexpected response: #{status}", details: %{body: body})

          Logger.error(
            "KV v1 read failed with unexpected status",
            Map.merge(metadata, %{status: status, error: error})
          )

          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}

        {:error, reason} ->
          duration = System.monotonic_time() - start_time
          error = Error.new(:network_error, "HTTP request failed", details: %{reason: reason})

          Logger.error(
            "KV v1 read transport error",
            Map.merge(metadata, %{reason: reason, error: error})
          )

          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}
      end
    else
      # If a validation already returned an Error struct, pass it through
      {:error, %Error{} = err} ->
        {:error, err}
    end
  end

  def write(path, data, opts \\ []) do
    with :ok <- validate_path(path),
         :ok <- validate_opts(opts),
         :ok <- validate_secret_data(data) do
      mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

      metadata = %{
        engine: :kv,
        version: 1,
        operation: :write,
        path: path,
        mount_path: mount_path,
        data_keys: Map.keys(data)
      }

      Logger.debug("Writing KV v1 secret", metadata)
      Telemetry.operation_start(metadata)

      start_time = System.monotonic_time()

      case HTTP.post("/v1/#{mount_path}/#{path}", data, opts) do
        {:ok, %{status: status}} when status in [200, 204] ->
          duration = System.monotonic_time() - start_time

          write_result = %Types.WriteResult{
            version: nil,
            created_time: DateTime.utc_now(),
            deletion_time: nil,
            destroyed: false
          }

          Logger.debug("Successfully wrote KV v1 secret", metadata)
          Telemetry.operation_success(duration, metadata)

          {:ok, write_result}

        {:ok, %{status: status, body: body}} ->
          duration = System.monotonic_time() - start_time

          error =
            Error.new(:server_error, "Write failed with status: #{status}",
              details: %{body: body}
            )

          Logger.error("KV v1 write failed", Map.merge(metadata, %{status: status, error: error}))
          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}

        {:error, reason} ->
          duration = System.monotonic_time() - start_time
          error = Error.new(:network_error, "HTTP request failed", details: %{reason: reason})

          Logger.error(
            "KV v1 write transport error",
            Map.merge(metadata, %{reason: reason, error: error})
          )

          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}
      end
    else
      # If a validation already returned an Error struct, pass it through
      {:error, %Error{} = err} ->
        {:error, err}
    end
  end

  def delete(path, opts \\ []) do
    with :ok <- validate_path(path),
         :ok <- validate_opts(opts) do
      mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

      metadata = %{
        engine: :kv,
        version: 1,
        operation: :delete,
        path: path,
        mount_path: mount_path
      }

      Logger.debug("Deleting KV v1 secret", metadata)
      Telemetry.operation_start(metadata)

      start_time = System.monotonic_time()

      case HTTP.delete("/v1/#{mount_path}/#{path}", opts) do
        {:ok, %{status: status}} when status in [200, 204] ->
          duration = System.monotonic_time() - start_time

          Logger.debug("Successfully deleted KV v1 secret", metadata)
          Telemetry.operation_success(duration, metadata)

          :ok

        {:ok, %{status: 404}} ->
          duration = System.monotonic_time() - start_time
          error = Error.new(:not_found, "Secret not found at path: #{path}")

          Logger.debug("KV v1 secret not found for deletion", Map.put(metadata, :error, error))
          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}

        {:ok, %{status: status, body: body}} ->
          duration = System.monotonic_time() - start_time

          error =
            Error.new(:server_error, "Delete failed with status: #{status}",
              details: %{body: body}
            )

          Logger.error(
            "KV v1 delete failed",
            Map.merge(metadata, %{status: status, error: error})
          )

          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}

        {:error, reason} ->
          duration = System.monotonic_time() - start_time
          error = Error.new(:network_error, "HTTP request failed", details: %{reason: reason})

          Logger.error(
            "KV v1 delete transport error",
            Map.merge(metadata, %{reason: reason, error: error})
          )

          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}
      end
    else
      # If a validation already returned an Error struct, pass it through
      {:error, %Error{} = err} ->
        {:error, err}
    end
  end

  def list(path, opts \\ []) do
    with :ok <- validate_path(path),
         :ok <- validate_opts(opts) do
      mount_path = Keyword.get(opts, :mount_path, @default_mount_path)
      # Ensure path ends with / for listing
      list_path = if String.ends_with?(path, "/"), do: path, else: path <> "/"

      metadata = %{
        engine: :kv,
        version: 1,
        operation: :list,
        path: list_path,
        mount_path: mount_path
      }

      Logger.debug("Listing KV v1 secrets", metadata)
      Telemetry.operation_start(metadata)

      start_time = System.monotonic_time()

      case HTTP.get("/v1/#{mount_path}/#{list_path}?list=true", opts) do
        {:ok, %{status: 200, body: %{"data" => %{"keys" => keys}}}} ->
          duration = System.monotonic_time() - start_time

          list_result = %Types.ListResult{
            keys: keys,
            metadata: nil
          }

          Logger.debug(
            "Successfully listed KV v1 secrets",
            Map.merge(metadata, %{count: length(keys)})
          )

          Telemetry.operation_success(duration, metadata)

          {:ok, list_result}

        {:ok, %{status: 404}} ->
          duration = System.monotonic_time() - start_time
          error = Error.new(:not_found, "Path not found: #{list_path}")

          Logger.debug("KV v1 path not found for listing", Map.put(metadata, :error, error))
          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}

        {:ok, %{status: status, body: body}} ->
          duration = System.monotonic_time() - start_time

          error =
            Error.new(:server_error, "List failed with status: #{status}", details: %{body: body})

          Logger.error("KV v1 list failed", Map.merge(metadata, %{status: status, error: error}))
          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}

        {:error, reason} ->
          duration = System.monotonic_time() - start_time
          error = Error.new(:network_error, "HTTP request failed", details: %{reason: reason})

          Logger.error(
            "KV v1 list transport error",
            Map.merge(metadata, %{reason: reason, error: error})
          )

          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}
      end
    else
      # If a validation already returned an Error struct, pass it through
      {:error, %Error{} = err} ->
        {:error, err}
    end
  end

  def configure(_config, _opts \\ []) do
    # KV v1 doesn't support configuration
    {:error, Error.new(:not_implemented, "KV v1 does not support configuration")}
  end

  def metadata do
    {:ok,
     %Types.EngineMetadata{
       type: :kv,
       version: 1,
       capabilities: [:read, :write, :delete, :list],
       configuration: %{},
       mount_path: @default_mount_path
     }}
  end

  def health_check(_opts \\ []) do
    # Simple health check - try to list root path
    case list("health-check", []) do
      {:ok, _} ->
        {:ok,
         %Types.HealthStatus{
           healthy: true,
           details: %{engine: "kv", version: 1},
           timestamp: DateTime.utc_now()
         }}

      {:error, error} ->
        {:ok,
         %Types.HealthStatus{
           healthy: false,
           details: %{engine: "kv", version: 1, error: error},
           timestamp: DateTime.utc_now()
         }}
    end
  end

  # KV v1 doesn't support these operations - return appropriate errors
  @impl Vaultx.Secrets.KV.Behaviour
  def read_metadata(_path, _opts),
    do: {:error, Error.new(:not_implemented, "KV v1 does not support metadata operations")}

  @impl Vaultx.Secrets.KV.Behaviour
  def write_metadata(_path, _metadata, _opts),
    do: {:error, Error.new(:not_implemented, "KV v1 does not support metadata operations")}

  @impl Vaultx.Secrets.KV.Behaviour
  def delete_metadata(_path, _opts),
    do: {:error, Error.new(:not_implemented, "KV v1 does not support metadata operations")}

  @impl Vaultx.Secrets.KV.Behaviour
  def undelete(_path, _opts),
    do: {:error, Error.new(:not_implemented, "KV v1 does not support undelete operations")}

  @impl Vaultx.Secrets.KV.Behaviour
  def destroy(_path, _opts),
    do: {:error, Error.new(:not_implemented, "KV v1 does not support destroy operations")}

  @impl Vaultx.Secrets.KV.Behaviour
  def list_versions(_path, _opts),
    do: {:error, Error.new(:not_implemented, "KV v1 does not support versioning")}

  # Private helper functions

  defp validate_secret_data(data) when is_map(data), do: :ok

  defp validate_secret_data(_),
    do: {:error, Error.new(:invalid_request, "Secret data must be a map")}

  # Path validation using Security module
  defp validate_path(path) do
    case Security.validate_path(path) do
      :ok -> :ok
      {:error, reason} -> {:error, Error.new(:invalid_request, reason)}
    end
  end

  # Options validation - basic validation for keyword lists
  defp validate_opts(opts) when is_list(opts), do: :ok

  defp validate_opts(_),
    do: {:error, Error.new(:invalid_request, "Options must be a keyword list")}
end
