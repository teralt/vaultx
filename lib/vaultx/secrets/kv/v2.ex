defmodule Vaultx.Secrets.KV.V2 do
  @moduledoc """
  HashiCorp Vault KV v2 secrets engine implementation.

  This module provides a comprehensive implementation of the KV v2 secrets
  engine, offering advanced key-value storage with versioning, metadata
  management, and sophisticated secret lifecycle capabilities. KV v2 is
  the modern, feature-rich version of Vault's key-value storage.

  ## Advanced Features

  - Versioned Storage: Automatic versioning of all secret changes
  - Metadata Management: Rich metadata tracking for secrets and versions
  - Check-and-Set (CAS): Atomic updates with version validation
  - Soft Delete: Reversible deletion with recovery capabilities
  - Permanent Destruction: Secure, irreversible version removal
  - Configurable Policies: Version limits, TTL, and retention policies
  - Audit Trail: Complete history of secret modifications

  ## API Compliance

  Fully implements HashiCorp Vault KV v2 API:
  - [KV v2 API Documentation](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2)

  ## HTTP Endpoints

  KV v2 uses structured paths with `/data/` and `/metadata/` prefixes:

  - `GET /{mount}/data/{path}` - Read secret data
  - `POST /{mount}/data/{path}` - Write secret data
  - `DELETE /{mount}/data/{path}` - Soft delete latest version
  - `GET /{mount}/metadata/{path}` - Read secret metadata
  - `POST /{mount}/metadata/{path}` - Write secret metadata
  - `DELETE /{mount}/metadata/{path}` - Delete all versions and metadata
  - `POST /{mount}/undelete/{path}` - Undelete specific versions
  - `POST /{mount}/destroy/{path}` - Permanently destroy versions
  - `LIST /{mount}/metadata/{path}` - List secrets

  ## Usage Examples

      # Read latest version
      {:ok, secret} = Vaultx.Secrets.KV.V2.read("myapp/config", mount_path: "secret")

      # Read specific version
      {:ok, secret} = Vaultx.Secrets.KV.V2.read("myapp/config", version: 2, mount_path: "secret")

      # Write with check-and-set
      {:ok, result} = Vaultx.Secrets.KV.V2.write("myapp/config", %{"key" => "value"}, cas: 1, mount_path: "secret")

      # Soft delete (reversible)
      :ok = Vaultx.Secrets.KV.V2.delete("myapp/config", versions: [2], mount_path: "secret")

      # Undelete versions
      :ok = Vaultx.Secrets.KV.V2.undelete("myapp/config", versions: [2], mount_path: "secret")

      # Permanently destroy
      :ok = Vaultx.Secrets.KV.V2.destroy("myapp/config", versions: [1], mount_path: "secret")

  ## Configuration

      # Enable KV v2 engine (default for new installations)
      vault secrets enable -version=2 -path=secret kv

      # Configure engine settings
      vault write secret/config max_versions=10 cas_required=false delete_version_after="0s"

  ## Version Management

  - Each write operation creates a new version (1, 2, 3, ...)
  - Versions can be soft-deleted (marked as deleted but recoverable)
  - Versions can be permanently destroyed (irreversible)
  - Maximum versions can be configured to auto-delete old versions
  - Auto-deletion timers can be set for automatic cleanup

  ## Metadata Structure

  KV v2 maintains rich metadata including:
  - Version information (created_time, deletion_time, destroyed)
  - Custom metadata fields
  - Version history and status
  - Configuration settings
  """

  @behaviour Vaultx.Secrets.KV.Behaviour

  alias Vaultx.Base.{Error, Logger, Security, Telemetry}
  alias Vaultx.Cache
  alias Vaultx.Transport.HTTP

  @default_mount_path "secret"

  def read(path, opts \\ []) do
    with :ok <- validate_path(path),
         :ok <- validate_opts(opts) do
      mount_path = Keyword.get(opts, :mount_path, @default_mount_path)
      version = Keyword.get(opts, :version)
      use_cache = Keyword.get(opts, :cache, true)

      metadata = %{
        engine: :kv,
        version: 2,
        operation: :read,
        path: path,
        mount_path: mount_path,
        requested_version: version,
        cache_enabled: use_cache
      }

      Logger.debug("Reading KV v2 secret", metadata)
      Telemetry.operation_start(metadata)

      # Try cache first if enabled
      if use_cache do
        cache_key = build_cache_key(mount_path, path, version)

        Cache.get_or_compute(
          cache_key,
          fn ->
            do_read_from_vault(mount_path, path, version, opts)
          end,
          ttl: :timer.minutes(15)
        )
      else
        do_read_from_vault(mount_path, path, version, opts)
      end
    end
  end

  # Private helper functions for caching

  defp build_cache_key(mount_path, path, version) do
    # Use a more robust key format to avoid conflicts
    base_key = "kv2:#{mount_path}:#{path}"

    if version do
      # Use a separator that's unlikely to appear in paths
      "#{base_key}|version:#{version}"
    else
      "#{base_key}|latest"
    end
  end

  defp do_read_from_vault(mount_path, path, version, opts) do
    # Build query parameters
    query_params = if version, do: [version: version], else: []

    case HTTP.get("#{mount_path}/data/#{path}?#{URI.encode_query(query_params)}", opts) do
      {:ok, %{status: 200, body: %{"data" => response_data}}} ->
        secret_data = %{
          data: response_data["data"] || %{},
          metadata: response_data["metadata"],
          version: response_data["metadata"]["version"],
          created_time: parse_datetime(response_data["metadata"]["created_time"]),
          deletion_time: parse_datetime(response_data["metadata"]["deletion_time"]),
          destroyed: response_data["metadata"]["destroyed"] || false
        }

        {:ok, secret_data}

      {:ok, %{status: 404}} ->
        error =
          if version do
            Error.new(:not_found, "Version #{version} not found at path: #{path}")
          else
            Error.new(:not_found, "Secret not found at path: #{path}")
          end

        {:error, error}

      {:ok, %{status: status, body: body}} ->
        error = Error.new(:server_error, "Unexpected response: #{status}", details: %{body: body})
        {:error, error}

      {:error, reason} ->
        error = Error.new(:network_error, "HTTP request failed", details: %{reason: reason})
        {:error, error}
    end
  end

  def write(path, data, opts \\ []) do
    with :ok <- validate_path(path),
         :ok <- validate_opts(opts),
         :ok <- validate_secret_data(data) do
      mount_path = Keyword.get(opts, :mount_path, @default_mount_path)
      cas = Keyword.get(opts, :cas)

      metadata = %{
        engine: :kv,
        version: 2,
        operation: :write,
        path: path,
        mount_path: mount_path,
        cas: cas,
        data_keys: Map.keys(data)
      }

      Logger.debug("Writing KV v2 secret", metadata)
      Telemetry.operation_start(metadata)

      start_time = System.monotonic_time()

      # Build request body
      request_body = %{"data" => data}

      request_body =
        if cas, do: Map.put(request_body, "options", %{"cas" => cas}), else: request_body

      case HTTP.post("#{mount_path}/data/#{path}", request_body, opts) do
        {:ok, %{status: 200, body: %{"data" => response_data}}} ->
          duration = System.monotonic_time() - start_time

          write_result = %{
            version: response_data["version"],
            created_time: parse_datetime(response_data["created_time"]),
            deletion_time: parse_datetime(response_data["deletion_time"]),
            destroyed: response_data["destroyed"] || false
          }

          Logger.debug(
            "Successfully wrote KV v2 secret",
            Map.merge(metadata, %{
              result_version: write_result.version
            })
          )

          Telemetry.operation_success(duration, metadata)

          # Clear cache entries for this path (all versions)
          clear_cache_for_path(mount_path, path)

          {:ok, write_result}

        {:ok, %{status: 400, body: %{"errors" => errors}}} when is_list(errors) ->
          duration = System.monotonic_time() - start_time
          error_msg = Enum.join(errors, "; ")

          error =
            cond do
              String.contains?(error_msg, "check-and-set parameter") ->
                Error.new(:invalid_request, "Check-and-set parameter mismatch",
                  details: %{cas: cas, path: path}
                )

              String.contains?(error_msg, "cannot write to a destroyed version") ->
                Error.new(:invalid_request, "Cannot write to a destroyed version",
                  details: %{path: path}
                )

              true ->
                Error.new(:server_error, "Write failed: #{error_msg}", details: %{errors: errors})
            end

          Logger.error(
            "KV v2 write failed with validation error",
            Map.merge(metadata, %{error: error, errors: errors})
          )

          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}

        {:ok, %{status: status, body: body}} ->
          duration = System.monotonic_time() - start_time

          error =
            Error.new(:server_error, "Write failed with status: #{status}",
              details: %{body: body}
            )

          Logger.error("KV v2 write failed", Map.merge(metadata, %{status: status, error: error}))
          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}

        {:error, reason} ->
          duration = System.monotonic_time() - start_time
          error = Error.new(:network_error, "HTTP request failed", details: %{reason: reason})

          Logger.error(
            "KV v2 write transport error",
            Map.merge(metadata, %{reason: reason, error: error})
          )

          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}
      end
    end
  end

  def delete(path, opts \\ []) do
    with :ok <- validate_path(path),
         :ok <- validate_opts(opts) do
      mount_path = Keyword.get(opts, :mount_path, @default_mount_path)
      versions = Keyword.get(opts, :versions, [])

      metadata = %{
        engine: :kv,
        version: 2,
        operation: :delete,
        path: path,
        mount_path: mount_path,
        versions: versions
      }

      Logger.debug("Deleting KV v2 secret", metadata)
      Telemetry.operation_start(metadata)

      start_time = System.monotonic_time()

      # Determine delete endpoint and payload
      {endpoint, payload} =
        if Enum.empty?(versions) do
          # Delete latest version
          {"#{mount_path}/data/#{path}", nil}
        else
          # Delete specific versions
          {"#{mount_path}/delete/#{path}", %{"versions" => versions}}
        end

      case HTTP.post(endpoint, payload, opts) do
        {:ok, %{status: status}} when status in [200, 204] ->
          duration = System.monotonic_time() - start_time

          Logger.debug("Successfully deleted KV v2 secret", metadata)
          Telemetry.operation_success(duration, metadata)

          # Clear cache entries for this path
          clear_cache_for_path(mount_path, path)

          :ok

        {:ok, %{status: 404}} ->
          duration = System.monotonic_time() - start_time
          error = Error.new(:not_found, "Secret not found at path: #{path}")

          Logger.debug("KV v2 secret not found for deletion", Map.put(metadata, :error, error))
          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}

        {:ok, %{status: status, body: body}} ->
          duration = System.monotonic_time() - start_time

          error =
            Error.new(:server_error, "Delete failed with status: #{status}",
              details: %{body: body}
            )

          Logger.error(
            "KV v2 delete failed",
            Map.merge(metadata, %{status: status, error: error})
          )

          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}

        {:error, reason} ->
          duration = System.monotonic_time() - start_time
          error = Error.new(:network_error, "HTTP request failed", details: %{reason: reason})

          Logger.error(
            "KV v2 delete transport error",
            Map.merge(metadata, %{reason: reason, error: error})
          )

          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}
      end
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
        version: 2,
        operation: :list,
        path: list_path,
        mount_path: mount_path
      }

      Logger.debug("Listing KV v2 secrets", metadata)
      Telemetry.operation_start(metadata)

      start_time = System.monotonic_time()

      case HTTP.get("#{mount_path}/metadata/#{list_path}?list=true", opts) do
        {:ok, %{status: 200, body: %{"data" => %{"keys" => keys}}}} ->
          duration = System.monotonic_time() - start_time

          list_result = %{
            keys: keys,
            metadata: nil
          }

          Logger.debug(
            "Successfully listed KV v2 secrets",
            Map.merge(metadata, %{count: length(keys)})
          )

          Telemetry.operation_success(duration, metadata)

          {:ok, list_result}

        {:ok, %{status: 404}} ->
          duration = System.monotonic_time() - start_time
          error = Error.new(:not_found, "Path not found: #{list_path}")

          Logger.debug("KV v2 path not found for listing", Map.put(metadata, :error, error))
          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}

        {:ok, %{status: status, body: body}} ->
          duration = System.monotonic_time() - start_time

          error =
            Error.new(:server_error, "List failed with status: #{status}", details: %{body: body})

          Logger.error("KV v2 list failed", Map.merge(metadata, %{status: status, error: error}))
          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}

        {:error, reason} ->
          duration = System.monotonic_time() - start_time
          error = Error.new(:network_error, "HTTP request failed", details: %{reason: reason})

          Logger.error(
            "KV v2 list transport error",
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

  def configure(config, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    metadata = %{
      engine: :kv,
      version: 2,
      operation: :configure,
      mount_path: mount_path,
      config_keys: Map.keys(config)
    }

    Logger.debug("Configuring KV v2 engine", metadata)
    Telemetry.operation_start(metadata)

    start_time = System.monotonic_time()

    case HTTP.post("#{mount_path}/config", config, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        duration = System.monotonic_time() - start_time

        Logger.debug("Successfully configured KV v2 engine", metadata)
        Telemetry.operation_success(duration, metadata)

        :ok

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:server_error, "Configuration failed with status: #{status}",
            details: %{body: body}
          )

        Logger.error(
          "KV v2 configuration failed",
          Map.merge(metadata, %{status: status, error: error})
        )

        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:network_error, "HTTP request failed", details: %{reason: reason})

        Logger.error(
          "KV v2 configuration transport error",
          Map.merge(metadata, %{reason: reason, error: error})
        )

        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @impl Vaultx.Secrets.KV.Behaviour
  def read_metadata(path, opts \\ []) do
    with :ok <- validate_path(path),
         :ok <- validate_opts(opts) do
      mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

      metadata = %{
        engine: :kv,
        version: 2,
        operation: :read_metadata,
        path: path,
        mount_path: mount_path
      }

      Logger.debug("Reading KV v2 metadata", metadata)
      Telemetry.operation_start(metadata)

      start_time = System.monotonic_time()

      case HTTP.get("#{mount_path}/metadata/#{path}", opts) do
        {:ok, %{status: 200, body: %{"data" => response_data}}} ->
          duration = System.monotonic_time() - start_time

          secret_data = %{
            data: %{},
            metadata: response_data,
            version: nil,
            created_time: parse_datetime(response_data["created_time"]),
            deletion_time: parse_datetime(response_data["deletion_time"]),
            destroyed: false
          }

          Logger.debug("Successfully read KV v2 metadata", metadata)
          Telemetry.operation_success(duration, metadata)

          {:ok, secret_data}

        {:ok, %{status: 404}} ->
          duration = System.monotonic_time() - start_time
          error = Error.new(:not_found, "Metadata not found at path: #{path}")

          Logger.debug("KV v2 metadata not found", Map.put(metadata, :error, error))
          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}

        {:ok, %{status: status, body: body}} ->
          duration = System.monotonic_time() - start_time

          error =
            Error.new(:server_error, "Metadata read failed with status: #{status}",
              details: %{body: body}
            )

          Logger.error(
            "KV v2 metadata read failed",
            Map.merge(metadata, %{status: status, error: error})
          )

          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}

        {:error, reason} ->
          duration = System.monotonic_time() - start_time
          error = Error.new(:network_error, "HTTP request failed", details: %{reason: reason})

          Logger.error(
            "KV v2 metadata read transport error",
            Map.merge(metadata, %{reason: reason, error: error})
          )

          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}
      end
    end
  end

  @impl Vaultx.Secrets.KV.Behaviour
  def write_metadata(path, metadata_data, opts \\ []) do
    with :ok <- validate_path(path),
         :ok <- validate_opts(opts),
         :ok <- validate_metadata(metadata_data) do
      mount_path = Keyword.get(opts, :mount_path, @default_mount_path)
      cas = Keyword.get(opts, :cas)

      metadata = %{
        engine: :kv,
        version: 2,
        operation: :write_metadata,
        path: path,
        mount_path: mount_path,
        cas: cas
      }

      Logger.debug("Writing KV v2 metadata", metadata)
      Telemetry.operation_start(metadata)

      start_time = System.monotonic_time()

      # Build request body
      request_body = metadata_data
      request_body = if cas, do: Map.put(request_body, "cas_required", cas), else: request_body

      case HTTP.post("#{mount_path}/metadata/#{path}", request_body, opts) do
        {:ok, %{status: status}} when status in [200, 204] ->
          duration = System.monotonic_time() - start_time

          Logger.debug("Successfully wrote KV v2 metadata", metadata)
          Telemetry.operation_success(duration, metadata)

          :ok

        {:ok, %{status: status, body: body}} ->
          duration = System.monotonic_time() - start_time

          error =
            Error.new(:server_error, "Metadata write failed with status: #{status}",
              details: %{body: body}
            )

          Logger.error(
            "KV v2 metadata write failed",
            Map.merge(metadata, %{status: status, error: error})
          )

          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}

        {:error, reason} ->
          duration = System.monotonic_time() - start_time
          error = Error.new(:network_error, "HTTP request failed", details: %{reason: reason})

          Logger.error(
            "KV v2 metadata write transport error",
            Map.merge(metadata, %{reason: reason, error: error})
          )

          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}
      end
    end
  end

  @impl Vaultx.Secrets.KV.Behaviour
  def delete_metadata(path, opts \\ []) do
    with :ok <- validate_path(path),
         :ok <- validate_opts(opts) do
      mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

      metadata = %{
        engine: :kv,
        version: 2,
        operation: :delete_metadata,
        path: path,
        mount_path: mount_path
      }

      Logger.debug("Deleting KV v2 metadata", metadata)
      Telemetry.operation_start(metadata)

      start_time = System.monotonic_time()

      case HTTP.delete("#{mount_path}/metadata/#{path}", opts) do
        {:ok, %{status: status}} when status in [200, 204] ->
          duration = System.monotonic_time() - start_time

          Logger.debug("Successfully deleted KV v2 metadata", metadata)
          Telemetry.operation_success(duration, metadata)

          :ok

        {:ok, %{status: 404}} ->
          duration = System.monotonic_time() - start_time
          error = Error.new(:not_found, "Metadata not found at path: #{path}")

          Logger.debug("KV v2 metadata not found for deletion", Map.put(metadata, :error, error))
          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}

        {:ok, %{status: status, body: body}} ->
          duration = System.monotonic_time() - start_time

          error =
            Error.new(:server_error, "Metadata delete failed with status: #{status}",
              details: %{body: body}
            )

          Logger.error(
            "KV v2 metadata delete failed",
            Map.merge(metadata, %{status: status, error: error})
          )

          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}

        {:error, reason} ->
          duration = System.monotonic_time() - start_time
          error = Error.new(:network_error, "HTTP request failed", details: %{reason: reason})

          Logger.error(
            "KV v2 metadata delete transport error",
            Map.merge(metadata, %{reason: reason, error: error})
          )

          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}
      end
    end
  end

  @impl Vaultx.Secrets.KV.Behaviour
  def undelete(path, opts \\ []) do
    with :ok <- validate_path(path),
         :ok <- validate_opts(opts) do
      mount_path = Keyword.get(opts, :mount_path, @default_mount_path)
      versions = Keyword.get(opts, :versions, [])

      if Enum.empty?(versions) do
        {:error, Error.new(:invalid_request, "Versions list is required for undelete operation")}
      else
        metadata = %{
          engine: :kv,
          version: 2,
          operation: :undelete,
          path: path,
          mount_path: mount_path,
          versions: versions
        }

        Logger.debug("Undeleting KV v2 secret versions", metadata)
        Telemetry.operation_start(metadata)

        start_time = System.monotonic_time()

        case HTTP.post("#{mount_path}/undelete/#{path}", %{"versions" => versions}, opts) do
          {:ok, %{status: status}} when status in [200, 204] ->
            duration = System.monotonic_time() - start_time

            Logger.debug("Successfully undeleted KV v2 secret versions", metadata)
            Telemetry.operation_success(duration, metadata)

            :ok

          {:ok, %{status: 404}} ->
            duration = System.monotonic_time() - start_time
            error = Error.new(:not_found, "Secret not found at path: #{path}")

            Logger.debug("KV v2 secret not found for undelete", Map.put(metadata, :error, error))
            Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

            {:error, error}

          {:ok, %{status: status, body: body}} ->
            duration = System.monotonic_time() - start_time

            error =
              Error.new(:server_error, "Undelete failed with status: #{status}",
                details: %{body: body}
              )

            Logger.error(
              "KV v2 undelete failed",
              Map.merge(metadata, %{status: status, error: error})
            )

            Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

            {:error, error}

          {:error, reason} ->
            duration = System.monotonic_time() - start_time
            error = Error.new(:network_error, "HTTP request failed", details: %{reason: reason})

            Logger.error(
              "KV v2 undelete transport error",
              Map.merge(metadata, %{reason: reason, error: error})
            )

            Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

            {:error, error}
        end
      end
    end
  end

  @impl Vaultx.Secrets.KV.Behaviour
  def destroy(path, opts \\ []) do
    with :ok <- validate_path(path),
         :ok <- validate_opts(opts) do
      mount_path = Keyword.get(opts, :mount_path, @default_mount_path)
      versions = Keyword.get(opts, :versions, [])

      if Enum.empty?(versions) do
        {:error, Error.new(:invalid_request, "Versions list is required for destroy operation")}
      else
        metadata = %{
          engine: :kv,
          version: 2,
          operation: :destroy,
          path: path,
          mount_path: mount_path,
          versions: versions
        }

        Logger.debug("Destroying KV v2 secret versions", metadata)
        Telemetry.operation_start(metadata)

        start_time = System.monotonic_time()

        case HTTP.post("#{mount_path}/destroy/#{path}", %{"versions" => versions}, opts) do
          {:ok, %{status: status}} when status in [200, 204] ->
            duration = System.monotonic_time() - start_time

            Logger.debug("Successfully destroyed KV v2 secret versions", metadata)
            Telemetry.operation_success(duration, metadata)

            :ok

          {:ok, %{status: 404}} ->
            duration = System.monotonic_time() - start_time
            error = Error.new(:not_found, "Secret not found at path: #{path}")

            Logger.debug("KV v2 secret not found for destroy", Map.put(metadata, :error, error))
            Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

            {:error, error}

          {:ok, %{status: status, body: body}} ->
            duration = System.monotonic_time() - start_time

            error =
              Error.new(:server_error, "Destroy failed with status: #{status}",
                details: %{body: body}
              )

            Logger.error(
              "KV v2 destroy failed",
              Map.merge(metadata, %{status: status, error: error})
            )

            Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

            {:error, error}

          {:error, reason} ->
            duration = System.monotonic_time() - start_time
            error = Error.new(:network_error, "HTTP request failed", details: %{reason: reason})

            Logger.error(
              "KV v2 destroy transport error",
              Map.merge(metadata, %{reason: reason, error: error})
            )

            Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

            {:error, error}
        end
      end
    end
  end

  @impl Vaultx.Secrets.KV.Behaviour
  def list_versions(path, opts \\ []) do
    with :ok <- validate_path(path),
         :ok <- validate_opts(opts) do
      mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

      metadata = %{
        engine: :kv,
        version: 2,
        operation: :list_versions,
        path: path,
        mount_path: mount_path
      }

      Logger.debug("Listing KV v2 secret versions", metadata)
      Telemetry.operation_start(metadata)

      start_time = System.monotonic_time()

      case HTTP.get("#{mount_path}/metadata/#{path}", opts) do
        {:ok, %{status: 200, body: %{"data" => response_data}}} ->
          duration = System.monotonic_time() - start_time

          versions = response_data["versions"] || %{}

          version_list =
            versions
            |> Map.keys()
            |> Enum.map(&String.to_integer/1)
            |> Enum.sort()
            |> Enum.map(&to_string/1)

          list_result = %{
            keys: version_list,
            metadata: response_data
          }

          Logger.debug(
            "Successfully listed KV v2 secret versions",
            Map.merge(metadata, %{version_count: length(version_list)})
          )

          Telemetry.operation_success(duration, metadata)

          {:ok, list_result}

        {:ok, %{status: 404}} ->
          duration = System.monotonic_time() - start_time
          error = Error.new(:not_found, "Secret not found at path: #{path}")

          Logger.debug(
            "KV v2 secret not found for version listing",
            Map.put(metadata, :error, error)
          )

          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}

        {:ok, %{status: status, body: body}} ->
          duration = System.monotonic_time() - start_time

          error =
            Error.new(:server_error, "Version list failed with status: #{status}",
              details: %{body: body}
            )

          Logger.error(
            "KV v2 version list failed",
            Map.merge(metadata, %{status: status, error: error})
          )

          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}

        {:error, reason} ->
          duration = System.monotonic_time() - start_time
          error = Error.new(:network_error, "HTTP request failed", details: %{reason: reason})

          Logger.error(
            "KV v2 version list transport error",
            Map.merge(metadata, %{reason: reason, error: error})
          )

          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}
      end
    end
  end

  # Private helper functions

  defp validate_secret_data(data) when is_map(data), do: :ok

  defp validate_secret_data(_),
    do: {:error, Error.new(:invalid_request, "Secret data must be a map")}

  defp validate_metadata(data) when is_map(data), do: :ok
  defp validate_metadata(_), do: {:error, Error.new(:invalid_request, "Metadata must be a map")}

  defp parse_datetime(nil), do: nil

  defp parse_datetime(datetime_string) when is_binary(datetime_string) do
    case DateTime.from_iso8601(datetime_string) do
      {:ok, datetime, _} -> datetime
      {:error, _} -> nil
    end
  end

  defp parse_datetime(_), do: nil

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

  # Cache management functions

  defp clear_cache_for_path(mount_path, path) do
    # Clear cache entries for this path (all versions)
    pattern = "kv2:#{mount_path}:#{path}|*"

    case Process.whereis(Vaultx.Cache.Manager) do
      # Cache not running
      nil -> :ok
      _pid -> Cache.clear(pattern)
    end
  end
end
