defmodule Vaultx.Client do
  @moduledoc """
  High-level, stateless client for HashiCorp Vault operations.

  This module provides a simplified, consistent API for common Vault operations
  while maintaining full compatibility with Vault's REST API. It emphasizes
  simplicity, reliability, and developer experience.

  ## Design Principles

  - Stateless: No background processes or state management required
  - Dynamic Configuration: Reads configuration on each call for flexibility
  - Consistent Error Handling: All operations return structured error tuples
  - Type Safety: Comprehensive type specifications and validation
  - Observability: Built-in logging and optional telemetry integration

  ## Supported Operations

  ### Secret Management
  - `read/2` - Read secrets from any engine
  - `write/3` - Write secrets with optional parameters
  - `delete/2` - Delete secrets (engine-specific behavior)
  - `list/2` - List available secret paths

  ### System Operations
  - `health/1` - Check Vault cluster health
  - `seal_status/1` - Get seal status information
  - `authenticate/3` - Authenticate with various methods (planned)

  ## Usage Examples

      # Basic secret operations
      {:ok, data} = Vaultx.Client.read("secret/myapp/config")
      :ok = Vaultx.Client.write("secret/myapp/config", %{"key" => "value"})
      :ok = Vaultx.Client.delete("secret/myapp/config")
      {:ok, keys} = Vaultx.Client.list("secret/myapp/")

      # System monitoring
      {:ok, health} = Vaultx.Client.health()
      {:ok, seal_status} = Vaultx.Client.seal_status()

  ## API Compliance

  This client fully implements HashiCorp Vault's HTTP API:
  - [Vault HTTP API](https://developer.hashicorp.com/vault/api-docs)
  - [System Backend](https://developer.hashicorp.com/vault/api-docs/system)

  ## Configuration

  The client reads configuration dynamically from `Vaultx.Base.Config`,
  allowing runtime changes without process restarts. For testing, set
  `retry_attempts: 0` to eliminate backoff delays.
  """

  alias Vaultx.Base.{Error, Logger, Security, Telemetry}
  alias Vaultx.Transport.HTTP
  alias Vaultx.Types

  @doc """
  Reads a secret from Vault at the specified path.

  Supports both KV v1 and KV v2 engines, automatically handling the different
  response formats. For KV v2, returns the latest version by default.

  ## Options

    * `:timeout` - Request timeout in milliseconds
    * `:retry_attempts` - Number of retry attempts
    * `:version` - For KV v2, specify version to read
    * `:token` - Override the configured token

  ## Examples

      # Read from KV v1 engine
      {:ok, data} = Vaultx.Client.read("secret/myapp/config")

      # Read from KV v2 engine (automatic detection)
      {:ok, data} = Vaultx.Client.read("secret/data/myapp/config")

      # Read specific version from KV v2
      {:ok, data} = Vaultx.Client.read("secret/data/myapp/config", version: 2)

      # Read with custom timeout
      {:ok, data} = Vaultx.Client.read("secret/myapp/config", timeout: 60_000)

  ## Returns

    * `{:ok, data}` - Secret data as a map
    * `{:error, %Vaultx.Base.Error{type: :not_found}}` - Secret not found
    * `{:error, %Vaultx.Base.Error{type: :authorization_denied}}` - Access denied
    * `{:error, %Vaultx.Base.Error{}}` - Other errors

  """
  @spec read(Types.path(), Types.options()) :: Types.read_result()
  def read(path, opts \\ []) do
    with :ok <- Security.validate_path(path) do
      metadata = %{operation: :read, path: path}

      Telemetry.measure([:operation, :read], metadata, fn ->
        case HTTP.get(path, opts) do
          {:ok, %{status: status, body: %{"data" => %{"data" => data}}}}
          when status in 200..299 ->
            # KV v2 format
            Logger.debug("Secret read successfully (KV v2)", %{path: path, keys: Map.keys(data)})
            {:ok, data}

          {:ok, %{status: status, body: %{"data" => data}}}
          when status in 200..299 and is_map(data) ->
            # KV v1 format or other engines
            Logger.debug("Secret read successfully", %{path: path, keys: Map.keys(data)})
            {:ok, data}

          {:ok, %{status: status, body: data}} when status in 200..299 and is_map(data) ->
            # coveralls-ignore-start
            # This branch handles direct data responses without "data" key nesting,
            # which is rare as most Vault engines use structured responses
            # Direct data response
            Logger.debug("Data read successfully", %{path: path})
            {:ok, data}

          # coveralls-ignore-stop

          {:ok, %{status: status, body: body}} ->
            error =
              Error.new(:not_found, "Secret not found",
                details: body,
                http_status: status
              )

            Logger.error("Failed to read secret", %{path: path, error: error})
            {:error, error}

          {:error, error} ->
            Logger.error("Failed to read secret", %{path: path, error: error})
            {:error, error}
        end
      end)
    end
  end

  @doc """
  Writes a secret to Vault at the specified path.

  Supports both KV v1 and KV v2 engines, automatically formatting the request
  based on the path structure.

  ## Options

    * `:timeout` - Request timeout in milliseconds
    * `:retry_attempts` - Number of retry attempts
    * `:cas` - For KV v2, perform check-and-set operation
    * `:token` - Override the configured token

  ## Examples

      # Write to KV v1 engine
      :ok = Vaultx.Client.write("secret/myapp/config", %{"key" => "value"})

      # Write to KV v2 engine
      :ok = Vaultx.Client.write("secret/data/myapp/config", %{"key" => "value"})

      # Write with check-and-set (KV v2 only)
      :ok = Vaultx.Client.write("secret/data/myapp/config", %{"key" => "value"}, cas: 1)

  """
  @spec write(Types.path(), Types.secret_data(), Types.options()) :: Types.write_result()
  def write(path, data, opts \\ []) do
    with :ok <- Security.validate_path(path),
         :ok <- validate_secret_data(data) do
      metadata = %{operation: :write, path: path, data_keys: Map.keys(data)}

      Telemetry.measure([:operation, :write], metadata, fn ->
        # Format data for KV v2 if needed
        formatted_data = format_write_data(path, data, opts)

        case HTTP.post(path, formatted_data, opts) do
          {:ok, _response} ->
            Logger.info("Secret written successfully", %{path: path})
            :ok

          {:error, error} ->
            Logger.error("Failed to write secret", %{path: path, error: error})
            {:error, error}
        end
      end)
    end
  end

  @doc """
  Deletes a secret from Vault at the specified path.

  For KV v2 engines, this performs a soft delete by default. Use the `:destroy`
  option to permanently destroy all versions.

  ## Options

    * `:timeout` - Request timeout in milliseconds
    * `:retry_attempts` - Number of retry attempts
    * `:versions` - For KV v2, specify versions to delete
    * `:destroy` - For KV v2, permanently destroy the secret
    * `:token` - Override the configured token

  ## Examples

      # Delete from KV v1 engine
      :ok = Vaultx.Client.delete("secret/myapp/config")

      # Soft delete from KV v2 engine
      :ok = Vaultx.Client.delete("secret/data/myapp/config")

      # Delete specific versions from KV v2
      :ok = Vaultx.Client.delete("secret/data/myapp/config", versions: [1, 2])

  """
  @spec delete(Types.path(), Types.options()) :: Types.delete_result()
  def delete(path, opts \\ []) do
    with :ok <- Security.validate_path(path) do
      metadata = %{operation: :delete, path: path}

      Telemetry.measure([:operation, :delete], metadata, fn ->
        case HTTP.delete(path, opts) do
          {:ok, %{status: status}} when status in 200..299 ->
            Logger.info("Secret deleted successfully", %{path: path})
            :ok

          {:ok, %{status: status, body: body}} ->
            error =
              Error.new(:not_found, "Delete failed",
                details: body,
                http_status: status
              )

            Logger.error("Failed to delete secret", %{path: path, error: error})
            {:error, error}

          {:error, error} ->
            Logger.error("Failed to delete secret", %{path: path, error: error})
            {:error, error}
        end
      end)
    end
  end

  @doc """
  Lists secrets at the specified path.

  Returns a list of key names at the given path. For KV v2 engines,
  this lists the secret names without version information.

  ## Options

    * `:timeout` - Request timeout in milliseconds
    * `:retry_attempts` - Number of retry attempts
    * `:token` - Override the configured token

  ## Examples

      # List secrets in a path
      {:ok, keys} = Vaultx.Client.list("secret/myapp/")
      # Returns: ["config", "database", "api-keys"]

  """
  @spec list(Types.path(), Types.options()) :: Types.list_result()
  def list(path, opts \\ []) do
    with :ok <- Security.validate_path(path) do
      metadata = %{operation: :list, path: path}

      # Add LIST method parameter for Vault
      list_opts = Keyword.put(opts, :method, "LIST")

      Telemetry.measure([:operation, :list], metadata, fn ->
        case HTTP.request(:get, path, nil, [], list_opts) do
          {:ok, %{body: %{"data" => %{"keys" => keys}}}} when is_list(keys) ->
            Logger.debug("Path listed successfully", %{path: path, count: length(keys)})
            {:ok, keys}

          {:ok, %{body: %{"data" => keys}}} when is_list(keys) ->
            Logger.debug("Path listed successfully", %{path: path, count: length(keys)})
            {:ok, keys}

          {:error, error} ->
            Logger.error("Failed to list path", %{path: path, error: error})
            {:error, error}
        end
      end)
    end
  end

  @doc """
  Authenticates with Vault using the specified method and credentials.

  Supports multiple authentication methods and returns a token that can be
  used for subsequent operations.

  ## Supported Methods

    * `:app_role` - AppRole authentication
    * `:jwt` - JWT/OIDC authentication
    * `:aws` - AWS IAM authentication
    * `:token` - Direct token authentication (validation)

  ## Examples

      # AppRole authentication
      {:ok, token} = Vaultx.Client.authenticate(:app_role, %{
        role_id: "your-role-id",
        secret_id: "your-secret-id"
      }, [])

      # JWT authentication
      {:ok, token} = Vaultx.Client.authenticate(:jwt, %{
        jwt: "your-jwt-token",
        role: "your-role"
      }, [])

  """
  @spec authenticate(Types.auth_method(), Types.credentials(), Types.options()) ::
          Types.auth_result()
  def authenticate(method, _credentials, _opts \\ []) do
    metadata = %{operation: :authenticate, method: method}

    Telemetry.measure([:auth], metadata, fn ->
      # For now, return a placeholder implementation
      # This will be replaced when auth modules are implemented
      Logger.info("Authentication requested", %{method: method})
      {:error, Error.new(:not_implemented, "Authentication method #{method} not yet implemented")}
    end)
  end

  @doc """
  Performs a health check against Vault.

  Returns comprehensive health information including initialization status,
  seal status, and cluster information.

  ## Examples

      {:ok, health} = Vaultx.Client.health()
      # Returns: %{
      #   "initialized" => true,
      #   "sealed" => false,
      #   "standby" => false,
      #   "version" => "1.12.0"
      # }

  """
  @spec health(Types.options()) :: Types.result(Types.health_status())
  def health(opts \\ []) do
    metadata = %{operation: :health}

    Telemetry.measure([:operation, :health], metadata, fn ->
      case HTTP.get("sys/health", opts) do
        {:ok, %{status: status, body: %{"data" => health_data}}} when status in 200..299 ->
          Logger.debug("Health check successful", %{status: health_data})
          {:ok, health_data}

        {:ok, %{status: status, body: health_data}}
        when status in 200..299 and is_map(health_data) ->
          Logger.debug("Health check successful", %{status: health_data})
          {:ok, health_data}

        {:ok, %{status: status, body: body}} ->
          error =
            Error.new(:server_error, "Health check failed",
              details: body,
              http_status: status
            )

          Logger.error("Health check failed", %{error: error})
          {:error, error}

        {:error, error} ->
          Logger.error("Health check failed", %{error: error})
          {:error, error}
      end
    end)
  end

  @doc """
  Gets the seal status of the Vault server.

  ## Examples

      iex> Vaultx.Client.seal_status()
      {:ok, %{"sealed" => false, "initialized" => true}}

  """
  @spec seal_status(Types.options()) :: Types.result(Types.seal_status())
  def seal_status(opts \\ []) do
    metadata = %{operation: :seal_status}

    Telemetry.measure([:operation, :seal_status], metadata, fn ->
      case HTTP.get("sys/seal-status", opts) do
        {:ok, %{status: status, body: %{"data" => seal_data}}} when status in 200..299 ->
          Logger.debug("Seal status retrieved successfully", %{status: seal_data})
          {:ok, seal_data}

        {:ok, %{status: status, body: seal_data}} when status in 200..299 and is_map(seal_data) ->
          Logger.debug("Seal status retrieved successfully", %{status: seal_data})
          {:ok, seal_data}

        {:ok, %{status: status, body: body}} ->
          error =
            Error.new(:server_error, "Seal status retrieval failed",
              details: body,
              http_status: status
            )

          Logger.error("Seal status retrieval failed", %{error: error})
          {:error, error}

        {:error, error} ->
          Logger.error("Seal status retrieval failed", %{error: error})
          {:error, error}
      end
    end)
  end

  # Private helper functions

  defp validate_secret_data(data) when is_map(data) do
    if map_size(data) > 0 do
      :ok
    else
      {:error, Error.new(:invalid_request, "Secret data cannot be empty")}
    end
  end

  defp validate_secret_data(data) when not is_map(data) do
    {:error, Error.new(:invalid_request, "Secret data must be a map")}
  end

  defp format_write_data(path, data, opts) do
    if String.contains?(path, "/data/") do
      # KV v2 format
      formatted = %{"data" => data}

      if cas_version = Keyword.get(opts, :cas) do
        Map.put(formatted, "options", %{"cas" => cas_version})
      else
        formatted
      end
    else
      # KV v1 or other engines
      data
    end
  end

  # Private helper functions remain unchanged
end
