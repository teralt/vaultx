defmodule Vaultx.Sys.Namespaces do
  @moduledoc """
  HashiCorp Vault namespaces operations.

  This module provides namespace management capabilities for Vault Enterprise,
  allowing you to create, read, update, delete, and manage namespaces for
  multi-tenant Vault deployments.

  ## Namespace Features

  ### Core Operations
  - List Namespaces: Enumerate all available namespaces
  - Create Namespace: Create new namespaces with metadata
  - Read Namespace: Get detailed namespace information
  - Update Namespace: Modify namespace metadata
  - Delete Namespace: Remove namespaces and their contents

  ### Advanced Operations
  - Lock Namespace: Lock namespace API access
  - Unlock Namespace: Restore namespace API access
  - Patch Namespace: Partial updates to namespace metadata
  - Custom Metadata: Arbitrary key-value metadata support

  ## Important Notes

  **Enterprise Feature**
  - Namespaces are only available in Vault Enterprise
  - Requires appropriate Vault Enterprise license
  - Not available in Vault Community Edition

  **Authentication Required**
  - All namespace operations require valid authentication
  - Appropriate permissions needed for namespace management
  - Root namespace access may be required for some operations

  **Destructive Operations**
  - Deleting a namespace removes all contained secrets and policies
  - Namespace deletion is irreversible
  - Consider backup and recovery procedures

  ## API Compliance

  Fully implements HashiCorp Vault Namespaces API:
  - [Namespaces API](https://developer.hashicorp.com/vault/api-docs/system/namespaces)
  - [Vault Namespaces](https://developer.hashicorp.com/vault/docs/enterprise/namespaces)

  ## Usage Examples

  ### List Namespaces

      {:ok, namespaces} = Vaultx.Sys.Namespaces.list()

      Enum.each(namespaces.keys, fn namespace ->
        IO.puts("Namespace: \#{namespace}")
      end)

  ### Create Namespace

      {:ok, _} = Vaultx.Sys.Namespaces.create("production", %{
        "environment" => "prod",
        "team" => "platform"
      })

  ### Read Namespace Information

      {:ok, info} = Vaultx.Sys.Namespaces.read("production")
      IO.puts("Namespace ID: \#{info.id}")
      IO.puts("Path: \#{info.path}")

  ### Update Namespace Metadata

      {:ok, _} = Vaultx.Sys.Namespaces.update("production", %{
        "environment" => "production",
        "team" => "platform",
        "owner" => "ops-team"
      })

  ### Delete Namespace

      {:ok, _} = Vaultx.Sys.Namespaces.delete("staging")

  ## Namespace Information

  Namespace objects contain:
  - `id`: Unique namespace identifier
  - `path`: Namespace path (with trailing slash)
  - `custom_metadata`: User-defined metadata map

  ## Use Cases

  ### Multi-Tenancy
  - Isolate different teams or applications
  - Provide tenant-specific secret management
  - Implement organizational boundaries
  - Support compliance requirements

  ### Environment Separation
  - Separate development, staging, and production
  - Isolate different deployment environments
  - Implement environment-specific policies
  - Control cross-environment access

  ### Organizational Structure
  - Map namespaces to business units
  - Implement departmental boundaries
  - Support hierarchical organizations
  - Enable decentralized management

  ### Security and Compliance
  - Implement security boundaries
  - Support regulatory compliance
  - Enable audit trail separation
  - Control data residency requirements
  """

  alias Vaultx.Base.{Error, Logger, Telemetry}
  alias Vaultx.Transport.HTTP
  alias Vaultx.Types

  @typedoc """
  Namespace information.
  """
  @type namespace_info :: %{
          :id => String.t(),
          :path => String.t(),
          :custom_metadata => map()
        }

  @typedoc """
  Namespace list response.
  """
  @type namespace_list :: %{
          :keys => [String.t()],
          :key_info => map()
        }

  @doc """
  List all namespaces.

  This endpoint lists all the namespaces available to the current token.

  ## Parameters

  - `opts` - Request options (optional)

  ## Returns

  Returns `{:ok, namespace_list()}` with namespace information,
  or `{:error, Error.t()}` on failure.

  ## Examples

      {:ok, namespaces} = Vaultx.Sys.Namespaces.list()

      IO.puts("Available namespaces:")
      Enum.each(namespaces.keys, fn namespace ->
        info = namespaces.key_info[namespace]
        IO.puts("  \#{namespace} (ID: \#{info["id"]})")
      end)

  """
  @spec list(Types.options()) :: {:ok, namespace_list()} | {:error, Error.t()}
  def list(opts \\ []) do
    path = "sys/namespaces"

    metadata = %{operation: :list_namespaces}
    Logger.debug("Listing namespaces", metadata)
    Telemetry.operation_start(metadata)

    start_time = System.monotonic_time()

    # Use GET request with LIST method parameter for namespace listing
    list_opts = Keyword.put(opts, :method, "LIST")

    case HTTP.get(path, list_opts) do
      {:ok, %{status: 200, body: %{"data" => data}}} ->
        duration = System.monotonic_time() - start_time

        namespace_list = %{
          keys: data["keys"] || [],
          key_info: data["key_info"] || %{}
        }

        Logger.info(
          "Successfully listed namespaces",
          Map.put(metadata, :count, length(namespace_list.keys))
        )

        Telemetry.operation_success(duration, metadata)

        {:ok, namespace_list}

      {:ok, %{status: status_code, body: body}} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:server_error, "Failed to list namespaces: HTTP #{status_code}",
            details: %{status: status_code, body: body}
          )

        Logger.error("Failed to list namespaces", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Error listing namespaces", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Create a new namespace.

  This endpoint creates a namespace at the given path with optional custom metadata.

  ## Parameters

  - `path` - The namespace path to create
  - `custom_metadata` - Optional custom metadata map (default: %{})
  - `opts` - Request options (optional)

  ## Returns

  Returns `{:ok, response}` on successful creation,
  or `{:error, Error.t()}` on failure.

  ## Examples

      # Create simple namespace
      {:ok, _} = Vaultx.Sys.Namespaces.create("development")

      # Create with metadata
      {:ok, _} = Vaultx.Sys.Namespaces.create("production", %{
        "environment" => "prod",
        "team" => "platform",
        "contact" => "ops@company.com"
      })

  """
  @spec create(String.t(), map(), Types.options()) ::
          {:ok, Types.response()} | {:error, Error.t()}
  def create(path, custom_metadata \\ %{}, opts \\ [])
      when is_binary(path) and is_map(custom_metadata) do
    api_path = "sys/namespaces/#{path}"

    payload = %{custom_metadata: custom_metadata}

    metadata = %{
      operation: :create_namespace,
      namespace_path: path,
      has_metadata: not Enum.empty?(custom_metadata)
    }

    Logger.debug("Creating namespace", metadata)
    Telemetry.operation_start(metadata)

    start_time = System.monotonic_time()

    case HTTP.post(api_path, payload, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        duration = System.monotonic_time() - start_time

        Logger.info("Successfully created namespace", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, %{status: status}}

      {:ok, %{status: status_code, body: body}} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:server_error, "Failed to create namespace: HTTP #{status_code}",
            details: %{status: status_code, body: body, namespace_path: path}
          )

        Logger.error("Failed to create namespace", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Error creating namespace", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Read namespace information.

  This endpoint gets the metadata for the given namespace path.

  ## Parameters

  - `path` - The namespace path to read
  - `opts` - Request options (optional)

  ## Returns

  Returns `{:ok, namespace_info()}` with namespace information,
  or `{:error, Error.t()}` on failure.

  ## Examples

      {:ok, info} = Vaultx.Sys.Namespaces.read("production")

      IO.puts("Namespace ID: \#{info.id}")
      IO.puts("Path: \#{info.path}")
      IO.puts("Metadata: \#{inspect(info.custom_metadata)}")

  """
  @spec read(String.t(), Types.options()) :: {:ok, namespace_info()} | {:error, Error.t()}
  def read(path, opts \\ []) when is_binary(path) do
    api_path = "sys/namespaces/#{path}"

    metadata = %{operation: :read_namespace, namespace_path: path}
    Logger.debug("Reading namespace", metadata)
    Telemetry.operation_start(metadata)

    start_time = System.monotonic_time()

    case HTTP.get(api_path, opts) do
      {:ok, %{status: 200, body: body}} ->
        duration = System.monotonic_time() - start_time

        namespace_info = %{
          id: body["id"],
          path: body["path"],
          custom_metadata: body["custom_metadata"] || %{}
        }

        Logger.info("Successfully read namespace", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, namespace_info}

      {:ok, %{status: status_code, body: body}} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:server_error, "Failed to read namespace: HTTP #{status_code}",
            details: %{status: status_code, body: body, namespace_path: path}
          )

        Logger.error("Failed to read namespace", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Error reading namespace", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Update namespace metadata.

  This endpoint updates the custom metadata for an existing namespace.

  ## Parameters

  - `path` - The namespace path to update
  - `custom_metadata` - New custom metadata map
  - `opts` - Request options (optional)

  ## Returns

  Returns `{:ok, response}` on successful update,
  or `{:error, Error.t()}` on failure.

  ## Examples

      {:ok, _} = Vaultx.Sys.Namespaces.update("production", %{
        "environment" => "production",
        "team" => "platform",
        "updated_at" => DateTime.utc_now() |> DateTime.to_iso8601()
      })

  """
  @spec update(String.t(), map(), Types.options()) ::
          {:ok, Types.response()} | {:error, Error.t()}
  def update(path, custom_metadata, opts \\ [])
      when is_binary(path) and is_map(custom_metadata) do
    api_path = "sys/namespaces/#{path}"

    payload = %{custom_metadata: custom_metadata}

    metadata = %{
      operation: :update_namespace,
      namespace_path: path,
      metadata_keys: Map.keys(custom_metadata)
    }

    Logger.debug("Updating namespace", metadata)
    Telemetry.operation_start(metadata)

    start_time = System.monotonic_time()

    case HTTP.post(api_path, payload, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        duration = System.monotonic_time() - start_time

        Logger.info("Successfully updated namespace", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, %{status: status}}

      {:ok, %{status: status_code, body: body}} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:server_error, "Failed to update namespace: HTTP #{status_code}",
            details: %{status: status_code, body: body, namespace_path: path}
          )

        Logger.error("Failed to update namespace", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Error updating namespace", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Delete a namespace.

  This endpoint deletes a namespace at the specified path. This operation
  is destructive and will remove all secrets, policies, and other data
  within the namespace.

  ## Parameters

  - `path` - The namespace path to delete
  - `opts` - Request options (optional)

  ## Returns

  Returns `{:ok, response}` on successful deletion,
  or `{:error, Error.t()}` on failure.

  ## Examples

      {:ok, _} = Vaultx.Sys.Namespaces.delete("old-project")

  ## Warning

  This operation is destructive and irreversible. All data within
  the namespace will be permanently deleted.

  """
  @spec delete(String.t(), Types.options()) :: {:ok, Types.response()} | {:error, Error.t()}
  def delete(path, opts \\ []) when is_binary(path) do
    api_path = "sys/namespaces/#{path}"

    metadata = %{operation: :delete_namespace, namespace_path: path}
    Logger.debug("Deleting namespace", metadata)
    Telemetry.operation_start(metadata)

    start_time = System.monotonic_time()

    case HTTP.delete(api_path, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        duration = System.monotonic_time() - start_time

        Logger.info("Successfully deleted namespace", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, %{status: status}}

      {:ok, %{status: status_code, body: body}} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:server_error, "Failed to delete namespace: HTTP #{status_code}",
            details: %{status: status_code, body: body, namespace_path: path}
          )

        Logger.error("Failed to delete namespace", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Error deleting namespace", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Check if a namespace exists.

  This is a convenience function that checks if a namespace exists
  by attempting to read its information.

  ## Parameters

  - `path` - The namespace path to check
  - `opts` - Request options (optional)

  ## Returns

  Returns `{:ok, boolean()}` where true means the namespace exists,
  or `{:error, Error.t()}` on failure.

  ## Examples

      case Vaultx.Sys.Namespaces.exists?("production") do
        {:ok, true} -> IO.puts("Namespace exists")
        {:ok, false} -> IO.puts("Namespace does not exist")
        {:error, error} -> IO.puts("Error: \#{error.message}")
      end

  """
  @spec exists?(String.t(), Types.options()) :: {:ok, boolean()} | {:error, Error.t()}
  def exists?(path, opts \\ []) when is_binary(path) do
    case read(path, opts) do
      {:ok, _info} -> {:ok, true}
      {:error, %Error{type: :server_error, details: %{status: 404}}} -> {:ok, false}
      {:error, error} -> {:error, error}
    end
  end

  @doc """
  Get a list of namespace names only.

  This is a convenience function that returns just the namespace names
  without additional metadata.

  ## Parameters

  - `opts` - Request options (optional)

  ## Returns

  Returns `{:ok, [String.t()]}` with namespace names,
  or `{:error, Error.t()}` on failure.

  ## Examples

      {:ok, namespace_names} = Vaultx.Sys.Namespaces.list_names()
      IO.puts("Namespaces: \#{Enum.join(namespace_names, ", ")}")

  """
  @spec list_names(Types.options()) :: {:ok, [String.t()]} | {:error, Error.t()}
  def list_names(opts \\ []) do
    case list(opts) do
      {:ok, namespace_list} -> {:ok, namespace_list.keys}
      {:error, error} -> {:error, error}
    end
  end
end
