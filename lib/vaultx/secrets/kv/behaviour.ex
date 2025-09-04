defmodule Vaultx.Secrets.KV.Behaviour do
  @moduledoc """
  Key-Value specific behaviour definition for Vault KV secrets engines.

  This behaviour provides KV-specific operations
  supporting both KV v1 and KV v2 engines. It provides a comprehensive interface
  for versioned secret management, metadata operations, and advanced KV lifecycle
  management.

  ## KV Engine Versions

  ### KV v1 Features
  - Simple key-value storage and retrieval
  - Basic CRUD operations without versioning
  - Direct path-based secret access
  - Immediate permanent deletion
  - Minimal storage overhead
  - No versioning or metadata support

  ### KV v2 Features
  - Versioned secret storage
  - Automatic versioning of all secret changes
  - Rich metadata management and tracking
  - Check-and-set (CAS) operations for safe concurrent updates
  - Soft delete with recovery capabilities
  - Permanent destruction of specific versions
  - Configurable retention and version policies
  - Complete audit trail of modifications

  ## Extended Operations

  Beyond standard secrets operations, KV engines provide:

  ### Metadata Management (KV v2)
  - `read_metadata/2` - Read secret metadata and version history
  - `write_metadata/3` - Update secret metadata without creating versions
  - `delete_metadata/2` - Permanently delete all metadata and versions

  ### Version Management (KV v2)
  - `undelete/2` - Restore soft-deleted secret versions
  - `destroy/2` - Permanently destroy specific versions
  - `list_versions/2` - List all versions with metadata

  ## API Compliance

  This behaviour ensures full compliance with HashiCorp Vault KV APIs:
  - [KV v1 API](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v1)
  - [KV v2 API](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2)

  ## Usage Examples

      defmodule MyApp.KVEngine do
        @behaviour Vaultx.Secrets.KV.Behaviour

        # Basic operations (work with both v1 and v2)
        @impl true
        def read(path, opts) do
          # Implementation
        end

        # KV v2 specific operations
        @impl true
        def read_metadata(path, opts) do
          # Implementation for metadata reading
        end

        @impl true
        def undelete(path, opts) do
          # Implementation for undeleting versions
        end
      end

  ## Options

  KV-specific options extend the base options:

  - `:version` - Specific version to read (KV v2)
  - `:versions` - List of versions for batch operations (KV v2)
  - `:cas` - Check-and-set parameter for safe updates (KV v2)
  - `:max_versions` - Maximum versions to keep (KV v2 config)
  - `:delete_version_after` - Auto-delete after duration (KV v2 config)

  ## Error Handling

  KV operations return standardized errors:

      {:error, %Vaultx.Base.Error{
        type: :version_not_found,
        message: "Version 5 not found",
        details: %{path: "myapp/config", version: 5}
      }}

  Common KV error types:
  - `:version_not_found` - Requested version doesn't exist
  - `:cas_mismatch` - Check-and-set parameter mismatch
  - `:max_versions_exceeded` - Too many versions stored
  - `:already_deleted` - Version already soft-deleted
  - `:permanently_destroyed` - Version permanently destroyed
  """

  alias Vaultx.Base.Error

  # Modern type definitions using @type instead of nested modules
  @typedoc """
  Structured secret data with metadata for KV engines.

  ## Fields

  - `:data` - The actual secret data as a map
  - `:metadata` - Optional metadata about the secret
  - `:version` - Version number (KV v2 only)
  - `:created_time` - When this version was created
  - `:deletion_time` - When this version was deleted (if soft-deleted)
  - `:destroyed` - Whether this version has been permanently destroyed
  """
  @type secret_data :: %{
          data: map(),
          metadata: map() | nil,
          version: pos_integer() | nil,
          created_time: DateTime.t() | nil,
          deletion_time: DateTime.t() | nil,
          destroyed: boolean()
        }

  @typedoc """
  Result of a KV write operation.

  ## Fields

  - `:version` - Version number of the written secret (KV v2 only)
  - `:created_time` - When this version was created
  - `:deletion_time` - When this version was deleted (if applicable)
  - `:destroyed` - Whether this version has been permanently destroyed
  """
  @type write_result :: %{
          version: pos_integer() | nil,
          created_time: DateTime.t() | nil,
          deletion_time: DateTime.t() | nil,
          destroyed: boolean()
        }

  @typedoc """
  Result of a KV list operation.

  ## Fields

  - `:keys` - List of secret keys found
  - `:metadata` - Optional metadata about the listing operation
  """
  @type list_result :: %{
          keys: [String.t()],
          metadata: map() | nil
        }

  @typedoc """
  KV-specific operation options.
  Extends base operation options with KV-specific parameters.
  """
  @type kv_opts :: [
          # Base options
          mount_path: String.t(),
          timeout: pos_integer(),
          retry_attempts: non_neg_integer(),
          metadata: boolean(),

          # KV-specific options
          version: pos_integer(),
          versions: [pos_integer()],
          cas: non_neg_integer(),
          max_versions: pos_integer(),
          delete_version_after: String.t(),

          # KV v2 configuration options
          cas_required: boolean(),
          delete_version_after: String.t()
        ]

  @typedoc """
  Result of a metadata read operation.
  """
  @type metadata_result :: {:ok, secret_data()} | {:error, Error.t()}

  @typedoc """
  Result of a version list operation.
  """
  @type versions_result :: {:ok, list_result()} | {:error, Error.t()}

  @doc """
  Reads metadata for a secret path.

  This operation is only available for KV v2 engines and returns
  metadata about all versions of a secret without the actual secret data.

  ## Parameters

  - `path` - The secret path to read metadata for
  - `opts` - KV operation options

  ## Returns

  - `{:ok, metadata}` - Successfully read metadata
  - `{:error, error}` - Failed to read metadata

  ## Examples

      # Read metadata for a secret
      {:ok, metadata} = MyKVEngine.read_metadata("myapp/config", [])

      # Read metadata with custom mount path
      {:ok, metadata} = MyKVEngine.read_metadata("myapp/config", mount_path: "kv-v2")
  """
  @callback read_metadata(String.t(), kv_opts()) :: metadata_result()

  @doc """
  Writes metadata for a secret path.

  This operation is only available for KV v2 engines and allows
  updating secret metadata without affecting the secret data itself.

  ## Parameters

  - `path` - The secret path to write metadata for
  - `metadata` - The metadata to write
  - `opts` - KV operation options

  ## Returns

  - `:ok` - Successfully wrote metadata
  - `{:error, error}` - Failed to write metadata

  ## Examples

      # Write metadata
      :ok = MyKVEngine.write_metadata("myapp/config", %{"max_versions" => 5}, [])

      # Write metadata with CAS
      :ok = MyKVEngine.write_metadata("myapp/config", %{"description" => "Updated"}, cas: 2)
  """
  @callback write_metadata(String.t(), map(), kv_opts()) :: :ok | {:error, Error.t()}

  @doc """
  Deletes metadata for a secret path.

  This operation is only available for KV v2 engines and removes
  all metadata and versions of a secret permanently.

  ## Parameters

  - `path` - The secret path to delete metadata for
  - `opts` - KV operation options

  ## Returns

  - `:ok` - Successfully deleted metadata
  - `{:error, error}` - Failed to delete metadata

  ## Examples

      # Delete all metadata and versions
      :ok = MyKVEngine.delete_metadata("myapp/config", [])
  """
  @callback delete_metadata(String.t(), kv_opts()) :: :ok | {:error, Error.t()}

  @doc """
  Undeletes (restores) soft-deleted secret versions.

  This operation is only available for KV v2 engines and can restore
  previously deleted versions that haven't been permanently destroyed.

  ## Parameters

  - `path` - The secret path to undelete versions for
  - `opts` - KV operation options (must include `:versions`)

  ## Returns

  - `:ok` - Successfully undeleted versions
  - `{:error, error}` - Failed to undelete versions

  ## Examples

      # Undelete specific versions
      :ok = MyKVEngine.undelete("myapp/config", versions: [1, 2, 3])

      # Undelete with custom mount path
      :ok = MyKVEngine.undelete("myapp/config", versions: [1], mount_path: "kv-v2")
  """
  @callback undelete(String.t(), kv_opts()) :: :ok | {:error, Error.t()}

  @doc """
  Permanently destroys secret versions.

  This operation is only available for KV v2 engines and permanently
  removes specified versions, making them unrecoverable.

  ## Parameters

  - `path` - The secret path to destroy versions for
  - `opts` - KV operation options (must include `:versions`)

  ## Returns

  - `:ok` - Successfully destroyed versions
  - `{:error, error}` - Failed to destroy versions

  ## Examples

      # Permanently destroy specific versions
      :ok = MyKVEngine.destroy("myapp/config", versions: [1, 2])

      # Destroy with custom mount path
      :ok = MyKVEngine.destroy("myapp/config", versions: [1], mount_path: "kv-v2")
  """
  @callback destroy(String.t(), kv_opts()) :: :ok | {:error, Error.t()}

  @doc """
  Lists all versions of a secret.

  This operation is only available for KV v2 engines and returns
  information about all versions of a secret including their status.

  ## Parameters

  - `path` - The secret path to list versions for
  - `opts` - KV operation options

  ## Returns

  - `{:ok, versions}` - Successfully listed versions
  - `{:error, error}` - Failed to list versions

  ## Examples

      # List all versions
      {:ok, versions} = MyKVEngine.list_versions("myapp/config", [])

      # List versions with metadata
      {:ok, versions} = MyKVEngine.list_versions("myapp/config", metadata: true)
  """
  @callback list_versions(String.t(), kv_opts()) :: versions_result()

  # Optional callbacks - not all KV engines need to implement all operations
  @optional_callbacks [
    read_metadata: 2,
    write_metadata: 3,
    delete_metadata: 2,
    undelete: 2,
    destroy: 2,
    list_versions: 2
  ]
end
