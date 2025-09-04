defmodule Vaultx.Secrets.KV do
  @moduledoc """
  Unified Key-Value secrets engine interface for HashiCorp Vault.

  This module provides a unified interface for both KV v1 and KV v2 engines,
  automatically detecting the engine version and delegating operations to the
  appropriate implementation. It offers a seamless experience for working with
  KV secrets regardless of the underlying engine version.

  ## Features

  - Automatic Version Detection: Detects KV v1 vs v2 automatically
  - Unified API: Same interface works with both versions
  - Version-Specific Features: Advanced features available when supported
  - Graceful Degradation: Unsupported operations return clear errors
  - Performance Optimized: Caches version detection results
  - Convenience Functions: Additional utility functions for common operations

  ## Supported Operations

  ### Core Operations (Both v1 and v2)
  - `read/2` - Read secrets from any path
  - `write/3` - Write secrets to any path
  - `delete/2` - Delete secrets (soft delete in v2)
  - `list/2` - List secret keys at a path

  ### KV v2 Specific Operations
  - `read_metadata/2` - Read secret metadata and version history
  - `write_metadata/3` - Update secret metadata without creating new version
  - `delete_metadata/2` - Permanently delete all versions and metadata
  - `undelete/2` - Restore soft-deleted versions
  - `destroy/2` - Permanently destroy specific versions
  - `list_versions/2` - List all versions of a secret

  ### Convenience Functions
  - `read_version/3` - Read specific version of a secret
  - `write_cas/4` - Write with Check-And-Set (CAS) support
  - `delete_versions/3` - Delete specific versions
  - `exists?/2` - Check if a secret exists
  - `keys/2` - Get field names from a secret
  - `get_field/3` - Get specific field value
  - `update_field/4` - Update single field preserving others

  ## Usage Examples

      # Basic operations (work with both v1 and v2)
      {:ok, secret} = Vaultx.Secrets.KV.read("myapp/config", mount_path: "secret")
      {:ok, result} = Vaultx.Secrets.KV.write("myapp/config", %{"key" => "value"}, mount_path: "secret")
      :ok = Vaultx.Secrets.KV.delete("myapp/config", mount_path: "secret")
      {:ok, keys} = Vaultx.Secrets.KV.list("myapp/", mount_path: "secret")

      # KV v2 specific operations (gracefully fail on v1)
      {:ok, secret} = Vaultx.Secrets.KV.read_version("myapp/config", 2, mount_path: "secret")
      {:ok, result} = Vaultx.Secrets.KV.write_cas("myapp/config", %{"key" => "value"}, 1, mount_path: "secret")
      :ok = Vaultx.Secrets.KV.undelete("myapp/config", versions: [1, 2], mount_path: "secret")

      # Metadata operations (KV v2 only)
      {:ok, metadata} = Vaultx.Secrets.KV.read_metadata("myapp/config", mount_path: "secret")
      :ok = Vaultx.Secrets.KV.write_metadata("myapp/config", %{"max_versions" => 5}, mount_path: "secret")

      # Convenience functions
      true = Vaultx.Secrets.KV.exists?("myapp/config", mount_path: "secret")
      {:ok, ["username", "password"]} = Vaultx.Secrets.KV.keys("myapp/config", mount_path: "secret")
      {:ok, "admin"} = Vaultx.Secrets.KV.get_field("myapp/config", "username", mount_path: "secret")

  ## Version Detection

  The module automatically detects the KV engine version by:

  1. Checking engine mount information via `/sys/mounts`
  2. Caching the result for subsequent operations
  3. Falling back to API behavior analysis if needed

  ## API Compliance

  This implementation fully complies with HashiCorp Vault's official KV API:
  - KV v1: https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v1
  - KV v2: https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2


  ## Configuration

      # KV v1 engine
      vault secrets enable -version=1 -path=kv-v1 kv

      # KV v2 engine (default for new installations)
      vault secrets enable -version=2 -path=secret kv

  ## Error Handling

  Operations return standardized errors with clear messages:

      {:error, %Vaultx.Base.Error{
        type: :unsupported_operation,
        message: "KV v1 does not support versioning",
        details: %{operation: :read, version: 2}
      }}

  ## Performance Considerations

  - Version detection results are cached per mount path
  - Cache can be cleared with `clear_version_cache/1`
  - First operation per mount may be slightly slower due to detection
  """

  @behaviour Vaultx.Secrets.KV.Behaviour

  alias Vaultx.Base.{Error, Logger}
  alias Vaultx.Secrets.KV.{V1, V2}
  alias Vaultx.Transport.HTTP

  @default_mount_path "secret"

  # Version detection cache
  @version_cache_table :kv_version_cache

  @doc """
  Initializes the KV module and sets up version detection cache.
  This is called automatically when the module is loaded.
  """
  def __init__ do
    :ets.new(@version_cache_table, [:set, :public, :named_table])
    :ok
  rescue
    # Table already exists
    ArgumentError -> :ok
  end

  def read(path, opts \\ []), do: do_read(path, opts)

  defp do_read(path, opts),
    do: with_version_detection(path, opts, fn _v, mod -> mod.read(path, opts) end)

  def write(path, data, opts \\ []), do: do_write(path, data, opts)

  defp do_write(path, data, opts),
    do: with_version_detection(path, opts, fn _v, mod -> mod.write(path, data, opts) end)

  def delete(path, opts \\ []), do: do_delete(path, opts)

  defp do_delete(path, opts),
    do: with_version_detection(path, opts, fn _v, mod -> mod.delete(path, opts) end)

  def list(path, opts \\ []), do: do_list(path, opts)

  defp do_list(path, opts),
    do: with_version_detection(path, opts, fn _v, mod -> mod.list(path, opts) end)

  def configure(config, opts \\ []), do: do_configure(config, opts)

  defp do_configure(config, opts),
    do: with_version_detection("", opts, fn _v, mod -> mod.configure(config, opts) end)

  # KV-specific behaviour implementations

  @impl Vaultx.Secrets.KV.Behaviour
  def read_metadata(path, opts \\ []), do: do_read_metadata(path, opts)

  defp do_read_metadata(path, opts),
    do: with_version_detection(path, opts, fn _v, mod -> mod.read_metadata(path, opts) end)

  @impl Vaultx.Secrets.KV.Behaviour
  def write_metadata(path, metadata_data, opts \\ []),
    do: do_write_metadata(path, metadata_data, opts)

  defp do_write_metadata(path, metadata_data, opts),
    do:
      with_version_detection(path, opts, fn _v, mod ->
        mod.write_metadata(path, metadata_data, opts)
      end)

  @impl Vaultx.Secrets.KV.Behaviour
  def delete_metadata(path, opts \\ []), do: do_delete_metadata(path, opts)

  defp do_delete_metadata(path, opts),
    do: with_version_detection(path, opts, fn _v, mod -> mod.delete_metadata(path, opts) end)

  @impl Vaultx.Secrets.KV.Behaviour
  def undelete(path, opts \\ []), do: do_undelete(path, opts)

  defp do_undelete(path, opts),
    do: with_version_detection(path, opts, fn _v, mod -> mod.undelete(path, opts) end)

  @impl Vaultx.Secrets.KV.Behaviour
  def destroy(path, opts \\ []), do: do_destroy(path, opts)

  defp do_destroy(path, opts),
    do: with_version_detection(path, opts, fn _v, mod -> mod.destroy(path, opts) end)

  @impl Vaultx.Secrets.KV.Behaviour
  def list_versions(path, opts \\ []), do: do_list_versions(path, opts)

  defp do_list_versions(path, opts),
    do: with_version_detection(path, opts, fn _v, mod -> mod.list_versions(path, opts) end)

  @doc """
  Detects the KV engine version for a given mount path.

  ## Parameters

  - `mount_path` - The mount path to detect version for
  - `opts` - Operation options

  ## Returns

  - `{:ok, 1}` - KV v1 engine detected
  - `{:ok, 2}` - KV v2 engine detected
  - `{:error, error}` - Detection failed

  ## Examples

      {:ok, 1} = Vaultx.Secrets.KV.detect_kv_version("kv-v1")
      {:ok, 2} = Vaultx.Secrets.KV.detect_kv_version("secret")
  """
  @spec detect_kv_version(String.t(), keyword()) :: {:ok, 1 | 2} | {:error, Error.t()}
  def detect_kv_version(mount_path, opts \\ []) do
    # Initialize cache table if needed
    __init__()

    # Check cache first
    case :ets.lookup(@version_cache_table, mount_path) do
      [{^mount_path, version}] ->
        Logger.debug("Using cached KV version", %{mount_path: mount_path, version: version})
        {:ok, version}

      [] ->
        # Detect version and cache result
        case do_detect_kv_version(mount_path, opts) do
          {:ok, version} = result ->
            :ets.insert(@version_cache_table, {mount_path, version})

            Logger.debug("Detected and cached KV version", %{
              mount_path: mount_path,
              version: version
            })

            result

          error ->
            error
        end
    end
  end

  @doc """
  Clears the version detection cache for a specific mount path or all mount paths.

  ## Parameters

  - `mount_path` - Mount path to clear cache for, or `:all` to clear all

  ## Examples

      :ok = Vaultx.Secrets.KV.clear_version_cache("secret")
      :ok = Vaultx.Secrets.KV.clear_version_cache(:all)
  """
  @spec clear_version_cache(String.t() | :all) :: :ok
  def clear_version_cache(:all) do
    __init__()
    :ets.delete_all_objects(@version_cache_table)
    Logger.debug("Cleared all KV version cache entries")
    :ok
  end

  def clear_version_cache(mount_path) when is_binary(mount_path) do
    __init__()
    :ets.delete(@version_cache_table, mount_path)
    Logger.debug("Cleared KV version cache", %{mount_path: mount_path})
    :ok
  end

  # Convenience functions for better tab completion experience

  @doc """
  Read a secret from KV store with version support.

  This is an alias for `read/2` with explicit version parameter.
  """
  @spec read_version(String.t(), pos_integer(), keyword()) :: {:ok, map()} | {:error, Error.t()}
  def read_version(path, version, opts \\ []),
    do: read(path, Keyword.put(opts, :version, version))

  @doc """
  Write a secret to KV store with CAS (Check-And-Set) support.

  This is an alias for `write/3` with explicit cas parameter.
  """
  @spec write_cas(String.t(), map(), pos_integer(), keyword()) ::
          {:ok, map()} | {:error, Error.t()}
  def write_cas(path, data, cas, opts \\ []), do: write(path, data, Keyword.put(opts, :cas, cas))

  @doc """
  Delete specific versions of a secret (KV v2 only).

  This is an alias for `delete/2` with explicit versions parameter.
  """
  @spec delete_versions(String.t(), [pos_integer()], keyword()) :: :ok | {:error, Error.t()}
  def delete_versions(path, versions, opts \\ []),
    do: delete(path, Keyword.put(opts, :versions, versions))

  @doc """
  Get the latest version of a secret.

  This is a convenience function that reads the latest version.
  """
  @spec read_latest(String.t(), keyword()) :: {:ok, map()} | {:error, Error.t()}
  def read_latest(path, opts \\ []), do: read(path, opts)

  @doc """
  Check if a secret exists at the given path.
  """
  @spec exists?(String.t(), keyword()) :: boolean()
  def exists?(path, opts \\ []), do: do_exists?(path, opts)

  @doc """
  Get secret keys (field names) without values.
  """
  @spec keys(String.t(), keyword()) :: {:ok, [String.t()]} | {:error, Error.t()}
  def keys(path, opts \\ []), do: do_keys(path, opts)

  @doc """
  Get a specific field from a secret.
  """
  @spec get_field(String.t(), String.t(), keyword()) :: {:ok, any()} | {:error, Error.t()}
  def get_field(path, field, opts \\ []), do: do_get_field(path, field, opts)

  @doc """
  Update a single field in a secret (preserves other fields).
  """
  @spec update_field(String.t(), String.t(), any(), keyword()) ::
          {:ok, map()} | {:error, Error.t()}
  def update_field(path, field, value, opts \\ []), do: do_update_field(path, field, value, opts)

  # Internal implementations for convenience functions (allow 1-line public defs for coverage)
  defp do_exists?(path, opts) do
    case read(path, opts) do
      {:ok, _} -> true
      {:error, _} -> false
    end
  end

  defp do_keys(path, opts) do
    case read(path, opts) do
      {:ok, %{data: data}} when is_map(data) -> {:ok, Map.keys(data)}
      {:error, error} -> {:error, error}
    end
  end

  defp do_get_field(path, field, opts) do
    case read(path, opts) do
      {:ok, %{data: data}} when is_map(data) ->
        case Map.get(data, field) do
          nil -> {:error, Error.new(:not_found, "Field '#{field}' not found")}
          value -> {:ok, value}
        end

      {:error, error} ->
        {:error, error}
    end
  end

  defp do_update_field(path, field, value, opts) do
    case read(path, opts) do
      {:ok, %{data: data}} when is_map(data) ->
        updated_data = Map.put(data, field, value)
        write(path, updated_data, opts)

      {:error, error} ->
        {:error, error}
    end
  end

  # Private functions

  defp with_version_detection(path, opts, operation_fn) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    case detect_kv_version(mount_path, opts) do
      {:ok, version} ->
        engine_module = get_engine_module(version)
        operation_fn.(version, engine_module)

      {:error, error} ->
        Logger.error("KV version detection failed", %{
          mount_path: mount_path,
          path: path,
          error: error
        })

        {:error, error}
    end
  end

  defp get_engine_module(1), do: V1
  defp get_engine_module(2), do: V2

  defp do_detect_kv_version(mount_path, opts) do
    Logger.debug("Detecting KV version", %{mount_path: mount_path})

    # Method 1: Check mount information
    case HTTP.get("/v1/sys/mounts", opts) do
      {:ok, %{status: 200, body: %{"data" => mounts}}} ->
        mount_key = mount_path <> "/"

        case Map.get(mounts, mount_key) do
          %{"options" => %{"version" => version_str}} when is_binary(version_str) ->
            case Integer.parse(version_str) do
              {version, ""} when version in [1, 2] ->
                Logger.debug("Detected KV version from mount info", %{
                  mount_path: mount_path,
                  version: version
                })

                {:ok, version}

              _ ->
                detect_by_api_behavior(mount_path, opts)
            end

          %{"type" => "kv"} ->
            # Default to v2 for new KV engines without explicit version
            Logger.debug("KV engine found without version, defaulting to v2", %{
              mount_path: mount_path
            })

            {:ok, 2}

          nil ->
            {:error, Error.new(:not_found, "Mount path not found: #{mount_path}")}

          _ ->
            detect_by_api_behavior(mount_path, opts)
        end

      {:error, _} ->
        # Fallback to API behavior detection
        detect_by_api_behavior(mount_path, opts)

      _ ->
        detect_by_api_behavior(mount_path, opts)
    end
  end

  defp detect_by_api_behavior(mount_path, opts) do
    Logger.debug("Detecting KV version by API behavior", %{mount_path: mount_path})

    # Try KV v2 config endpoint - only exists in v2
    case HTTP.get("/v1/#{mount_path}/config", opts) do
      {:ok, %{status: 200}} ->
        Logger.debug("KV v2 detected via config endpoint", %{mount_path: mount_path})
        {:ok, 2}

      {:ok, %{status: 404}} ->
        Logger.debug("KV v1 detected (no config endpoint)", %{mount_path: mount_path})
        {:ok, 1}

      {:error, reason} ->
        Logger.error("Failed to detect KV version", %{
          mount_path: mount_path,
          reason: reason
        })

        {:error,
         Error.new(:unknown_error, "Could not detect KV version",
           details: %{
             mount_path: mount_path,
             reason: reason
           }
         )}

      _ ->
        # Default to v1 if uncertain
        Logger.debug("Defaulting to KV v1 due to uncertain detection", %{mount_path: mount_path})
        {:ok, 1}
    end
  end
end
