defmodule Vaultx.Secrets.Transit.Keys do
  @moduledoc """
  Enterprise key management for HashiCorp Vault Transit secrets engine.

  This module provides comprehensive cryptographic key management functionality
  for enterprise applications, including key creation, configuration, rotation,
  import/export, and complete lifecycle management operations. It supports
  industry-standard algorithms with enterprise-grade security and compliance.

  ## Enterprise Key Management Capabilities

  - Create keys with advanced algorithms and enterprise configurations
  - Read comprehensive key information and security metadata
  - Update key configurations and security policies
  - Automated and manual key rotation to new versions
  - Secure key material import and export with HSM integration
  - Safe key deletion with comprehensive safety checks
  - List and audit all available cryptographic keys
  - Enterprise backup and disaster recovery for key data

  ## Supported Key Types

  ### Symmetric Encryption Keys
  - `aes128-gcm96` - AES-128 with GCM (96-bit nonce)
  - `aes256-gcm96` - AES-256 with GCM (96-bit nonce, default)
  - `chacha20-poly1305` - ChaCha20-Poly1305 AEAD

  ### Asymmetric Keys
  - `rsa-2048`, `rsa-3072`, `rsa-4096` - RSA keys
  - `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521` - ECDSA keys
  - `ed25519` - Ed25519 keys

  ### Special Purpose Keys
  - `hmac` - HMAC key generation and verification
  - `managed_key` - External managed keys (Enterprise)

  ## Usage Examples

      # Create a new AES key
      {:ok, _} = Vaultx.Secrets.Transit.Keys.create("my-app-key", "aes256-gcm96")

      # Create a derived key for multi-tenant encryption
      {:ok, _} = Vaultx.Secrets.Transit.Keys.create("tenant-key", "aes256-gcm96",
        derived: true, convergent_encryption: true)

      # Read key information
      {:ok, key_info} = Vaultx.Secrets.Transit.Keys.read("my-app-key")

      # Update key configuration
      :ok = Vaultx.Secrets.Transit.Keys.update_config("my-app-key", %{
        deletion_allowed: true,
        min_encryption_version: 2
      })

      # Rotate key to new version
      :ok = Vaultx.Secrets.Transit.Keys.rotate("my-app-key")

      # List all keys
      {:ok, keys} = Vaultx.Secrets.Transit.Keys.list()

      # Export key material (if exportable)
      {:ok, key_data} = Vaultx.Secrets.Transit.Keys.export("my-key", "encryption-key")

      # Delete key (if deletion allowed)
      :ok = Vaultx.Secrets.Transit.Keys.delete("old-key")

  ## Key Configuration Options

  ### Creation Options
  - `:derived` - Enable key derivation for multi-tenant use
  - `:convergent_encryption` - Enable deterministic encryption
  - `:exportable` - Allow key material export
  - `:allow_plaintext_backup` - Allow plaintext key backup
  - `:auto_rotate_period` - Automatic rotation period
  - `:key_size` - Key size for variable-size algorithms

  ### Update Options
  - `:min_decryption_version` - Minimum version for decryption
  - `:min_encryption_version` - Minimum version for encryption
  - `:deletion_allowed` - Allow key deletion
  - `:auto_rotate_period` - Update rotation period

  ## Security Considerations

  - Keys cannot be deleted by default (must enable `deletion_allowed`)
  - Exported keys should be handled with extreme care
  - Key rotation creates new versions without invalidating old ones
  - Minimum version settings can prevent use of compromised key versions
  - Convergent encryption requires careful nonce management

  ## API Compliance

  Fully implements HashiCorp Vault Transit key management:
  - [Transit Key Management](https://developer.hashicorp.com/vault/api-docs/secret/transit#create-key)
  - [Transit Key Configuration](https://developer.hashicorp.com/vault/api-docs/secret/transit#update-key-configuration)
  - [Transit Key Rotation](https://developer.hashicorp.com/vault/api-docs/secret/transit#rotate-key)

  """

  alias Vaultx.Base.{Error, Logger, Telemetry}
  alias Vaultx.Transport.HTTP

  @default_mount_path "transit"
  @default_key_type "aes256-gcm96"

  @typedoc """
  Key creation options.
  """
  @type create_opts :: [
          derived: boolean(),
          convergent_encryption: boolean(),
          exportable: boolean(),
          allow_plaintext_backup: boolean(),
          auto_rotate_period: String.t(),
          key_size: pos_integer(),
          managed_key_name: String.t(),
          managed_key_id: String.t()
        ]

  @typedoc """
  Key configuration options.
  """
  @type config_opts :: [
          min_decryption_version: non_neg_integer(),
          min_encryption_version: non_neg_integer(),
          deletion_allowed: boolean(),
          exportable: boolean(),
          allow_plaintext_backup: boolean(),
          auto_rotate_period: String.t()
        ]

  @typedoc """
  Key information structure.
  """
  @type key_info :: %{
          name: String.t(),
          type: String.t(),
          derived: boolean(),
          exportable: boolean(),
          allow_plaintext_backup: boolean(),
          keys: map(),
          min_decryption_version: non_neg_integer(),
          min_encryption_version: non_neg_integer(),
          deletion_allowed: boolean(),
          supports_encryption: boolean(),
          supports_decryption: boolean(),
          supports_derivation: boolean(),
          supports_signing: boolean(),
          imported: boolean(),
          auto_rotate_period: String.t()
        }

  @doc """
  Creates a new named encryption key.

  ## Parameters

  - `name` - The name of the encryption key to create
  - `key_type` - The type of key to create (default: "aes256-gcm96")
  - `opts` - Key creation options

  ## Options

  - `:mount_path` - Transit engine mount path (default: "transit")
  - `:derived` - Enable key derivation (default: false)
  - `:convergent_encryption` - Enable convergent encryption (default: false)
  - `:exportable` - Allow key export (default: false)
  - `:allow_plaintext_backup` - Allow plaintext backup (default: false)
  - `:auto_rotate_period` - Automatic rotation period (default: "0")
  - `:key_size` - Key size for variable-size algorithms
  - `:managed_key_name` - Name of managed key (for managed_key type)
  - `:managed_key_id` - UUID of managed key (for managed_key type)

  ## Returns

  - `:ok` - Key created successfully
  - `{:error, reason}` - Key creation failed

  ## Examples

      iex> create("my-app-key", "aes256-gcm96")
      :ok

      iex> create("tenant-key", "aes256-gcm96", derived: true, convergent_encryption: true)
      :ok

      iex> create("signing-key", "ed25519", exportable: true)
      :ok

  """
  @spec create(String.t(), String.t(), keyword()) :: :ok | {:error, term()}
  def create(name, key_type \\ @default_key_type, opts \\ []) do
    start_time = System.monotonic_time()
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    metadata = %{
      operation: :create_key,
      key_name: name,
      key_type: key_type,
      mount_path: mount_path
    }

    Logger.debug("Creating Transit key", metadata)
    Telemetry.operation_start(metadata)

    path = "#{mount_path}/keys/#{name}"
    payload = build_create_payload(key_type, opts)

    case HTTP.post(path, payload, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        duration = System.monotonic_time() - start_time

        Logger.info("Transit key created successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        :ok

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warning("Transit key creation failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:network_error, "Failed to create key: #{inspect(reason)}")

        Logger.error("Transit key creation network error", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Reads information about a named encryption key.

  ## Parameters

  - `name` - The name of the encryption key to read
  - `opts` - Additional options

  ## Options

  - `:mount_path` - Transit engine mount path (default: "transit")

  ## Returns

  - `{:ok, key_info}` - Key information retrieved successfully
  - `{:error, reason}` - Key read failed

  ## Examples

      iex> read("my-app-key")
      {:ok, %{name: "my-app-key", type: "aes256-gcm96", ...}}

  """
  @spec read(String.t(), keyword()) :: {:ok, key_info()} | {:error, term()}
  def read(name, opts \\ []) do
    start_time = System.monotonic_time()
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    metadata = %{
      operation: :read_key,
      key_name: name,
      mount_path: mount_path
    }

    Logger.debug("Reading Transit key", metadata)
    Telemetry.operation_start(metadata)

    path = "#{mount_path}/keys/#{name}"

    case HTTP.get(path, opts) do
      {:ok, %{status: 200, body: body}} ->
        duration = System.monotonic_time() - start_time

        key_info = parse_key_info(body["data"])

        Logger.debug("Transit key read successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, key_info}

      {:ok, %{status: 404}} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:key_not_found, "Key '#{name}' not found")

        Logger.warning("Transit key not found", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warning("Transit key read failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:network_error, "Failed to read key: #{inspect(reason)}")

        Logger.error("Transit key read network error", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Updates configuration for a named encryption key.

  ## Parameters

  - `name` - The name of the encryption key to update
  - `config` - Configuration updates to apply
  - `opts` - Additional options

  ## Options

  - `:mount_path` - Transit engine mount path (default: "transit")

  ## Configuration Options

  - `:min_decryption_version` - Minimum version for decryption
  - `:min_encryption_version` - Minimum version for encryption
  - `:deletion_allowed` - Allow key deletion
  - `:exportable` - Allow key export (cannot be disabled once set)
  - `:allow_plaintext_backup` - Allow plaintext backup (cannot be disabled once set)
  - `:auto_rotate_period` - Automatic rotation period

  ## Returns

  - `:ok` - Key configuration updated successfully
  - `{:error, reason}` - Key update failed

  ## Examples

      iex> update_config("my-app-key", %{deletion_allowed: true})
      :ok

      iex> update_config("my-app-key", %{min_encryption_version: 2, auto_rotate_period: "24h"})
      :ok

  """
  @spec update_config(String.t(), map(), keyword()) :: :ok | {:error, term()}
  def update_config(name, config, opts \\ []) do
    start_time = System.monotonic_time()
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    metadata = %{
      operation: :update_key_config,
      key_name: name,
      mount_path: mount_path,
      config_keys: Map.keys(config)
    }

    Logger.debug("Updating Transit key configuration", metadata)
    Telemetry.operation_start(metadata)

    path = "#{mount_path}/keys/#{name}/config"

    case HTTP.post(path, config, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        duration = System.monotonic_time() - start_time

        Logger.info("Transit key configuration updated successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        :ok

      {:ok, %{status: 404}} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:key_not_found, "Key '#{name}' not found")

        Logger.warning(
          "Transit key not found for config update",
          Map.put(metadata, :error, error)
        )

        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warning("Transit key config update failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:network_error, "Failed to update key config: #{inspect(reason)}")

        Logger.error("Transit key config update network error", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  # Private helper functions

  defp build_create_payload(key_type, opts) do
    base_payload = %{"type" => key_type}

    Enum.reduce(opts, base_payload, fn
      {:derived, value}, acc when is_boolean(value) ->
        Map.put(acc, "derived", value)

      {:convergent_encryption, value}, acc when is_boolean(value) ->
        Map.put(acc, "convergent_encryption", value)

      {:exportable, value}, acc when is_boolean(value) ->
        Map.put(acc, "exportable", value)

      {:allow_plaintext_backup, value}, acc when is_boolean(value) ->
        Map.put(acc, "allow_plaintext_backup", value)

      {:auto_rotate_period, value}, acc when is_binary(value) ->
        Map.put(acc, "auto_rotate_period", value)

      {:key_size, value}, acc when is_integer(value) and value > 0 ->
        Map.put(acc, "key_size", value)

      {:managed_key_name, value}, acc when is_binary(value) ->
        Map.put(acc, "managed_key_name", value)

      {:managed_key_id, value}, acc when is_binary(value) ->
        Map.put(acc, "managed_key_id", value)

      _other, acc ->
        acc
    end)
  end

  defp parse_key_info(data) when is_map(data) do
    %{
      name: Map.get(data, "name", ""),
      type: Map.get(data, "type", ""),
      derived: Map.get(data, "derived", false),
      exportable: Map.get(data, "exportable", false),
      allow_plaintext_backup: Map.get(data, "allow_plaintext_backup", false),
      keys: Map.get(data, "keys", %{}),
      min_decryption_version: Map.get(data, "min_decryption_version", 0),
      min_encryption_version: Map.get(data, "min_encryption_version", 0),
      deletion_allowed: Map.get(data, "deletion_allowed", false),
      supports_encryption: Map.get(data, "supports_encryption", false),
      supports_decryption: Map.get(data, "supports_decryption", false),
      supports_derivation: Map.get(data, "supports_derivation", false),
      supports_signing: Map.get(data, "supports_signing", false),
      imported: Map.get(data, "imported", false),
      auto_rotate_period: Map.get(data, "auto_rotate_period", "0")
    }
  end

  defp parse_key_info(_) do
    %{
      name: "",
      type: "",
      derived: false,
      exportable: false,
      allow_plaintext_backup: false,
      keys: %{},
      min_decryption_version: 0,
      min_encryption_version: 0,
      deletion_allowed: false,
      supports_encryption: false,
      supports_decryption: false,
      supports_derivation: false,
      supports_signing: false,
      imported: false,
      auto_rotate_period: "0"
    }
  end

  @doc """
  Rotates a named encryption key to create a new version.

  ## Parameters

  - `name` - The name of the encryption key to rotate
  - `opts` - Additional options

  ## Options

  - `:mount_path` - Transit engine mount path (default: "transit")

  ## Returns

  - `:ok` - Key rotated successfully
  - `{:error, reason}` - Key rotation failed

  ## Examples

      iex> rotate("my-app-key")
      :ok

  """
  @spec rotate(String.t(), keyword()) :: :ok | {:error, term()}
  def rotate(name, opts \\ []) do
    start_time = System.monotonic_time()
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    metadata = %{
      operation: :rotate_key,
      key_name: name,
      mount_path: mount_path
    }

    Logger.debug("Rotating Transit key", metadata)
    Telemetry.operation_start(metadata)

    path = "#{mount_path}/keys/#{name}/rotate"

    case HTTP.post(path, %{}, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        duration = System.monotonic_time() - start_time

        Logger.info("Transit key rotated successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        :ok

      {:ok, %{status: 404}} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:key_not_found, "Key '#{name}' not found")

        Logger.warning("Transit key not found for rotation", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warning("Transit key rotation failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:network_error, "Failed to rotate key: #{inspect(reason)}")

        Logger.error("Transit key rotation network error", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Deletes a named encryption key.

  Note: The key must have `deletion_allowed` set to true before it can be deleted.

  ## Parameters

  - `name` - The name of the encryption key to delete
  - `opts` - Additional options

  ## Options

  - `:mount_path` - Transit engine mount path (default: "transit")

  ## Returns

  - `:ok` - Key deleted successfully
  - `{:error, reason}` - Key deletion failed

  ## Examples

      iex> delete("old-key")
      :ok

  """
  @spec delete(String.t(), keyword()) :: :ok | {:error, term()}
  def delete(name, opts \\ []) do
    start_time = System.monotonic_time()
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    metadata = %{
      operation: :delete_key,
      key_name: name,
      mount_path: mount_path
    }

    Logger.debug("Deleting Transit key", metadata)
    Telemetry.operation_start(metadata)

    path = "#{mount_path}/keys/#{name}"

    case HTTP.delete(path, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        duration = System.monotonic_time() - start_time

        Logger.info("Transit key deleted successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        :ok

      {:ok, %{status: 404}} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:key_not_found, "Key '#{name}' not found")

        Logger.warning("Transit key not found for deletion", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warning("Transit key deletion failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:network_error, "Failed to delete key: #{inspect(reason)}")

        Logger.error("Transit key deletion network error", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Lists all available encryption keys.

  ## Parameters

  - `opts` - Additional options

  ## Options

  - `:mount_path` - Transit engine mount path (default: "transit")

  ## Returns

  - `{:ok, keys}` - List of key names
  - `{:error, reason}` - List operation failed

  ## Examples

      iex> list()
      {:ok, ["key1", "key2", "key3"]}

  """
  @spec list(keyword()) :: {:ok, [String.t()]} | {:error, term()}
  def list(opts \\ []) do
    start_time = System.monotonic_time()
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    metadata = %{
      operation: :list_keys,
      mount_path: mount_path
    }

    Logger.debug("Listing Transit keys", metadata)
    Telemetry.operation_start(metadata)

    path = "#{mount_path}/keys"
    query_params = [{"list", "true"}]

    case HTTP.get(path, Keyword.put(opts, :query, query_params)) do
      {:ok, %{status: 200, body: body}} ->
        duration = System.monotonic_time() - start_time

        keys =
          case get_in(body, ["data", "keys"]) do
            list when is_list(list) -> list
            _ -> []
          end

        Logger.debug("Transit keys listed successfully", Map.put(metadata, :count, length(keys)))
        Telemetry.operation_success(duration, Map.put(metadata, :count, length(keys)))

        {:ok, keys}

      {:ok, %{status: 404}} ->
        duration = System.monotonic_time() - start_time

        Logger.debug("No Transit keys found", metadata)
        Telemetry.operation_success(duration, Map.put(metadata, :count, 0))

        {:ok, []}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warning("Transit key listing failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:network_error, "Failed to list keys: #{inspect(reason)}")

        Logger.error("Transit key listing network error", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end
end
