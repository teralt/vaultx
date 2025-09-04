defmodule Vaultx.Secrets.Transit.Encryption do
  @moduledoc """
  Enterprise encryption services for HashiCorp Vault Transit secrets engine.

  This module provides comprehensive encryption and decryption functionality
  for enterprise applications, including symmetric and asymmetric encryption,
  high-performance batch operations, key derivation, and convergent encryption
  support. It implements industry-standard cryptographic algorithms with
  enterprise-grade security and performance.

  ## Enterprise Encryption Capabilities

  - High-performance symmetric encryption/decryption (AES-GCM, ChaCha20-Poly1305)
  - Asymmetric encryption/decryption (RSA-OAEP, RSA-PKCS1)
  - Batch operations for high-throughput enterprise workloads
  - Context-based key derivation for multi-tenant scenarios
  - Convergent encryption for deterministic, deduplication-friendly results
  - Associated data support for authenticated encryption (AEAD)
  - Key version selection for cryptographic agility
  - Data rewrapping for seamless key rotation

  ## Supported Algorithms

  ### Symmetric Ciphers
  - `aes128-gcm96` - AES-128 with GCM (96-bit nonce)
  - `aes256-gcm96` - AES-256 with GCM (96-bit nonce, default)
  - `chacha20-poly1305` - ChaCha20-Poly1305 AEAD

  ### Asymmetric Ciphers
  - `rsa-2048`, `rsa-3072`, `rsa-4096` - RSA encryption

  ## Usage Examples

      # Basic encryption/decryption
      {:ok, result} = Vaultx.Secrets.Transit.Encryption.encrypt("my-key", "dGVzdCBkYXRh")
      {:ok, plaintext} = Vaultx.Secrets.Transit.Encryption.decrypt("my-key", result.ciphertext)

      # Encryption with context (key derivation)
      {:ok, result} = Vaultx.Secrets.Transit.Encryption.encrypt("tenant-key", "dGVzdCBkYXRh",
        context: "dGVuYW50LWlk")

      # Convergent encryption (deterministic)
      {:ok, result} = Vaultx.Secrets.Transit.Encryption.encrypt("convergent-key", "dGVzdCBkYXRh",
        nonce: "bm9uY2U=")

      # Batch encryption
      batch_items = [
        %{plaintext: "dGVzdDE="},
        %{plaintext: "dGVzdDI=", context: "Y29udGV4dA=="}
      ]
      {:ok, results} = Vaultx.Secrets.Transit.Encryption.batch_encrypt("my-key", batch_items)

      # Rewrap data with latest key version
      {:ok, rewrapped} = Vaultx.Secrets.Transit.Encryption.rewrap("my-key", old_ciphertext)

  ## Encryption Options

  - `:context` - Base64 encoded key derivation context
  - `:nonce` - Base64 encoded nonce for convergent encryption
  - `:key_version` - Specific key version to use for encryption
  - `:associated_data` - Additional authenticated data for AEAD
  - `:type` - Encryption type ("aead" for AEAD ciphers)

  ## Security Considerations

  - Always use base64 encoding for plaintext and context data
  - Context should be unique per tenant/user for derived keys
  - Nonce must be unique for convergent encryption
  - Associated data is authenticated but not encrypted
  - Key versions allow for gradual key rotation

  ## API Compliance

  Fully implements HashiCorp Vault Transit encryption operations:
  - [Transit Encrypt API](https://developer.hashicorp.com/vault/api-docs/secret/transit#encrypt-data)
  - [Transit Decrypt API](https://developer.hashicorp.com/vault/api-docs/secret/transit#decrypt-data)
  - [Transit Batch Operations](https://developer.hashicorp.com/vault/api-docs/secret/transit#batch-encrypt-data)

  """

  alias Vaultx.Base.{Error, Logger, Telemetry}
  alias Vaultx.Transport.HTTP

  @default_mount_path "transit"

  @typedoc """
  Encryption result structure.
  """
  @type encryption_result :: %{
          ciphertext: String.t(),
          key_version: pos_integer()
        }

  @typedoc """
  Decryption result structure.
  """
  @type decryption_result :: %{
          plaintext: String.t(),
          key_version: pos_integer()
        }

  @typedoc """
  Batch encryption item.
  """
  @type batch_encrypt_item :: %{
          plaintext: String.t(),
          context: String.t() | nil,
          nonce: String.t() | nil,
          associated_data: String.t() | nil
        }

  @typedoc """
  Batch decryption item.
  """
  @type batch_decrypt_item :: %{
          ciphertext: String.t(),
          context: String.t() | nil,
          nonce: String.t() | nil,
          associated_data: String.t() | nil
        }

  @doc """
  Encrypts plaintext data using a named key.

  ## Parameters

  - `key_name` - The name of the encryption key to use
  - `plaintext` - Base64 encoded plaintext to encrypt
  - `opts` - Additional encryption options

  ## Options

  - `:mount_path` - Transit engine mount path (default: "transit")
  - `:context` - Base64 encoded key derivation context
  - `:nonce` - Base64 encoded nonce for convergent encryption
  - `:key_version` - Specific key version to use
  - `:associated_data` - Additional authenticated data for AEAD
  - `:type` - Encryption type ("aead" for AEAD ciphers)

  ## Returns

  - `{:ok, result}` - Encryption successful
  - `{:error, reason}` - Encryption failed

  ## Examples

      iex> encrypt("my-key", "dGVzdCBkYXRh")
      {:ok, %{ciphertext: "vault:v1:...", key_version: 1}}

      iex> encrypt("my-key", "dGVzdCBkYXRh", context: "Y29udGV4dA==")
      {:ok, %{ciphertext: "vault:v1:...", key_version: 1}}

  """
  @spec encrypt(String.t(), String.t(), keyword()) ::
          {:ok, encryption_result()} | {:error, term()}
  def encrypt(key_name, plaintext, opts \\ []) do
    start_time = System.monotonic_time()
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    metadata = %{
      operation: :encrypt,
      key_name: key_name,
      mount_path: mount_path,
      has_context: Keyword.has_key?(opts, :context),
      has_nonce: Keyword.has_key?(opts, :nonce)
    }

    Logger.debug("Encrypting data with Transit key", metadata)
    Telemetry.operation_start(metadata)

    path = "#{mount_path}/encrypt/#{key_name}"
    payload = build_encrypt_payload(plaintext, opts)

    case HTTP.post(path, payload, opts) do
      {:ok, %{status: 200, body: body}} ->
        duration = System.monotonic_time() - start_time

        result = parse_encrypt_response(body["data"])

        Logger.debug("Data encrypted successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, result}

      {:ok, %{status: 404}} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:key_not_found, "Key '#{key_name}' not found")

        Logger.warn("Transit key not found for encryption", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warn("Data encryption failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:network_error, "Failed to encrypt data: #{inspect(reason)}")

        Logger.error("Data encryption network error", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Decrypts ciphertext data using a named key.

  ## Parameters

  - `key_name` - The name of the encryption key to use
  - `ciphertext` - The ciphertext to decrypt
  - `opts` - Additional decryption options

  ## Options

  - `:mount_path` - Transit engine mount path (default: "transit")
  - `:context` - Base64 encoded key derivation context
  - `:nonce` - Base64 encoded nonce for convergent encryption
  - `:associated_data` - Additional authenticated data for AEAD

  ## Returns

  - `{:ok, result}` - Decryption successful
  - `{:error, reason}` - Decryption failed

  ## Examples

      iex> decrypt("my-key", "vault:v1:...")
      {:ok, %{plaintext: "dGVzdCBkYXRh", key_version: 1}}

      iex> decrypt("my-key", "vault:v1:...", context: "Y29udGV4dA==")
      {:ok, %{plaintext: "dGVzdCBkYXRh", key_version: 1}}

  """
  @spec decrypt(String.t(), String.t(), keyword()) ::
          {:ok, decryption_result()} | {:error, term()}
  def decrypt(key_name, ciphertext, opts \\ []) do
    start_time = System.monotonic_time()
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    metadata = %{
      operation: :decrypt,
      key_name: key_name,
      mount_path: mount_path,
      has_context: Keyword.has_key?(opts, :context),
      has_nonce: Keyword.has_key?(opts, :nonce)
    }

    Logger.debug("Decrypting data with Transit key", metadata)
    Telemetry.operation_start(metadata)

    path = "#{mount_path}/decrypt/#{key_name}"
    payload = build_decrypt_payload(ciphertext, opts)

    case HTTP.post(path, payload, opts) do
      {:ok, %{status: 200, body: body}} ->
        duration = System.monotonic_time() - start_time

        result = parse_decrypt_response(body["data"])

        Logger.debug("Data decrypted successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, result}

      {:ok, %{status: 404}} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:key_not_found, "Key '#{key_name}' not found")

        Logger.warn("Transit key not found for decryption", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warn("Data decryption failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:network_error, "Failed to decrypt data: #{inspect(reason)}")

        Logger.error("Data decryption network error", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  # Private helper functions

  defp build_encrypt_payload(plaintext, opts) do
    base_payload = %{"plaintext" => plaintext}

    Enum.reduce(opts, base_payload, fn
      {:context, value}, acc when is_binary(value) ->
        Map.put(acc, "context", value)

      {:nonce, value}, acc when is_binary(value) ->
        Map.put(acc, "nonce", value)

      {:key_version, value}, acc when is_integer(value) and value > 0 ->
        Map.put(acc, "key_version", value)

      {:associated_data, value}, acc when is_binary(value) ->
        Map.put(acc, "associated_data", value)

      {:type, value}, acc when is_binary(value) ->
        Map.put(acc, "type", value)

      _other, acc ->
        acc
    end)
  end

  defp build_decrypt_payload(ciphertext, opts) do
    base_payload = %{"ciphertext" => ciphertext}

    Enum.reduce(opts, base_payload, fn
      {:context, value}, acc when is_binary(value) ->
        Map.put(acc, "context", value)

      {:nonce, value}, acc when is_binary(value) ->
        Map.put(acc, "nonce", value)

      {:associated_data, value}, acc when is_binary(value) ->
        Map.put(acc, "associated_data", value)

      _other, acc ->
        acc
    end)
  end

  defp parse_encrypt_response(data) when is_map(data) do
    %{
      ciphertext: Map.get(data, "ciphertext", ""),
      key_version: Map.get(data, "key_version", 1)
    }
  end

  defp parse_encrypt_response(_), do: %{ciphertext: "", key_version: 1}

  defp parse_decrypt_response(data) when is_map(data) do
    %{
      plaintext: Map.get(data, "plaintext", ""),
      key_version: Map.get(data, "key_version", 1)
    }
  end

  defp parse_decrypt_response(_), do: %{plaintext: "", key_version: 1}

  @doc """
  Re-encrypts ciphertext with the latest version of the named key.

  This is useful for key rotation scenarios where you want to upgrade
  ciphertext to use the latest key version without decrypting and re-encrypting.

  ## Parameters

  - `key_name` - The name of the encryption key to use
  - `ciphertext` - The ciphertext to rewrap
  - `opts` - Additional options

  ## Options

  - `:mount_path` - Transit engine mount path (default: "transit")
  - `:context` - Base64 encoded key derivation context
  - `:nonce` - Base64 encoded nonce for convergent encryption
  - `:key_version` - Specific key version to rewrap to

  ## Returns

  - `{:ok, result}` - Rewrap successful
  - `{:error, reason}` - Rewrap failed

  ## Examples

      iex> rewrap("my-key", "vault:v1:old-ciphertext")
      {:ok, %{ciphertext: "vault:v2:new-ciphertext", key_version: 2}}

  """
  @spec rewrap(String.t(), String.t(), keyword()) :: {:ok, encryption_result()} | {:error, term()}
  def rewrap(key_name, ciphertext, opts \\ []) do
    start_time = System.monotonic_time()
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    metadata = %{
      operation: :rewrap,
      key_name: key_name,
      mount_path: mount_path
    }

    Logger.debug("Rewrapping data with Transit key", metadata)
    Telemetry.operation_start(metadata)

    path = "#{mount_path}/rewrap/#{key_name}"
    payload = build_rewrap_payload(ciphertext, opts)

    case HTTP.post(path, payload, opts) do
      {:ok, %{status: 200, body: body}} ->
        duration = System.monotonic_time() - start_time

        result = parse_encrypt_response(body["data"])

        Logger.debug("Data rewrapped successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, result}

      {:ok, %{status: 404}} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:key_not_found, "Key '#{key_name}' not found")

        Logger.warn("Transit key not found for rewrap", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warn("Data rewrap failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:network_error, "Failed to rewrap data: #{inspect(reason)}")

        Logger.error("Data rewrap network error", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Encrypts multiple plaintext items in a single request.

  ## Parameters

  - `key_name` - The name of the encryption key to use
  - `batch_items` - List of items to encrypt
  - `opts` - Additional options

  ## Options

  - `:mount_path` - Transit engine mount path (default: "transit")

  ## Returns

  - `{:ok, results}` - Batch encryption successful
  - `{:error, reason}` - Batch encryption failed

  ## Examples

      iex> batch_items = [
      ...>   %{plaintext: "dGVzdDE="},
      ...>   %{plaintext: "dGVzdDI=", context: "Y29udGV4dA=="}
      ...> ]
      iex> batch_encrypt("my-key", batch_items)
      {:ok, [%{ciphertext: "vault:v1:...", key_version: 1}, ...]}

  """
  @spec batch_encrypt(String.t(), [batch_encrypt_item()], keyword()) ::
          {:ok, [encryption_result()]} | {:error, term()}
  def batch_encrypt(key_name, batch_items, opts \\ []) do
    start_time = System.monotonic_time()
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    metadata = %{
      operation: :batch_encrypt,
      key_name: key_name,
      mount_path: mount_path,
      batch_size: length(batch_items)
    }

    Logger.debug("Batch encrypting data with Transit key", metadata)
    Telemetry.operation_start(metadata)

    path = "#{mount_path}/encrypt/#{key_name}"
    payload = %{"batch_input" => batch_items}

    case HTTP.post(path, payload, opts) do
      {:ok, %{status: 200, body: body}} ->
        duration = System.monotonic_time() - start_time

        results = parse_batch_encrypt_response(body["data"])

        Logger.debug("Batch data encrypted successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, results}

      {:ok, %{status: 404}} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:key_not_found, "Key '#{key_name}' not found")

        Logger.warn(
          "Transit key not found for batch encryption",
          Map.put(metadata, :error, error)
        )

        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warn("Batch data encryption failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:network_error, "Failed to batch encrypt data: #{inspect(reason)}")

        Logger.error("Batch data encryption network error", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  # Additional private helper functions

  defp build_rewrap_payload(ciphertext, opts) do
    base_payload = %{"ciphertext" => ciphertext}

    Enum.reduce(opts, base_payload, fn
      {:context, value}, acc when is_binary(value) ->
        Map.put(acc, "context", value)

      {:nonce, value}, acc when is_binary(value) ->
        Map.put(acc, "nonce", value)

      {:key_version, value}, acc when is_integer(value) and value > 0 ->
        Map.put(acc, "key_version", value)

      _other, acc ->
        acc
    end)
  end

  defp parse_batch_encrypt_response(data) when is_map(data) do
    batch_results = Map.get(data, "batch_results", [])

    case batch_results do
      list when is_list(list) ->
        Enum.map(list, fn item ->
          %{
            ciphertext: Map.get(item, "ciphertext", ""),
            key_version: Map.get(item, "key_version", 1)
          }
        end)

      _ ->
        []
    end
  end

  defp parse_batch_encrypt_response(_), do: []
end
