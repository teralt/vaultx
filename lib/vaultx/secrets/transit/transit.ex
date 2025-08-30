defmodule Vaultx.Secrets.Transit do
  @moduledoc """
  Unified Transit secrets engine interface for HashiCorp Vault.

  This module provides a comprehensive, enterprise-grade interface for the
  Transit secrets engine, offering encryption-as-a-service functionality
  with advanced key management, data encryption/decryption, digital signatures,
  HMAC operations, and cryptographically secure random data generation.

  ## Enterprise Encryption-as-a-Service

  - Advanced Key Management: Create, read, update, rotate, and securely delete encryption keys
  - High-Performance Encryption: Symmetric and asymmetric encryption/decryption operations
  - Digital Signature Services: Sign and verify data with industry-standard algorithms
  - HMAC Authentication: Generate and verify HMAC signatures for data integrity
  - Batch Operations: High-throughput batch processing for enterprise workloads
  - Multi-Tenant Key Derivation: Context-based key derivation for secure multi-tenancy
  - Convergent Encryption: Deterministic encryption for deduplication and storage efficiency
  - Secure Random Generation: Cryptographically secure random data for enterprise applications

  ## Usage Examples

      # Key management
      :ok = Vaultx.Secrets.Transit.create_key("my-app-key", "aes256-gcm96")
      {:ok, key_info} = Vaultx.Secrets.Transit.read_key("my-app-key")
      :ok = Vaultx.Secrets.Transit.rotate_key("my-app-key")

      # Encryption operations
      {:ok, result} = Vaultx.Secrets.Transit.encrypt("my-key", "dGVzdCBkYXRh")
      {:ok, plaintext} = Vaultx.Secrets.Transit.decrypt("my-key", result.ciphertext)

      # Digital signatures
      {:ok, signature} = Vaultx.Secrets.Transit.sign("signing-key", "dGVzdCBkYXRh")
      {:ok, valid} = Vaultx.Secrets.Transit.verify("signing-key", "dGVzdCBkYXRh", signature.signature)

      # HMAC operations
      {:ok, hmac} = Vaultx.Secrets.Transit.hmac("hmac-key", "dGVzdCBkYXRh")
      {:ok, valid} = Vaultx.Secrets.Transit.verify_hmac("hmac-key", "dGVzdCBkYXRh", hmac.hmac)

      # Random data generation
      {:ok, random} = Vaultx.Secrets.Transit.generate_random(32)

  ## Configuration

      # Enable Transit engine
      vault secrets enable transit

      # Enable at custom path
      vault secrets enable -path=encryption transit

  ## Key Types

  ### Symmetric Encryption
  - `aes128-gcm96` - AES-128 with GCM (96-bit nonce)
  - `aes256-gcm96` - AES-256 with GCM (96-bit nonce, default)
  - `chacha20-poly1305` - ChaCha20-Poly1305 AEAD

  ### Asymmetric Encryption/Signing
  - `rsa-2048`, `rsa-3072`, `rsa-4096` - RSA keys
  - `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521` - ECDSA keys
  - `ed25519` - Ed25519 keys

  ### Special Purpose
  - `hmac` - HMAC key generation and verification

  ## Security Best Practices

  - Use key derivation for multi-tenant applications
  - Rotate keys regularly using the rotate_key function
  - Use convergent encryption carefully (requires unique nonces)
  - Always validate signatures and HMAC values
  - Use appropriate key types for your use case
  - Monitor key usage through telemetry events

  ## API Compliance

  Fully implements HashiCorp Vault Transit secrets engine:
  - [Transit Secrets Engine](https://developer.hashicorp.com/vault/api-docs/secret/transit)
  - [Transit Encryption Guide](https://developer.hashicorp.com/vault/docs/secrets/transit)
  - [Transit Best Practices](https://developer.hashicorp.com/vault/tutorials/encryption-as-a-service)

  """

  @behaviour Vaultx.Secrets.Transit.Behaviour

  alias Vaultx.Base.{Error, Logger, Telemetry}
  alias Vaultx.Secrets.Transit.{Encryption, Keys}
  alias Vaultx.Transport.HTTP

  @default_mount_path "transit"

  # Key Management Operations

  @impl true
  def create_key(name, key_type \\ "aes256-gcm96", opts \\ []) do
    # Convert atom key types to strings for API compatibility
    string_key_type = normalize_key_type(key_type)
    Keys.create(name, string_key_type, opts)
  end

  @impl true
  def read_key(name, opts \\ []) do
    Keys.read(name, opts)
  end

  @impl true
  def update_key_config(name, config, opts \\ []) do
    Keys.update_config(name, config, opts)
  end

  @impl true
  def rotate_key(name, opts \\ []) do
    Keys.rotate(name, opts)
  end

  @impl true
  def delete_key(name, opts \\ []) do
    Keys.delete(name, opts)
  end

  @impl true
  def list_keys(opts \\ []) do
    Keys.list(opts)
  end

  # Encryption Operations

  @impl true
  def encrypt(key_name, plaintext, opts \\ []) do
    Encryption.encrypt(key_name, plaintext, opts)
  end

  @impl true
  def decrypt(key_name, ciphertext, opts \\ []) do
    Encryption.decrypt(key_name, ciphertext, opts)
  end

  @doc """
  Re-encrypts ciphertext with the latest version of the named key.

  ## Parameters

  - `key_name` - The name of the encryption key to use
  - `ciphertext` - The ciphertext to rewrap
  - `opts` - Additional options

  ## Returns

  - `{:ok, result}` - Rewrap successful
  - `{:error, reason}` - Rewrap failed

  ## Examples

      iex> rewrap("my-key", "vault:v1:old-ciphertext")
      {:ok, %{ciphertext: "vault:v2:new-ciphertext", key_version: 2}}

  """
  @spec rewrap(String.t(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def rewrap(key_name, ciphertext, opts \\ []) do
    Encryption.rewrap(key_name, ciphertext, opts)
  end

  @doc """
  Encrypts multiple plaintext items in a single request.

  ## Parameters

  - `key_name` - The name of the encryption key to use
  - `batch_items` - List of items to encrypt
  - `opts` - Additional options

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
  @spec batch_encrypt(String.t(), [map()], keyword()) :: {:ok, [map()]} | {:error, term()}
  def batch_encrypt(key_name, batch_items, opts \\ []) do
    Encryption.batch_encrypt(key_name, batch_items, opts)
  end

  # Digital Signature Operations

  @impl true
  def sign(key_name, data, opts \\ []) do
    start_time = System.monotonic_time()
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    metadata = %{
      operation: :sign,
      key_name: key_name,
      mount_path: mount_path
    }

    Logger.debug("Signing data with Transit key", metadata)
    Telemetry.operation_start(metadata)

    path = "#{mount_path}/sign/#{key_name}"
    payload = build_sign_payload(data, opts)

    case HTTP.post(path, payload, opts) do
      {:ok, %{status: 200, body: body}} ->
        duration = System.monotonic_time() - start_time

        result = parse_sign_response(body["data"])

        Logger.debug("Data signed successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, result}

      {:ok, %{status: 404}} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:key_not_found, "Key '#{key_name}' not found")

        Logger.warning("Transit key not found for signing", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warning("Data signing failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:network_error, "Failed to sign data: #{inspect(reason)}")

        Logger.error("Data signing network error", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @impl true
  def verify(key_name, data, signature, opts \\ []) do
    start_time = System.monotonic_time()
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    metadata = %{
      operation: :verify,
      key_name: key_name,
      mount_path: mount_path
    }

    Logger.debug("Verifying signature with Transit key", metadata)
    Telemetry.operation_start(metadata)

    path = "#{mount_path}/verify/#{key_name}"
    payload = build_verify_payload(data, signature, opts)

    case HTTP.post(path, payload, opts) do
      {:ok, %{status: 200, body: body}} ->
        duration = System.monotonic_time() - start_time

        valid = get_in(body, ["data", "valid"]) || false

        Logger.debug("Signature verified successfully", Map.put(metadata, :valid, valid))
        Telemetry.operation_success(duration, Map.put(metadata, :valid, valid))

        {:ok, valid}

      {:ok, %{status: 404}} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:key_not_found, "Key '#{key_name}' not found")

        Logger.warning("Transit key not found for verification", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warning("Signature verification failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:network_error, "Failed to verify signature: #{inspect(reason)}")

        Logger.error("Signature verification network error", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  # HMAC Operations

  @impl true
  def hmac(key_name, data, opts \\ []) do
    start_time = System.monotonic_time()
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    metadata = %{
      operation: :hmac,
      key_name: key_name,
      mount_path: mount_path
    }

    Logger.debug("Generating HMAC with Transit key", metadata)
    Telemetry.operation_start(metadata)

    path = "#{mount_path}/hmac/#{key_name}"
    payload = build_hmac_payload(data, opts)

    case HTTP.post(path, payload, opts) do
      {:ok, %{status: 200, body: body}} ->
        duration = System.monotonic_time() - start_time

        result = parse_hmac_response(body["data"])

        Logger.debug("HMAC generated successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, result}

      {:ok, %{status: 404}} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:key_not_found, "Key '#{key_name}' not found")

        Logger.warning("Transit key not found for HMAC", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warning("HMAC generation failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:network_error, "Failed to generate HMAC: #{inspect(reason)}")

        Logger.error("HMAC generation network error", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @impl true
  def verify_hmac(key_name, data, hmac, opts \\ []) do
    start_time = System.monotonic_time()
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    metadata = %{
      operation: :verify_hmac,
      key_name: key_name,
      mount_path: mount_path
    }

    Logger.debug("Verifying HMAC with Transit key", metadata)
    Telemetry.operation_start(metadata)

    path = "#{mount_path}/verify/#{key_name}"
    payload = build_verify_hmac_payload(data, hmac, opts)

    case HTTP.post(path, payload, opts) do
      {:ok, %{status: 200, body: body}} ->
        duration = System.monotonic_time() - start_time

        valid = get_in(body, ["data", "valid"]) || false

        Logger.debug("HMAC verified successfully", Map.put(metadata, :valid, valid))
        Telemetry.operation_success(duration, Map.put(metadata, :valid, valid))

        {:ok, valid}

      {:ok, %{status: 404}} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:key_not_found, "Key '#{key_name}' not found")

        Logger.warning(
          "Transit key not found for HMAC verification",
          Map.put(metadata, :error, error)
        )

        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warning("HMAC verification failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:network_error, "Failed to verify HMAC: #{inspect(reason)}")

        Logger.error("HMAC verification network error", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  # Utility Operations

  @impl true
  def generate_random(bytes, opts \\ []) do
    start_time = System.monotonic_time()
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    metadata = %{
      operation: :generate_random,
      bytes: bytes,
      mount_path: mount_path
    }

    Logger.debug("Generating random data", metadata)
    Telemetry.operation_start(metadata)

    path = "#{mount_path}/random/#{bytes}"
    format = Keyword.get(opts, :format, "base64")
    query_params = [{"format", format}]

    case HTTP.get(path, Keyword.put(opts, :query, query_params)) do
      {:ok, %{status: 200, body: body}} ->
        duration = System.monotonic_time() - start_time

        result = parse_random_response(body["data"])

        Logger.debug("Random data generated successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, result}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warning("Random data generation failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:network_error, "Failed to generate random data: #{inspect(reason)}")

        Logger.error("Random data generation network error", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  # Private helper functions

  defp build_sign_payload(data, opts) do
    base_payload = %{"input" => data}

    Enum.reduce(opts, base_payload, fn
      {:hash_algorithm, value}, acc when is_binary(value) ->
        Map.put(acc, "hash_algorithm", value)

      {:signature_algorithm, value}, acc when is_binary(value) ->
        Map.put(acc, "signature_algorithm", value)

      {:prehashed, value}, acc when is_boolean(value) ->
        Map.put(acc, "prehashed", value)

      {:context, value}, acc when is_binary(value) ->
        Map.put(acc, "context", value)

      _other, acc ->
        acc
    end)
  end

  defp build_verify_payload(data, signature, opts) do
    base_payload = %{"input" => data, "signature" => signature}

    Enum.reduce(opts, base_payload, fn
      {:hash_algorithm, value}, acc when is_binary(value) ->
        Map.put(acc, "hash_algorithm", value)

      {:signature_algorithm, value}, acc when is_binary(value) ->
        Map.put(acc, "signature_algorithm", value)

      {:prehashed, value}, acc when is_boolean(value) ->
        Map.put(acc, "prehashed", value)

      {:context, value}, acc when is_binary(value) ->
        Map.put(acc, "context", value)

      _other, acc ->
        acc
    end)
  end

  defp build_hmac_payload(data, opts) do
    base_payload = %{"input" => data}

    Enum.reduce(opts, base_payload, fn
      {:hash_algorithm, value}, acc when is_binary(value) ->
        Map.put(acc, "hash_algorithm", value)

      {:key_version, value}, acc when is_integer(value) and value > 0 ->
        Map.put(acc, "key_version", value)

      _other, acc ->
        acc
    end)
  end

  defp build_verify_hmac_payload(data, hmac, opts) do
    base_payload = %{"input" => data, "hmac" => hmac}

    Enum.reduce(opts, base_payload, fn
      {:hash_algorithm, value}, acc when is_binary(value) ->
        Map.put(acc, "hash_algorithm", value)

      _other, acc ->
        acc
    end)
  end

  defp parse_sign_response(data) when is_map(data) do
    %{
      signature: Map.get(data, "signature", ""),
      key_version: Map.get(data, "key_version", 1)
    }
  end

  defp parse_sign_response(_), do: %{signature: "", key_version: 1}

  defp parse_hmac_response(data) when is_map(data) do
    %{
      hmac: Map.get(data, "hmac", ""),
      key_version: Map.get(data, "key_version", 1)
    }
  end

  defp parse_hmac_response(_), do: %{hmac: "", key_version: 1}

  defp parse_random_response(data) when is_map(data) do
    %{
      random_bytes: Map.get(data, "random_bytes", "")
    }
  end

  defp parse_random_response(_), do: %{random_bytes: ""}

  # Key type normalization helper
  defp normalize_key_type(key_type) when is_atom(key_type) do
    case key_type do
      :aes128_gcm96 -> "aes128-gcm96"
      :aes256_gcm96 -> "aes256-gcm96"
      :chacha20_poly1305 -> "chacha20-poly1305"
      :rsa_2048 -> "rsa-2048"
      :rsa_3072 -> "rsa-3072"
      :rsa_4096 -> "rsa-4096"
      :ecdsa_p256 -> "ecdsa-p256"
      :ecdsa_p384 -> "ecdsa-p384"
      :ecdsa_p521 -> "ecdsa-p521"
      :ed25519 -> "ed25519"
      :hmac -> "hmac"
      :managed_key -> "managed_key"
      _ -> Atom.to_string(key_type)
    end
  end

  defp normalize_key_type(key_type) when is_binary(key_type), do: key_type
end
