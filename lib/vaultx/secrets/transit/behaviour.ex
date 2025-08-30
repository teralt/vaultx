defmodule Vaultx.Secrets.Transit.Behaviour do
  @moduledoc """
  Comprehensive behaviour for HashiCorp Vault Transit secrets engine.

  This behaviour provides enterprise-grade
  encryption-as-a-service functionality. It provides a complete interface
  for cryptographic operations including encryption, decryption, digital
  signatures, key management, and HMAC operations with industry-standard
  algorithms and security practices.

  ## Enterprise Cryptographic Capabilities

  ### Advanced Key Management
  - Create, read, update, and delete encryption keys with policies
  - Support for multiple key types (AES, RSA, ECDSA, Ed25519, ChaCha20)
  - Automated key rotation and comprehensive versioning
  - Secure key import and export with HSM integration
  - Configurable key policies, constraints, and lifecycle management

  ### High-Performance Encryption
  - Symmetric encryption/decryption (AES-GCM, ChaCha20-Poly1305)
  - Asymmetric encryption/decryption (RSA-OAEP, RSA-PKCS1)
  - Convergent encryption for deterministic, deduplication-friendly results
  - Batch operations for high-throughput scenarios
  - Associated data support for AEAD ciphers and authenticated encryption

  ### Digital Signature Services
  - Sign and verify data with industry-standard algorithms
  - Support for RSA-PSS, RSA-PKCS1v15, ECDSA, Ed25519 signatures
  - Batch signing and verification for operational efficiency
  - Pre-hashed data support for large payloads
  - Message recovery and signature format flexibility

  ### HMAC and Authentication
  - Generate and verify HMAC signatures with configurable algorithms
  - Support for SHA-256, SHA-384, SHA-512 hash functions
  - Batch HMAC operations for high-throughput authentication
  - Key derivation for context-specific authentication

  ### Enterprise Features
  - Cryptographically secure random data generation
  - Key derivation and context-based cryptographic operations
  - Certificate signing request (CSR) generation and processing
  - Secure key backup and disaster recovery
  - Performance optimization through intelligent caching

  ## Extended Operations

  Beyond the base secrets operations, Transit engines support:

  ### Key Management
  - `create_key/3` - Create a new encryption key
  - `read_key/2` - Read key information and metadata
  - `update_key_config/3` - Update key configuration
  - `rotate_key/2` - Rotate key to new version
  - `delete_key/2` - Delete an encryption key
  - `list_keys/1` - List all available keys
  - `export_key/3` - Export key material
  - `import_key/3` - Import external key material

  ### Encryption Operations
  - `encrypt/3` - Encrypt plaintext data
  - `decrypt/3` - Decrypt ciphertext data
  - `rewrap/3` - Re-encrypt data with latest key version
  - `batch_encrypt/2` - Encrypt multiple items
  - `batch_decrypt/2` - Decrypt multiple items

  ### Digital Signatures
  - `sign/3` - Sign data with a key
  - `verify/4` - Verify signature against data
  - `batch_sign/2` - Sign multiple items
  - `batch_verify/2` - Verify multiple signatures

  ### HMAC Operations
  - `hmac/3` - Generate HMAC for data
  - `verify_hmac/4` - Verify HMAC signature
  - `batch_hmac/2` - Generate HMAC for multiple items

  ### Utility Operations
  - `generate_random/2` - Generate random data
  - `hash/3` - Hash data with specified algorithm
  - `generate_data_key/3` - Generate data encryption key

  ## Usage Examples

      defmodule MyApp.TransitEngine do
        @behaviour Vaultx.Secrets.Transit.Behaviour

        # Key management
        @impl true
        def create_key(name, key_type, opts) do
          # Implementation for key creation
        end

        # Encryption operations
        @impl true
        def encrypt(key_name, plaintext, opts) do
          # Implementation for data encryption
        end

        # Digital signatures
        @impl true
        def sign(key_name, data, opts) do
          # Implementation for data signing
        end

        # HMAC operations
        @impl true
        def hmac(key_name, data, opts) do
          # Implementation for HMAC generation
        end
      end

  ## Key Types and Algorithms

  ### Symmetric Keys
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

  ## Error Handling

  Transit operations return standardized errors:

      {:error, %Vaultx.Base.Error{
        type: :key_not_found,
        message: "Key 'my-key' not found",
        details: %{key_name: "my-key", mount_path: "transit"}
      }}

  ## Configuration Options

  Transit operations support various options:

  - `:mount_path` - Transit engine mount path (default: "transit")
  - `:timeout` - Request timeout in milliseconds
  - `:retry_attempts` - Number of retry attempts
  - `:namespace` - Vault namespace (Enterprise)
  - `:token` - Override authentication token

  ### Encryption Options
  - `:context` - Key derivation context (base64 encoded)
  - `:nonce` - Nonce for convergent encryption (base64 encoded)
  - `:key_version` - Specific key version to use
  - `:associated_data` - Additional authenticated data for AEAD

  ### Key Creation Options
  - `:derived` - Enable key derivation
  - `:convergent_encryption` - Enable convergent encryption
  - `:exportable` - Allow key export
  - `:allow_plaintext_backup` - Allow plaintext backup
  - `:auto_rotate_period` - Automatic rotation period

  ## References

  - [Transit Secrets Engine API](https://developer.hashicorp.com/vault/api-docs/secret/transit)
  - [Transit Encryption Guide](https://developer.hashicorp.com/vault/docs/secrets/transit)
  - [Cryptographic Standards](https://developer.hashicorp.com/vault/docs/secrets/transit#key-types)

  """

  @typedoc """
  Transit operation options.
  Common options for all transit operations.
  """
  @type transit_opts :: [
          # Base options
          mount_path: String.t(),
          timeout: pos_integer(),
          retry_attempts: non_neg_integer(),
          namespace: String.t(),
          token: String.t(),

          # Encryption options
          context: String.t(),
          nonce: String.t(),
          key_version: pos_integer(),
          associated_data: String.t(),
          padding_scheme: String.t(),

          # Key creation options
          derived: boolean(),
          convergent_encryption: boolean(),
          exportable: boolean(),
          allow_plaintext_backup: boolean(),
          auto_rotate_period: String.t(),
          key_size: pos_integer(),

          # Signing options
          hash_algorithm: String.t(),
          signature_algorithm: String.t(),
          prehashed: boolean(),

          # Batch options
          batch_input: [map()],
          partial_failure_response_code: pos_integer()
        ]

  @typedoc """
  Supported key types for Transit engine.
  Can be either atom or string format.
  """
  @type key_type ::
          :aes128_gcm96
          | :aes256_gcm96
          | :chacha20_poly1305
          | :rsa_2048
          | :rsa_3072
          | :rsa_4096
          | :ecdsa_p256
          | :ecdsa_p384
          | :ecdsa_p521
          | :ed25519
          | :hmac
          | :managed_key
          | String.t()

  @typedoc """
  Key information structure returned by read operations.
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
  Signature result structure.
  """
  @type signature_result :: %{
          signature: String.t(),
          key_version: pos_integer()
        }

  @typedoc """
  HMAC result structure.
  """
  @type hmac_result :: %{
          hmac: String.t(),
          key_version: pos_integer()
        }

  @typedoc """
  Random data result structure.
  """
  @type random_result :: %{
          random_bytes: String.t()
        }

  # Key Management Operations

  @doc """
  Creates a new named encryption key.

  ## Parameters

  - `name` - The name of the encryption key to create
  - `key_type` - The type of key to create
  - `opts` - Additional options for key creation

  ## Returns

  - `:ok` - Key created successfully
  - `{:error, reason}` - Key creation failed

  ## Examples

      iex> create_key("my-app-key", :aes256_gcm96, derived: true)
      :ok

      iex> create_key("signing-key", :ed25519, exportable: true)
      :ok

  """
  @callback create_key(name :: String.t(), key_type :: key_type(), opts :: transit_opts()) ::
              :ok | {:error, term()}

  @doc """
  Reads information about a named encryption key.

  ## Parameters

  - `name` - The name of the encryption key to read
  - `opts` - Additional options

  ## Returns

  - `{:ok, key_info}` - Key information retrieved successfully
  - `{:error, reason}` - Key read failed

  ## Examples

      iex> read_key("my-app-key")
      {:ok, %{name: "my-app-key", type: "aes256-gcm96", ...}}

  """
  @callback read_key(name :: String.t(), opts :: transit_opts()) ::
              {:ok, key_info()} | {:error, term()}

  @doc """
  Updates configuration for a named encryption key.

  ## Parameters

  - `name` - The name of the encryption key to update
  - `config` - Configuration updates to apply
  - `opts` - Additional options

  ## Returns

  - `:ok` - Key configuration updated successfully
  - `{:error, reason}` - Key update failed

  ## Examples

      iex> update_key_config("my-app-key", %{deletion_allowed: true})
      :ok

  """
  @callback update_key_config(name :: String.t(), config :: map(), opts :: transit_opts()) ::
              :ok | {:error, term()}

  @doc """
  Rotates a named encryption key to create a new version.

  ## Parameters

  - `name` - The name of the encryption key to rotate
  - `opts` - Additional options

  ## Returns

  - `:ok` - Key rotated successfully
  - `{:error, reason}` - Key rotation failed

  ## Examples

      iex> rotate_key("my-app-key")
      :ok

  """
  @callback rotate_key(name :: String.t(), opts :: transit_opts()) ::
              :ok | {:error, term()}

  @doc """
  Deletes a named encryption key.

  ## Parameters

  - `name` - The name of the encryption key to delete
  - `opts` - Additional options

  ## Returns

  - `:ok` - Key deleted successfully
  - `{:error, reason}` - Key deletion failed

  ## Examples

      iex> delete_key("old-key")
      :ok

  """
  @callback delete_key(name :: String.t(), opts :: transit_opts()) ::
              :ok | {:error, term()}

  @doc """
  Lists all available encryption keys.

  ## Parameters

  - `opts` - Additional options

  ## Returns

  - `{:ok, keys}` - List of key names
  - `{:error, reason}` - List operation failed

  ## Examples

      iex> list_keys()
      {:ok, ["key1", "key2", "key3"]}

  """
  @callback list_keys(opts :: transit_opts()) ::
              {:ok, [String.t()]} | {:error, term()}

  # Encryption Operations

  @doc """
  Encrypts plaintext data using a named key.

  ## Parameters

  - `key_name` - The name of the encryption key to use
  - `plaintext` - Base64 encoded plaintext to encrypt
  - `opts` - Additional encryption options

  ## Returns

  - `{:ok, result}` - Encryption successful
  - `{:error, reason}` - Encryption failed

  ## Examples

      iex> encrypt("my-key", "dGVzdCBkYXRh", context: "Y29udGV4dA==")
      {:ok, %{ciphertext: "vault:v1:...", key_version: 1}}

  """
  @callback encrypt(key_name :: String.t(), plaintext :: String.t(), opts :: transit_opts()) ::
              {:ok, encryption_result()} | {:error, term()}

  @doc """
  Decrypts ciphertext data using a named key.

  ## Parameters

  - `key_name` - The name of the encryption key to use
  - `ciphertext` - The ciphertext to decrypt
  - `opts` - Additional decryption options

  ## Returns

  - `{:ok, result}` - Decryption successful
  - `{:error, reason}` - Decryption failed

  ## Examples

      iex> decrypt("my-key", "vault:v1:...", context: "Y29udGV4dA==")
      {:ok, %{plaintext: "dGVzdCBkYXRh", key_version: 1}}

  """
  @callback decrypt(key_name :: String.t(), ciphertext :: String.t(), opts :: transit_opts()) ::
              {:ok, decryption_result()} | {:error, term()}

  # Digital Signature Operations

  @doc """
  Signs data using a named key.

  ## Parameters

  - `key_name` - The name of the signing key to use
  - `data` - Base64 encoded data to sign
  - `opts` - Additional signing options

  ## Returns

  - `{:ok, result}` - Signing successful
  - `{:error, reason}` - Signing failed

  ## Examples

      iex> sign("signing-key", "dGVzdCBkYXRh", hash_algorithm: "sha2-256")
      {:ok, %{signature: "vault:v1:...", key_version: 1}}

  """
  @callback sign(key_name :: String.t(), data :: String.t(), opts :: transit_opts()) ::
              {:ok, signature_result()} | {:error, term()}

  @doc """
  Verifies a signature against data using a named key.

  ## Parameters

  - `key_name` - The name of the verification key to use
  - `data` - Base64 encoded data that was signed
  - `signature` - The signature to verify
  - `opts` - Additional verification options

  ## Returns

  - `{:ok, valid}` - Verification completed, returns boolean validity
  - `{:error, reason}` - Verification failed

  ## Examples

      iex> verify("signing-key", "dGVzdCBkYXRh", "vault:v1:...", hash_algorithm: "sha2-256")
      {:ok, true}

  """
  @callback verify(
              key_name :: String.t(),
              data :: String.t(),
              signature :: String.t(),
              opts :: transit_opts()
            ) ::
              {:ok, boolean()} | {:error, term()}

  # HMAC Operations

  @doc """
  Generates HMAC for data using a named key.

  ## Parameters

  - `key_name` - The name of the HMAC key to use
  - `data` - Base64 encoded data to generate HMAC for
  - `opts` - Additional HMAC options

  ## Returns

  - `{:ok, result}` - HMAC generation successful
  - `{:error, reason}` - HMAC generation failed

  ## Examples

      iex> hmac("hmac-key", "dGVzdCBkYXRh", hash_algorithm: "sha2-256")
      {:ok, %{hmac: "vault:v1:...", key_version: 1}}

  """
  @callback hmac(key_name :: String.t(), data :: String.t(), opts :: transit_opts()) ::
              {:ok, hmac_result()} | {:error, term()}

  @doc """
  Verifies HMAC signature against data using a named key.

  ## Parameters

  - `key_name` - The name of the HMAC key to use
  - `data` - Base64 encoded data that was signed
  - `hmac` - The HMAC signature to verify
  - `opts` - Additional verification options

  ## Returns

  - `{:ok, valid}` - Verification completed, returns boolean validity
  - `{:error, reason}` - Verification failed

  ## Examples

      iex> verify_hmac("hmac-key", "dGVzdCBkYXRh", "vault:v1:...")
      {:ok, true}

  """
  @callback verify_hmac(
              key_name :: String.t(),
              data :: String.t(),
              hmac :: String.t(),
              opts :: transit_opts()
            ) ::
              {:ok, boolean()} | {:error, term()}

  # Utility Operations

  @doc """
  Generates cryptographically secure random data.

  ## Parameters

  - `bytes` - Number of random bytes to generate
  - `opts` - Additional options

  ## Returns

  - `{:ok, result}` - Random data generated successfully
  - `{:error, reason}` - Random generation failed

  ## Examples

      iex> generate_random(32)
      {:ok, %{random_bytes: "base64-encoded-random-data"}}

  """
  @callback generate_random(bytes :: pos_integer(), opts :: transit_opts()) ::
              {:ok, random_result()} | {:error, term()}
end
