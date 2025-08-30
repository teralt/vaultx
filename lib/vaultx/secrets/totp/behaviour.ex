defmodule Vaultx.Secrets.TOTP.Behaviour do
  @moduledoc """
  Behaviour definition for HashiCorp Vault TOTP secrets engine operations.

  This behaviour defines the interface that TOTP secrets engine implementations
  must provide, ensuring consistency and type safety across different implementations.

  ## Core Operations

  The TOTP secrets engine supports the following operations:

  ### Key Management Operations
  - `create_key/3` - Create or update a TOTP key
  - `read_key/2` - Read a TOTP key configuration
  - `list_keys/1` - List all configured keys
  - `delete_key/2` - Delete a TOTP key

  ### Code Operations
  - `generate_code/2` - Generate a TOTP code for a key
  - `validate_code/3` - Validate a TOTP code against a key

  ## API Compliance

  This behaviour ensures compliance with:
  - [Vault TOTP Secrets Engine API](https://developer.hashicorp.com/vault/api-docs/secret/totp)
  - [RFC 6238 - TOTP Algorithm](https://tools.ietf.org/html/rfc6238)

  """

  alias Vaultx.Base.Error

  @typedoc """
  TOTP key name.
  Must be a non-empty string with valid characters.
  """
  @type key_name :: String.t()

  @typedoc """
  TOTP key configuration parameters.
  """
  @type key_config :: %{
          # Key generation options
          optional(:generate) => boolean(),
          optional(:exported) => boolean(),
          optional(:key_size) => pos_integer(),
          # Manual key configuration
          optional(:url) => String.t(),
          optional(:key) => String.t(),
          # Key metadata
          optional(:issuer) => String.t(),
          optional(:account_name) => String.t(),
          # TOTP algorithm parameters
          optional(:period) => pos_integer(),
          optional(:algorithm) => String.t(),
          optional(:digits) => pos_integer(),
          optional(:skew) => non_neg_integer(),
          optional(:qr_size) => non_neg_integer()
        }

  @typedoc """
  TOTP key information returned from read operations.
  """
  @type key_info :: %{
          account_name: String.t(),
          algorithm: String.t(),
          digits: pos_integer(),
          issuer: String.t(),
          period: pos_integer()
        }

  @typedoc """
  TOTP key creation response with optional QR code and URL.
  """
  @type key_creation_response :: %{
          optional(:barcode) => String.t(),
          optional(:url) => String.t()
        }

  @typedoc """
  Generated TOTP code.
  """
  @type totp_code :: %{
          code: String.t()
        }

  @typedoc """
  TOTP code validation result.
  """
  @type validation_result :: %{
          valid: boolean()
        }

  @typedoc """
  Options for TOTP secrets engine operations.
  """
  @type operation_opts :: [
          mount_path: String.t(),
          timeout: pos_integer(),
          retry_attempts: non_neg_integer()
        ]

  @typedoc """
  Result of a key creation operation.
  """
  @type create_key_result :: {:ok, key_creation_response()} | {:error, Error.t()}

  @typedoc """
  Result of a key read operation.
  """
  @type read_key_result :: {:ok, key_info()} | {:error, Error.t()}

  @typedoc """
  Result of a key list operation.
  """
  @type list_keys_result :: {:ok, [String.t()]} | {:error, Error.t()}

  @typedoc """
  Result of a key delete operation.
  """
  @type delete_key_result :: :ok | {:error, Error.t()}

  @typedoc """
  Result of a code generation operation.
  """
  @type generate_code_result :: {:ok, totp_code()} | {:error, Error.t()}

  @typedoc """
  Result of a code validation operation.
  """
  @type validate_code_result :: {:ok, validation_result()} | {:error, Error.t()}

  @doc """
  Create or update a TOTP key.

  Creates a new TOTP key definition that can be used to generate
  time-based one-time passwords. Supports both generated keys
  and imported keys from external sources.

  ## Parameters

  - `name` - Key name
  - `config` - Key configuration parameters
  - `opts` - Operation options

  ## Returns

  - `{:ok, response}` - Successfully created key (may include QR code)
  - `{:error, error}` - Failed to create key

  ## Examples

      # Generate a new key
      config = %{
        generate: true,
        issuer: "MyApp",
        account_name: "user@example.com"
      }
      {:ok, response} = MyTOTP.create_key("user-key", config, [])

      # Import an existing key
      config = %{
        url: "otpauth://totp/Google:test@gmail.com?secret=Y64VEVMBTSXCYIWRSHRNDZW62MPGVU2G&issuer=Google"
      }
      {:ok, _} = MyTOTP.create_key("imported-key", config, [])

  """
  @callback create_key(key_name(), key_config(), operation_opts()) :: create_key_result()

  @doc """
  Read a TOTP key configuration.

  ## Parameters

  - `name` - Key name to read
  - `opts` - Operation options

  ## Returns

  - `{:ok, key_info}` - Successfully read key information
  - `{:error, error}` - Failed to read key

  ## Examples

      {:ok, info} = MyTOTP.read_key("user-key", [])

  """
  @callback read_key(key_name(), operation_opts()) :: read_key_result()

  @doc """
  List all configured TOTP keys.

  ## Parameters

  - `opts` - Operation options

  ## Returns

  - `{:ok, keys}` - Successfully listed keys
  - `{:error, error}` - Failed to list keys

  ## Examples

      {:ok, keys} = MyTOTP.list_keys([])

  """
  @callback list_keys(operation_opts()) :: list_keys_result()

  @doc """
  Delete a TOTP key.

  ## Parameters

  - `name` - Key name to delete
  - `opts` - Operation options

  ## Returns

  - `:ok` - Successfully deleted key
  - `{:error, error}` - Failed to delete key

  ## Examples

      :ok = MyTOTP.delete_key("old-key", [])

  """
  @callback delete_key(key_name(), operation_opts()) :: delete_key_result()

  @doc """
  Generate a TOTP code for a key.

  ## Parameters

  - `name` - Key name to generate code for
  - `opts` - Operation options

  ## Returns

  - `{:ok, code}` - Successfully generated code
  - `{:error, error}` - Failed to generate code

  ## Examples

      {:ok, code} = MyTOTP.generate_code("user-key", [])

  """
  @callback generate_code(key_name(), operation_opts()) :: generate_code_result()

  @doc """
  Validate a TOTP code against a key.

  ## Parameters

  - `name` - Key name to validate against
  - `code` - TOTP code to validate
  - `opts` - Operation options

  ## Returns

  - `{:ok, result}` - Successfully validated code
  - `{:error, error}` - Failed to validate code

  ## Examples

      {:ok, result} = MyTOTP.validate_code("user-key", "123456", [])

  """
  @callback validate_code(key_name(), String.t(), operation_opts()) :: validate_code_result()
end
