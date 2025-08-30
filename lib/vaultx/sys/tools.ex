defmodule Vaultx.Sys.Tools do
  @moduledoc """
  HashiCorp Vault tools operations.

  This module provides a general set of cryptographic and utility tools available
  through Vault's system backend. These tools leverage Vault's cryptographic
  capabilities for various operations without requiring secrets storage.

  ## Tools Features

  ### Random Byte Generation
  - High-Quality Entropy: Generate cryptographically secure random bytes
  - Multiple Sources: Platform entropy, seal entropy, or mixed sources
  - Flexible Output: Configurable byte count and encoding formats
  - Enterprise Features: Entropy augmentation support in Vault Enterprise

  ### Data Hashing
  - Multiple Algorithms: Support for SHA-2 and SHA-3 hash families
  - Flexible Input: Base64 encoded input data processing
  - Output Formats: Hex or Base64 encoded hash outputs
  - Cryptographic Security: Industry-standard hash algorithms

  ## Important Notes

  **Authentication Required**
  - All tools endpoints require valid authentication
  - Appropriate permissions needed for tool access
  - Some features may be restricted based on policy

  **Enterprise Features**
  - Seal entropy source requires Vault Enterprise
  - Mixed entropy sources available in Enterprise editions
  - Platform entropy available in all editions

  **Input Validation**
  - Hash input must be base64 encoded
  - Random byte counts have reasonable limits
  - Invalid parameters will return appropriate errors

  ## API Compliance

  Fully implements HashiCorp Vault Tools API:
  - [Tools API](https://developer.hashicorp.com/vault/api-docs/system/tools)
  - [Vault Cryptographic Operations](https://developer.hashicorp.com/vault/docs/concepts/cryptographic-operations)

  ## Usage Examples

  ### Random Byte Generation

      # Generate 32 random bytes (default)
      {:ok, random_data} = Vaultx.Sys.Tools.generate_random()
      IO.puts("Random bytes: \#{random_data.random_bytes}")

      # Generate 64 bytes in hex format
      {:ok, random_data} = Vaultx.Sys.Tools.generate_random(
        bytes: 64,
        format: "hex"
      )

      # Use platform entropy source
      {:ok, random_data} = Vaultx.Sys.Tools.generate_random(
        bytes: 128,
        source: "platform"
      )

  ### Data Hashing

      # Hash data with SHA-256 (default)
      input_data = Base.encode64("Hello, World!")
      {:ok, hash_result} = Vaultx.Sys.Tools.hash_data(input_data)
      IO.puts("SHA-256 hash: \#{hash_result.sum}")

      # Hash with SHA-512 in base64 format
      {:ok, hash_result} = Vaultx.Sys.Tools.hash_data(
        input_data,
        algorithm: "sha2-512",
        format: "base64"
      )

      # Hash with SHA-3
      {:ok, hash_result} = Vaultx.Sys.Tools.hash_data(
        input_data,
        algorithm: "sha3-256"
      )

  ## Random Generation

  ### Supported Sources
  - `"platform"`: Platform's entropy source (default)
  - `"seal"`: Entropy augmentation (Enterprise only)
  - `"all"`: Mixed bytes from all available sources

  ### Output Formats
  - `"base64"`: Base64 encoded output (default)
  - `"hex"`: Hexadecimal encoded output

  ## Hash Algorithms

  ### SHA-2 Family
  - `"sha2-224"`: SHA-224 hash algorithm
  - `"sha2-256"`: SHA-256 hash algorithm (default)
  - `"sha2-384"`: SHA-384 hash algorithm
  - `"sha2-512"`: SHA-512 hash algorithm

  ### SHA-3 Family
  - `"sha3-224"`: SHA3-224 hash algorithm
  - `"sha3-256"`: SHA3-256 hash algorithm
  - `"sha3-384"`: SHA3-384 hash algorithm
  - `"sha3-512"`: SHA3-512 hash algorithm

  ## Use Cases

  ### Security Operations
  - Generate secure random tokens and keys
  - Create cryptographic nonces and salts
  - Hash sensitive data for comparison
  - Implement secure random number generation

  ### Application Integration
  - Generate session tokens and identifiers
  - Create secure random passwords
  - Hash user inputs for verification
  - Implement cryptographic protocols

  ### Development and Testing
  - Generate test data and fixtures
  - Create mock cryptographic values
  - Validate hash implementations
  - Test random number generation
  """

  alias Vaultx.Base.{Error, Logger, Telemetry}
  alias Vaultx.Transport.HTTP
  alias Vaultx.Types

  @valid_sources ~w(platform seal all)
  @valid_formats ~w(base64 hex)
  @valid_algorithms ~w(sha2-224 sha2-256 sha2-384 sha2-512 sha3-224 sha3-256 sha3-384 sha3-512)

  @typedoc """
  Random bytes generation result.
  """
  @type random_result :: %{
          :random_bytes => String.t()
        }

  @typedoc """
  Hash computation result.
  """
  @type hash_result :: %{
          :sum => String.t()
        }

  @doc """
  Generate high-quality random bytes.

  This endpoint returns high-quality random bytes of the specified length.

  ## Parameters

  - `opts` - Options for random generation
    - `:bytes` - Number of bytes to return (default: 32)
    - `:format` - Output encoding: "base64" or "hex" (default: "base64")
    - `:source` - Entropy source: "platform", "seal", or "all" (default: "platform")
    - Other HTTP request options

  ## Returns

  Returns `{:ok, random_result()}` with random bytes,
  or `{:error, Error.t()}` on failure.

  ## Examples

      # Generate 32 random bytes (default)
      {:ok, result} = Vaultx.Sys.Tools.generate_random()

      # Generate 64 bytes in hex format
      {:ok, result} = Vaultx.Sys.Tools.generate_random(
        bytes: 64,
        format: "hex"
      )

      # Use seal entropy (Enterprise)
      {:ok, result} = Vaultx.Sys.Tools.generate_random(
        bytes: 128,
        source: "seal"
      )

  """
  @spec generate_random(Types.options()) :: {:ok, random_result()} | {:error, Error.t()}
  def generate_random(opts \\ []) do
    bytes = Keyword.get(opts, :bytes, 32)
    format = Keyword.get(opts, :format, "base64")
    source = Keyword.get(opts, :source, "platform")

    with :ok <- validate_bytes(bytes),
         :ok <- validate_format(format),
         :ok <- validate_source(source) do
      path = "sys/tools/random/#{source}/#{bytes}"

      payload = %{format: format}

      metadata = %{
        operation: :generate_random,
        bytes: bytes,
        format: format,
        source: source
      }

      Logger.debug("Generating random bytes", metadata)
      Telemetry.operation_start(metadata)

      start_time = System.monotonic_time()

      case HTTP.post(path, payload, opts) do
        {:ok, %{status: 200, body: %{"data" => data}}} ->
          duration = System.monotonic_time() - start_time

          result = %{random_bytes: data["random_bytes"]}

          Logger.info("Successfully generated random bytes", metadata)
          Telemetry.operation_success(duration, metadata)

          {:ok, result}

        {:ok, %{status: status_code, body: body}} ->
          duration = System.monotonic_time() - start_time

          error =
            Error.new(:server_error, "Failed to generate random bytes: HTTP #{status_code}",
              details: %{status: status_code, body: body}
            )

          Logger.error("Failed to generate random bytes", Map.put(metadata, :error, error))
          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}

        {:error, error} ->
          duration = System.monotonic_time() - start_time

          Logger.error("Error generating random bytes", Map.put(metadata, :error, error))
          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}
      end
    end
  end

  @doc """
  Hash data using specified algorithm.

  This endpoint returns the cryptographic hash of given data using the specified
  algorithm.

  ## Parameters

  - `input` - Base64 encoded input data to hash
  - `opts` - Options for hashing
    - `:algorithm` - Hash algorithm to use (default: "sha2-256")
    - `:format` - Output encoding: "hex" or "base64" (default: "hex")
    - Other HTTP request options

  ## Returns

  Returns `{:ok, hash_result()}` with computed hash,
  or `{:error, Error.t()}` on failure.

  ## Examples

      # Hash with SHA-256 (default)
      input = Base.encode64("Hello, World!")
      {:ok, result} = Vaultx.Sys.Tools.hash_data(input)

      # Hash with SHA-512 in base64 format
      {:ok, result} = Vaultx.Sys.Tools.hash_data(
        input,
        algorithm: "sha2-512",
        format: "base64"
      )

      # Hash with SHA-3
      {:ok, result} = Vaultx.Sys.Tools.hash_data(
        input,
        algorithm: "sha3-256"
      )

  """
  @spec hash_data(String.t(), Types.options()) :: {:ok, hash_result()} | {:error, Error.t()}
  def hash_data(input, opts \\ []) when is_binary(input) do
    algorithm = Keyword.get(opts, :algorithm, "sha2-256")
    format = Keyword.get(opts, :format, "hex")

    with :ok <- validate_algorithm(algorithm),
         :ok <- validate_format(format),
         :ok <- validate_base64_input(input) do
      path = "sys/tools/hash/#{algorithm}"

      payload = %{
        input: input,
        format: format
      }

      metadata = %{
        operation: :hash_data,
        algorithm: algorithm,
        format: format,
        input_length: byte_size(input)
      }

      Logger.debug("Hashing data", metadata)
      Telemetry.operation_start(metadata)

      start_time = System.monotonic_time()

      case HTTP.post(path, payload, opts) do
        {:ok, %{status: 200, body: %{"data" => data}}} ->
          duration = System.monotonic_time() - start_time

          result = %{sum: data["sum"]}

          Logger.info("Successfully hashed data", metadata)
          Telemetry.operation_success(duration, metadata)

          {:ok, result}

        {:ok, %{status: status_code, body: body}} ->
          duration = System.monotonic_time() - start_time

          error =
            Error.new(:server_error, "Failed to hash data: HTTP #{status_code}",
              details: %{status: status_code, body: body}
            )

          Logger.error("Failed to hash data", Map.put(metadata, :error, error))
          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}

        {:error, error} ->
          duration = System.monotonic_time() - start_time

          Logger.error("Error hashing data", Map.put(metadata, :error, error))
          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}
      end
    end
  end

  @doc """
  Generate random bytes with automatic base64 encoding.

  This is a convenience function that generates random bytes and returns them
  as a base64 encoded string, suitable for use as tokens or keys.

  ## Parameters

  - `bytes` - Number of bytes to generate (default: 32)
  - `opts` - Additional options (passed to `generate_random/1`)

  ## Returns

  Returns `{:ok, String.t()}` with base64 encoded random bytes,
  or `{:error, Error.t()}` on failure.

  ## Examples

      # Generate 32-byte token
      {:ok, token} = Vaultx.Sys.Tools.generate_token()

      # Generate 64-byte key
      {:ok, key} = Vaultx.Sys.Tools.generate_token(64)

  """
  @spec generate_token(pos_integer(), Types.options()) :: {:ok, String.t()} | {:error, Error.t()}
  def generate_token(bytes \\ 32, opts \\ []) do
    case generate_random(Keyword.merge(opts, bytes: bytes, format: "base64")) do
      {:ok, result} -> {:ok, result.random_bytes}
      {:error, error} -> {:error, error}
    end
  end

  @doc """
  Hash a string with automatic base64 encoding.

  This is a convenience function that automatically base64 encodes the input
  string before hashing, suitable for hashing plain text data.

  ## Parameters

  - `data` - String data to hash
  - `opts` - Options for hashing (same as `hash_data/2`)

  ## Returns

  Returns `{:ok, String.t()}` with computed hash,
  or `{:error, Error.t()}` on failure.

  ## Examples

      # Hash a password
      {:ok, hash} = Vaultx.Sys.Tools.hash_string("my-password")

      # Hash with SHA-512
      {:ok, hash} = Vaultx.Sys.Tools.hash_string(
        "sensitive-data",
        algorithm: "sha2-512"
      )

  """
  @spec hash_string(String.t(), Types.options()) :: {:ok, String.t()} | {:error, Error.t()}
  def hash_string(data, opts \\ []) when is_binary(data) do
    encoded_input = Base.encode64(data)

    case hash_data(encoded_input, opts) do
      {:ok, result} -> {:ok, result.sum}
      {:error, error} -> {:error, error}
    end
  end

  # Private helper functions

  defp validate_bytes(bytes) when is_integer(bytes) and bytes > 0 and bytes <= 1024, do: :ok

  defp validate_bytes(bytes) do
    {:error,
     Error.new(:invalid_parameter, "Invalid byte count: #{bytes}",
       details: %{valid_range: "1-1024", provided: bytes}
     )}
  end

  defp validate_format(format) when format in @valid_formats, do: :ok

  defp validate_format(format) do
    {:error,
     Error.new(:invalid_parameter, "Invalid format: #{format}",
       details: %{valid_formats: @valid_formats, provided: format}
     )}
  end

  defp validate_source(source) when source in @valid_sources, do: :ok

  defp validate_source(source) do
    {:error,
     Error.new(:invalid_parameter, "Invalid source: #{source}",
       details: %{valid_sources: @valid_sources, provided: source}
     )}
  end

  defp validate_algorithm(algorithm) when algorithm in @valid_algorithms, do: :ok

  defp validate_algorithm(algorithm) do
    {:error,
     Error.new(:invalid_parameter, "Invalid algorithm: #{algorithm}",
       details: %{valid_algorithms: @valid_algorithms, provided: algorithm}
     )}
  end

  defp validate_base64_input(input) do
    case Base.decode64(input) do
      {:ok, _} ->
        :ok

      :error ->
        {:error,
         Error.new(:invalid_parameter, "Input must be valid base64 encoded data",
           details: %{provided_input: String.slice(input, 0, 50) <> "..."}
         )}
    end
  end
end
