defmodule Vaultx.Sys.AuditHash do
  @moduledoc """
  HashiCorp Vault audit hash calculation operations.

  This module provides audit hash calculation capabilities for Vault, allowing you
  to calculate the hash of data using an audit device's hash function and salt.
  This is essential for searching audit logs for hashed values when the original
  plaintext value is known.

  ## Audit Hash Features

  ### Core Functionality
  - Hash Calculation: Generate hashes using audit device's hash function
  - Salt Integration: Use audit device's salt for consistent hashing
  - Log Search Support: Find obfuscated values in audit logs
  - Binary Data Support: Handle base64-encoded binary data

  ### Use Cases
  - Audit Log Analysis: Search for specific values in audit logs
  - Compliance Verification: Verify data presence in audit trails
  - Security Investigation: Track specific data access patterns
  - Data Correlation: Match plaintext values with audit log entries

  ### Hash Function Support
  - HMAC-SHA256: Standard audit hash function
  - Salt-based Hashing: Consistent hashing with audit device salt
  - Binary Data Handling: Proper encoding for binary data

  ## Important Security Notes

  Restricted Endpoint
  - Must be called from root or administrative namespace
  - Requires appropriate audit device access permissions
  - Hash calculation uses the same salt as audit device

  Data Encoding Requirements
  - Binary data must be base64-encoded before hashing
  - JSON API responses are automatically base64-encoded by Vault
  - Use proper encoding for certificate data (DER format)

  ## API Compliance

  Fully implements HashiCorp Vault Audit Hash API:
  - [Audit Hash API](https://developer.hashicorp.com/vault/api-docs/system/audit-hash)
  - [Audit Devices](https://developer.hashicorp.com/vault/docs/audit)

  ## Usage Examples

  ### Basic Hash Calculation

      {:ok, result} = Vaultx.Sys.AuditHash.calculate("file-audit", "my-secret-value")
      result.hash #=> "hmac-sha256:08ba35a1b2c3d4e5f6..."

  ### Search for Value in Audit Logs

      # Calculate hash for known plaintext
      {:ok, result} = Vaultx.Sys.AuditHash.calculate("file-audit", "user-token-123")

      # Search audit logs for this hash value
      # grep "hmac-sha256:08ba35..." /var/log/vault/audit.log

  ### Binary Data Hashing

      # For binary data like certificates, base64-encode first
      cert_der = File.read!("certificate.der")
      cert_b64 = Base.encode64(cert_der)

      {:ok, result} = Vaultx.Sys.AuditHash.calculate("file-audit", cert_b64)
      result.hash #=> "hmac-sha256:a1b2c3d4e5f6..."

  ### Token Accessor Hashing

      # Hash token accessor for audit log correlation
      {:ok, result} = Vaultx.Sys.AuditHash.calculate("syslog-audit", "accessor_12345")

      # This hash can be found in audit logs when the token is used
      result.hash #=> "hmac-sha256:f1e2d3c4b5a6..."

  ## Audit Log Correlation Workflow

  1. Identify Target Value: Determine the plaintext value to search for
  2. Calculate Hash: Use this module to generate the audit hash
  3. Search Audit Logs: Look for the hash value in audit log files
  4. Analyze Results: Correlate hash occurrences with audit events
  5. Security Analysis: Investigate access patterns and compliance

  ## Hash Format

  Audit hashes are returned in the format: `hmac-sha256:<hex-encoded-hash>`

  - Algorithm: HMAC-SHA256
  - Encoding: Hexadecimal
  - Salt: Audit device's internal salt (not exposed)
  - Consistency: Same input always produces same hash for same audit device
  """

  alias Vaultx.Base.{Error, Logger, Telemetry}
  alias Vaultx.Transport.HTTP
  alias Vaultx.Types

  @typedoc """
  Hash calculation result.
  """
  @type hash_result :: %{
          :hash => String.t()
        }

  @doc """
  Calculate hash using an audit device's hash function and salt.

  This function hashes the given input data with the specified audit device's
  hash function and salt. The result can be used to search audit logs for
  the obfuscated form of the input value.

  ## Parameters

  - `audit_path` - The path of the audit device to use for hashing
  - `input` - The input string to hash
  - `opts` - Request options (optional)

  ## Returns

  Returns `{:ok, hash_result()}` with the calculated hash on success,
  or `{:error, Error.t()}` on failure.

  ## Examples

      # Hash a simple string
      {:ok, result} = Vaultx.Sys.AuditHash.calculate("file-audit", "my-secret")
      result.hash #=> "hmac-sha256:08ba35a1b2c3d4e5f6..."

      # Hash a token accessor
      {:ok, result} = Vaultx.Sys.AuditHash.calculate("syslog-audit", "accessor_12345")

      # Hash base64-encoded binary data
      cert_data = Base.encode64(File.read!("cert.der"))
      {:ok, result} = Vaultx.Sys.AuditHash.calculate("file-audit", cert_data)

  ## Important Notes

  - Binary data should be base64-encoded before hashing
  - The same input will always produce the same hash for the same audit device
  - Different audit devices may produce different hashes for the same input
  - Hash calculation uses the audit device's internal salt

  """
  @spec calculate(String.t(), String.t(), Types.options()) ::
          {:ok, hash_result()} | {:error, Error.t()}
  def calculate(audit_path, input, opts \\ []) do
    api_path = "sys/audit-hash/#{audit_path}"

    request_body = %{input: input}

    metadata = %{
      operation: :calculate_audit_hash,
      audit_path: audit_path,
      input_length: String.length(input)
    }

    Logger.debug("Calculating audit hash", metadata)
    Telemetry.operation_start(metadata)

    start_time = System.monotonic_time()

    case HTTP.post(api_path, request_body, opts) do
      {:ok, %{status: 200, body: %{"hash" => hash}}} when is_binary(hash) and hash != "" ->
        duration = System.monotonic_time() - start_time

        result = %{hash: hash}

        hash_prefix =
          if String.length(hash) > 20 do
            String.slice(hash, 0, 20) <> "..."
          else
            hash
          end

        Logger.info(
          "Successfully calculated audit hash",
          Map.merge(metadata, %{hash_prefix: hash_prefix})
        )

        Telemetry.operation_success(duration, metadata)

        {:ok, result}

      {:ok, %{status: 200, body: body}} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:server_error, "Invalid hash response from audit device",
            details: %{body: body}
          )

        Logger.error("Invalid hash response from audit device", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:server_error, "Failed to calculate audit hash: HTTP #{status}",
            details: %{status: status, body: body}
          )

        Logger.error("Failed to calculate audit hash", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Error calculating audit hash", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Calculate hash for multiple inputs using the same audit device.

  This is a convenience function for calculating hashes for multiple values
  using the same audit device, which can be more efficient than individual calls.

  ## Parameters

  - `audit_path` - The path of the audit device to use for hashing
  - `inputs` - List of input strings to hash
  - `opts` - Request options (optional)

  ## Returns

  Returns `{:ok, [hash_result()]}` with all calculated hashes on success,
  or `{:error, Error.t()}` on failure.

  ## Examples

      inputs = ["secret1", "secret2", "token_accessor_123"]
      {:ok, results} = Vaultx.Sys.AuditHash.calculate_batch("file-audit", inputs)

      Enum.each(results, fn result ->
        IO.puts("Hash: \#{result.hash}")
      end)

  """
  @spec calculate_batch(String.t(), [String.t()], Types.options()) ::
          {:ok, [hash_result()]} | {:error, Error.t()}
  def calculate_batch(audit_path, inputs, opts \\ []) when is_list(inputs) do
    metadata = %{
      operation: :calculate_audit_hash_batch,
      audit_path: audit_path,
      input_count: length(inputs)
    }

    Logger.debug("Calculating audit hash batch", metadata)
    Telemetry.operation_start(metadata)

    start_time = System.monotonic_time()

    # Calculate hashes sequentially to avoid overwhelming the server
    results =
      inputs
      |> Enum.reduce_while([], fn input, acc ->
        case calculate(audit_path, input, opts) do
          {:ok, result} -> {:cont, [result | acc]}
          {:error, error} -> {:halt, {:error, error}}
        end
      end)

    case results do
      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Failed to calculate audit hash batch", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      hash_results when is_list(hash_results) ->
        duration = System.monotonic_time() - start_time

        final_results = Enum.reverse(hash_results)

        Logger.info(
          "Successfully calculated audit hash batch",
          Map.put(metadata, :success_count, length(final_results))
        )

        Telemetry.operation_success(duration, metadata)

        {:ok, final_results}
    end
  end

  @doc """
  Validate that an audit device exists and is accessible for hash calculation.

  This function attempts to calculate a hash for a test value to verify that
  the audit device is properly configured and accessible.

  ## Parameters

  - `audit_path` - The path of the audit device to validate
  - `opts` - Request options (optional)

  ## Returns

  Returns `:ok` if the audit device is accessible, or `{:error, Error.t()}` if not.

  ## Examples

      case Vaultx.Sys.AuditHash.validate_audit_device("file-audit") do
        :ok ->
          IO.puts("Audit device is accessible")
        {:error, error} ->
          IO.puts("Audit device error: \#{error.message}")
      end

  """
  @spec validate_audit_device(String.t(), Types.options()) :: :ok | {:error, Error.t()}
  def validate_audit_device(audit_path, opts \\ []) do
    test_input = "vaultx-audit-test-#{System.system_time(:millisecond)}"

    case calculate(audit_path, test_input, opts) do
      {:ok, %{hash: hash}} when is_binary(hash) and hash != "" ->
        :ok

      # This branch is defensive programming for future-proofing. Currently, the calculate/3 function
      # only returns {:ok, %{hash: hash}} or {:error, error}, so this branch is never executed.
      # It exists to handle potential future changes to calculate/3 that might return other success formats.
      # coveralls-ignore-next-line
      {:ok, _} ->
        {:error, Error.new(:server_error, "Invalid hash response from audit device")}

      {:error, error} ->
        {:error, error}
    end
  end
end
