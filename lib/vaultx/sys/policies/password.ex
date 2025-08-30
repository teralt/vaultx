defmodule Vaultx.Sys.Policies.Password do
  @moduledoc """
  Comprehensive password policy management for HashiCorp Vault system backend.

  This module provides enterprise-grade password policy management capabilities for Vault,
  enabling fine-grained control over password generation requirements for secrets engines
  that support password policies. Password policies define rules for generating secure
  passwords with specific character sets, lengths, and complexity requirements.

  ## Password Policy Features

  ### Policy Definition
  - HCL-based policy syntax for password generation rules
  - Character set specifications (uppercase, lowercase, digits, symbols)
  - Length requirements and constraints
  - Rule-based password complexity validation
  - Custom character exclusion and inclusion rules

  ### Policy Management
  - Create and update password policies
  - Read existing policy configurations
  - List all configured password policies
  - Delete unused password policies
  - Generate test passwords from policies

  ### Integration Support
  - Compatible with secrets engines that support password policies
  - Automatic policy validation before saving
  - Performance optimization for password generation
  - Enterprise-grade security and compliance features

  ## API Compliance

  Fully implements HashiCorp Vault Password Policies API:
  - [Password Policies API](https://developer.hashicorp.com/vault/api-docs/system/policies-password)
  - [Password Policy Concepts](https://developer.hashicorp.com/vault/docs/concepts/password-policies)
  - [Password Policy Syntax](https://developer.hashicorp.com/vault/docs/concepts/password-policies#password-policy-syntax)

  ## Usage Examples

      # Create a password policy
      policy = ~s(
        length = 20
        rule "charset" {
          charset = "abcdefghijklmnopqrstuvwxyz"
          min-chars = 1
        }
        rule "charset" {
          charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
          min-chars = 1
        }
        rule "charset" {
          charset = "0123456789"
          min-chars = 1
        }
      )
      :ok = Vaultx.Sys.Policies.Password.write("strong-policy", policy)

      # List all password policies
      {:ok, policies} = Vaultx.Sys.Policies.Password.list()
      policies #=> ["strong-policy", "basic-policy"]

      # Read a specific policy
      {:ok, policy_info} = Vaultx.Sys.Policies.Password.read("strong-policy")
      policy_info.policy #=> "length = 20\\nrule \"charset\" { ... }"

      # Generate a password from a policy
      {:ok, password} = Vaultx.Sys.Policies.Password.generate("strong-policy")
      password #=> "Kj8mN2pQ9rT5vW3xY7zA"

      # Delete a policy
      :ok = Vaultx.Sys.Policies.Password.delete("old-policy")

  ## Password Policy Syntax Examples

  ### Basic Length Policy
      length = 16

  ### Character Set Rules
      length = 20
      rule "charset" {
        charset = "abcdefghijklmnopqrstuvwxyz"
        min-chars = 3
      }
      rule "charset" {
        charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        min-chars = 2
      }
      rule "charset" {
        charset = "0123456789"
        min-chars = 2
      }
      rule "charset" {
        charset = "!@#$%^&*"
        min-chars = 1
      }

  ### Advanced Rules with Exclusions
      length = 24
      rule "charset" {
        charset = "abcdefghijklmnopqrstuvwxyz"
        min-chars = 5
      }
      rule "charset" {
        charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        min-chars = 5
      }
      rule "charset" {
        charset = "0123456789"
        min-chars = 3
      }
      rule "charset" {
        charset = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        min-chars = 2
      }

  ## Security Considerations

  - Password policies are validated before being saved
  - Vault tests policy generation performance during creation
  - Overly restrictive policies may cause performance issues
  - Use reasonable character set sizes and length requirements
  - Test policies thoroughly before production deployment
  - Monitor password generation performance in production

  ## Compatibility

  Password policies are supported by the following secrets engines:
  - Active Directory secrets engine
  - LDAP secrets engine
  - Database secrets engine (some plugins)
  - Custom secrets engines with password policy support

  """

  alias Vaultx.Base.{Error, Logger, Telemetry}
  alias Vaultx.Transport.HTTP
  alias Vaultx.Types

  @typedoc """
  Password policy management options.
  """
  @type password_policy_opts :: [
          # Base options
          timeout: pos_integer(),
          retry_attempts: non_neg_integer(),
          namespace: String.t()
        ]

  @typedoc """
  Password policy information structure.
  """
  @type password_policy_info :: %{
          policy: String.t()
        }

  @typedoc """
  Generated password response structure.
  """
  @type password_generation_result :: %{
          password: String.t()
        }

  @doc """
  Create or update a password policy.

  Creates a new password policy or updates an existing one with the specified rules.
  Prior to saving, Vault will attempt to generate passwords from the policy to validate
  it and ensure it's not overly restrictive.
  Implements `POST /sys/policies/password/:name`.

  ## Parameters

  - `name`: The name of the password policy
  - `policy`: The HCL password policy document

  ## Examples

      policy = ~s(
        length = 20
        rule "charset" {
          charset = "abcdefghijklmnopqrstuvwxyz"
          min-chars = 1
        }
        rule "charset" {
          charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
          min-chars = 1
        }
      )
      :ok = Vaultx.Sys.Policies.Password.write("my-policy", policy)

  """
  @spec write(String.t(), String.t(), password_policy_opts()) :: Types.result(:ok)
  def write(name, policy, opts \\ []) do
    start_time = System.monotonic_time()

    metadata = %{
      operation: :write_password_policy,
      policy_name: name,
      module: __MODULE__
    }

    Logger.debug("Writing password policy", metadata)
    Telemetry.operation_start(metadata)

    payload = %{"policy" => policy}

    case HTTP.post("sys/policies/password/#{name}", payload, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        duration = System.monotonic_time() - start_time

        Logger.info("Password policy written successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        :ok

      {:ok, %{status: status, body: body}} when status >= 400 ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.error("Password policy write failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Password policy write failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  List all configured password policies.

  Returns a list of password policy names available in the Vault instance.
  Implements `LIST /sys/policies/password` and `GET /sys/policies/password?list=true`.

  ## Examples

      {:ok, policies} = Vaultx.Sys.Policies.Password.list()
      policies #=> ["my-policy", "strong-policy"]

  """
  @spec list(password_policy_opts()) :: Types.result([String.t()])
  def list(opts \\ []) do
    start_time = System.monotonic_time()

    metadata = %{
      operation: :list_password_policies,
      module: __MODULE__
    }

    Logger.debug("Listing password policies", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.request(:list, "sys/policies/password", nil, [], opts) do
      {:ok, %{status: 200, body: %{"data" => %{"keys" => policies}}}} ->
        duration = System.monotonic_time() - start_time

        Logger.debug(
          "Password policy listing successful",
          Map.put(metadata, :count, length(policies))
        )

        Telemetry.operation_success(duration, Map.put(metadata, :count, length(policies)))

        {:ok, policies}

      {:ok, %{status: 200, body: %{"keys" => policies}}} ->
        duration = System.monotonic_time() - start_time

        Logger.debug(
          "Password policy listing successful",
          Map.put(metadata, :count, length(policies))
        )

        Telemetry.operation_success(duration, Map.put(metadata, :count, length(policies)))

        {:ok, policies}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Password policy listing failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Read a specific password policy.

  Retrieves the policy rules for the specified password policy name.
  Implements `GET /sys/policies/password/:name`.

  ## Examples

      {:ok, policy_info} = Vaultx.Sys.Policies.Password.read("my-policy")
      policy_info.policy #=> "length = 20\\nrule \"charset\" { ... }"

  """
  @spec read(String.t(), password_policy_opts()) :: Types.result(password_policy_info())
  def read(name, opts \\ []) do
    start_time = System.monotonic_time()

    metadata = %{
      operation: :read_password_policy,
      policy_name: name,
      module: __MODULE__
    }

    Logger.debug("Reading password policy", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.get("sys/policies/password/#{name}", opts) do
      {:ok, %{status: 200, body: %{"policy" => policy}}} ->
        duration = System.monotonic_time() - start_time

        policy_info = %{policy: policy}

        Logger.debug("Password policy read successful", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, policy_info}

      {:ok, %{status: 404}} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:not_found, "Password policy not found: #{name}")

        Logger.debug("Password policy not found", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Password policy read failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Delete a password policy.

  Permanently removes the specified password policy. This does not check if any
  secrets engines are using it prior to deletion, so ensure that any engines
  utilizing this password policy are changed to a different policy or to their
  default behavior.
  Implements `DELETE /sys/policies/password/:name`.

  ## Examples

      :ok = Vaultx.Sys.Policies.Password.delete("old-policy")

  """
  @spec delete(String.t(), password_policy_opts()) :: Types.result(:ok)
  def delete(name, opts \\ []) do
    start_time = System.monotonic_time()

    metadata = %{
      operation: :delete_password_policy,
      policy_name: name,
      module: __MODULE__
    }

    Logger.debug("Deleting password policy", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.delete("sys/policies/password/#{name}", opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        duration = System.monotonic_time() - start_time

        Logger.info("Password policy deleted successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        :ok

      {:ok, %{status: 404}} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:not_found, "Password policy not found: #{name}")

        Logger.debug("Password policy not found for deletion", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Password policy deletion failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Generate a password from a password policy.

  Generates a password using the specified existing password policy.
  This is useful for testing password policies and generating passwords
  programmatically using the defined rules.
  Implements `GET /sys/policies/password/:name/generate`.

  ## Examples

      {:ok, result} = Vaultx.Sys.Policies.Password.generate("my-policy")
      result.password #=> "Kj8mN2pQ9rT5vW3xY7zA"

  """
  @spec generate(String.t(), password_policy_opts()) :: Types.result(password_generation_result())
  def generate(name, opts \\ []) do
    start_time = System.monotonic_time()

    metadata = %{
      operation: :generate_password,
      policy_name: name,
      module: __MODULE__
    }

    Logger.debug("Generating password from policy", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.get("sys/policies/password/#{name}/generate", opts) do
      {:ok, %{status: 200, body: %{"password" => password}}} ->
        duration = System.monotonic_time() - start_time

        result = %{password: password}

        Logger.debug("Password generation successful", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, result}

      {:ok, %{status: 404}} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:not_found, "Password policy not found: #{name}")

        Logger.debug("Password policy not found for generation", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:ok, %{status: status, body: body}} when status >= 400 ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.error("Password generation failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Password generation failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end
end
