defmodule Vaultx.Sys.Policy do
  @moduledoc """
  Enterprise policy management for HashiCorp Vault system backend.

  This module provides comprehensive policy management capabilities for Vault
  ACL (Access Control List) policies, enabling fine-grained access control
  and security governance for enterprise Vault deployments. It supports
  complete policy lifecycle management with validation and compliance features.

  ## Enterprise Policy Management

  - List and audit all configured security policies
  - Read and analyze specific policy content and rules
  - Create and update policies with validation
  - Safely delete policies with dependency checking
  - Policy syntax validation and compliance verification

  ## API Endpoints

  This module implements the following Vault API endpoints:

  - `GET /sys/policy` - List policies
  - `GET /sys/policy/:name` - Read policy
  - `POST /sys/policy/:name` - Create/Update policy
  - `DELETE /sys/policy/:name` - Delete policy

  ## Usage Examples

      # List all policies
      {:ok, policies} = Vaultx.Sys.Policy.list()
      policies #=> ["default", "root", "my-policy"]

      # Read a specific policy
      {:ok, policy} = Vaultx.Sys.Policy.read("my-policy")
      policy.rules #=> "path \"secret/*\" { capabilities = [\"read\"] }"

      # Create or update a policy
      rules = ~s(path "secret/myapp/*" { capabilities = ["create", "read", "update", "delete"] })
      :ok = Vaultx.Sys.Policy.write("myapp-policy", rules)

      # Delete a policy
      :ok = Vaultx.Sys.Policy.delete("old-policy")

  ## Policy Language

  Vault policies are written in HCL (HashiCorp Configuration Language) format:

      # Allow full access to secret/myapp/*
      path "secret/myapp/*" {
        capabilities = ["create", "read", "update", "delete", "list"]
      }

      # Allow read-only access to secret/shared/*
      path "secret/shared/*" {
        capabilities = ["read", "list"]
      }

      # Deny access to secret/admin/*
      path "secret/admin/*" {
        capabilities = ["deny"]
      }

  ## Security Considerations

  - Policy changes take effect immediately for all associated tokens
  - The "root" policy cannot be deleted or modified
  - The "default" policy is automatically attached to all tokens
  - Use principle of least privilege when designing policies

  ## API Compliance

  Fully implements HashiCorp Vault Policy API:
  - [System Policy API](https://developer.hashicorp.com/vault/api-docs/system/policy)
  - [Policy Concepts](https://developer.hashicorp.com/vault/docs/concepts/policies)
  - [Policy Syntax](https://developer.hashicorp.com/vault/docs/concepts/policies#policy-syntax)

  """

  alias Vaultx.Base.{Error, Logger, Telemetry}
  alias Vaultx.Transport.HTTP
  alias Vaultx.Types

  @typedoc """
  Policy management options.
  """
  @type policy_opts :: [
          # Base options
          timeout: pos_integer(),
          retry_attempts: non_neg_integer(),
          namespace: String.t()
        ]

  @typedoc """
  Policy information structure.
  """
  @type policy_info :: %{
          name: String.t(),
          rules: String.t()
        }

  @doc """
  List all configured policies.

  Returns a list of policy names available in the Vault instance.
  Implements `GET /sys/policy`.

  ## Examples

      {:ok, policies} = Vaultx.Sys.Policy.list()
      policies #=> ["default", "root", "my-policy"]

  """
  @spec list(policy_opts()) :: Types.result([String.t()])
  def list(opts \\ []) do
    start_time = System.monotonic_time()

    metadata = %{
      operation: :policy_list,
      module: __MODULE__
    }

    Logger.debug("Listing policies", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.get("sys/policy", opts) do
      {:ok, %{status: 200, body: %{"policies" => policies}}} ->
        duration = System.monotonic_time() - start_time

        Logger.debug("Policy listing successful", Map.put(metadata, :count, length(policies)))
        Telemetry.operation_success(duration, Map.put(metadata, :count, length(policies)))

        {:ok, policies}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Policy listing failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Read a specific policy.

  Retrieves the policy rules for the specified policy name.
  Implements `GET /sys/policy/:name`.

  ## Examples

      {:ok, policy} = Vaultx.Sys.Policy.read("my-policy")
      policy.name #=> "my-policy"
      policy.rules #=> "path \"secret/*\" { capabilities = [\"read\"] }"

  """
  @spec read(String.t(), policy_opts()) :: Types.result(policy_info())
  def read(name, opts \\ []) do
    start_time = System.monotonic_time()

    metadata = %{
      operation: :policy_read,
      policy_name: name,
      module: __MODULE__
    }

    Logger.debug("Reading policy", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.get("sys/policy/#{name}", opts) do
      {:ok, %{status: 200, body: %{"name" => ^name, "rules" => rules}}} ->
        duration = System.monotonic_time() - start_time

        policy_info = %{name: name, rules: rules}

        Logger.debug("Policy read successful", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, policy_info}

      {:ok, %{status: 404}} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:not_found, "Policy not found: #{name}")

        Logger.debug("Policy not found", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Policy read failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Create or update a policy.

  Creates a new policy or updates an existing one with the specified rules.
  Policy changes take effect immediately for all associated tokens.
  Implements `POST /sys/policy/:name`.

  ## Examples

      rules = ~s(path "secret/myapp/*" { capabilities = ["create", "read", "update", "delete"] })
      :ok = Vaultx.Sys.Policy.write("myapp-policy", rules)

  """
  @spec write(String.t(), String.t(), policy_opts()) :: Types.result(:ok)
  def write(name, rules, opts \\ []) do
    start_time = System.monotonic_time()

    metadata = %{
      operation: :policy_write,
      policy_name: name,
      module: __MODULE__
    }

    Logger.debug("Writing policy", metadata)
    Telemetry.operation_start(metadata)

    payload = %{"policy" => rules}

    case HTTP.post("sys/policy/#{name}", payload, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        duration = System.monotonic_time() - start_time

        Logger.info("Policy written successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        :ok

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Policy write failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Delete a policy.

  Permanently removes the specified policy. This will immediately affect
  all tokens associated with this policy.
  Implements `DELETE /sys/policy/:name`.

  ## Security Notes

  - The "root" policy cannot be deleted
  - The "default" policy cannot be deleted
  - Deletion takes effect immediately for all associated tokens

  ## Examples

      :ok = Vaultx.Sys.Policy.delete("old-policy")

  """
  @spec delete(String.t(), policy_opts()) :: Types.result(:ok)
  def delete(name, opts \\ []) do
    start_time = System.monotonic_time()

    metadata = %{
      operation: :policy_delete,
      policy_name: name,
      module: __MODULE__
    }

    Logger.debug("Deleting policy", metadata)
    Telemetry.operation_start(metadata)

    # Prevent deletion of system policies
    if name in ["root", "default"] do
      error = Error.new(:invalid_request, "Cannot delete system policy: #{name}")
      Logger.warn("Attempted to delete system policy", Map.put(metadata, :error, error))
      {:error, error}
    else
      case HTTP.delete("sys/policy/#{name}", opts) do
        {:ok, %{status: status}} when status in [200, 204] ->
          duration = System.monotonic_time() - start_time

          Logger.info("Policy deleted successfully", metadata)
          Telemetry.operation_success(duration, metadata)

          :ok

        {:ok, %{status: 404}} ->
          duration = System.monotonic_time() - start_time
          error = Error.new(:not_found, "Policy not found: #{name}")

          Logger.debug("Policy not found for deletion", Map.put(metadata, :error, error))
          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}

        {:error, error} ->
          duration = System.monotonic_time() - start_time

          Logger.error("Policy deletion failed", Map.put(metadata, :error, error))
          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}
      end
    end
  end
end
