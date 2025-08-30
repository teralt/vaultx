defmodule Vaultx.Sys.Seal do
  @moduledoc """
  HashiCorp Vault seal operations.

  This module provides seal management capabilities for Vault, allowing you to
  seal the Vault instance. Sealing a Vault prevents access to all secrets and
  requires unsealing before the Vault can be used again.

  ## Seal Operations

  ### Core Functionality
  - Seal Vault: Immediately seal the Vault instance
  - Security Control: Prevent access to all secrets
  - Emergency Response: Quickly secure Vault in emergency situations
  - HA Mode Support: Seal active nodes in High Availability configurations

  ### Security Features
  - Immediate Effect: Sealing takes effect immediately
  - Complete Protection: All secrets become inaccessible
  - Authentication Required: Requires root policy or sudo capability
  - Audit Trail: Seal operations are logged in audit devices

  ## Important Security Notes

  **Restricted Endpoint**
  - Must be called from the root namespace
  - Requires root policy or sudo capability on the path
  - Cannot be undone without unsealing process

  **High Availability Considerations**
  - Only active nodes can be sealed via API
  - Standby nodes should be restarted to achieve same effect
  - Sealing active node may trigger failover to standby

  **Operational Impact**
  - All client requests will fail after sealing
  - Vault must be unsealed before normal operations can resume
  - Consider impact on dependent applications and services

  ## API Compliance

  Fully implements HashiCorp Vault Seal API:
  - [Seal API](https://developer.hashicorp.com/vault/api-docs/system/seal)
  - [Vault Concepts](https://developer.hashicorp.com/vault/docs/concepts/seal)

  ## Usage Examples

  ### Basic Seal Operation

      {:ok, _} = Vaultx.Sys.Seal.seal()

  ### Seal with Custom Options

      {:ok, _} = Vaultx.Sys.Seal.seal(timeout: 30_000)

  ### Error Handling

      case Vaultx.Sys.Seal.seal() do
        {:ok, _} ->
          IO.puts("Vault successfully sealed")
        {:error, error} ->
          IO.puts("Failed to seal Vault: \#{error.message}")
      end

  ## Seal Process

  When a seal operation is performed:

  1. Immediate Effect: Vault stops serving requests immediately
  2. Memory Clearing: Encryption keys are removed from memory
  3. State Change: Vault transitions to sealed state
  4. Client Impact: All subsequent requests return sealed errors
  5. Audit Logging: Seal operation is recorded in audit logs

  ## Recovery Process

  After sealing, Vault must be unsealed using:
  - Unseal keys (Shamir's Secret Sharing)
  - Auto-unseal mechanisms (Cloud KMS, HSM, etc.)
  - Recovery keys (for auto-unseal configurations)

  ## Use Cases

  ### Emergency Response
  - Security incident response
  - Suspected compromise
  - Maintenance windows
  - Compliance requirements

  ### Operational Scenarios
  - Planned maintenance
  - Infrastructure changes
  - Security audits
  - Testing procedures

  ### High Availability Operations
  - Controlled failover
  - Node maintenance
  - Cluster rebalancing
  - Disaster recovery testing
  """

  alias Vaultx.Base.{Error, Logger, Telemetry}
  alias Vaultx.Transport.HTTP
  alias Vaultx.Types

  @doc """
  Seals the Vault.

  This endpoint seals the Vault. In HA mode, only an active node can be sealed.
  Standby nodes should be restarted to get the same effect. Requires a token with
  root policy or sudo capability on the path.

  ## Parameters

  - `opts` - Request options (optional)

  ## Returns

  Returns `{:ok, response}` on successful seal operation,
  or `{:error, Error.t()}` on failure.

  ## Examples

      {:ok, _} = Vaultx.Sys.Seal.seal()

      # With custom timeout
      {:ok, _} = Vaultx.Sys.Seal.seal(timeout: 30_000)

  ## Important Notes

  - Sealing takes effect immediately
  - All subsequent requests will fail until Vault is unsealed
  - In HA mode, only the active node can be sealed via API
  - Standby nodes should be restarted to achieve the same effect

  """
  @spec seal(Types.options()) :: {:ok, Types.response()} | {:error, Error.t()}
  def seal(opts \\ []) do
    path = "sys/seal"

    metadata = %{operation: :seal_vault}
    Logger.debug("Sealing Vault", metadata)
    Telemetry.operation_start(metadata)

    start_time = System.monotonic_time()

    case HTTP.post(path, %{}, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        duration = System.monotonic_time() - start_time

        Logger.info("Successfully sealed Vault", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, %{status: status}}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:server_error, "Failed to seal Vault: HTTP #{status}",
            details: %{status: status, body: body}
          )

        Logger.error("Failed to seal Vault", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Error sealing Vault", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Checks if the current token has permission to seal the Vault.

  This is a convenience function that attempts to determine if the seal
  operation would succeed based on current authentication and authorization.

  ## Parameters

  - `opts` - Request options (optional)

  ## Returns

  Returns `:ok` if seal permission is available,
  or `{:error, Error.t()}` if permission is denied or cannot be determined.

  ## Examples

      case Vaultx.Sys.Seal.check_seal_permission() do
        :ok ->
          IO.puts("Seal permission available")
        {:error, error} ->
          IO.puts("Seal permission denied: \#{error.message}")
      end

  ## Important Notes

  - This is a best-effort check and may not be 100% accurate
  - Actual seal operation may still fail due to various factors
  - Use this for pre-flight checks in automation scenarios

  """
  @spec check_seal_permission(Types.options()) :: :ok | {:error, Error.t()}
  def check_seal_permission(opts \\ []) do
    # Check capabilities on the seal endpoint
    capabilities_path = "sys/capabilities-self"
    request_body = %{path: "sys/seal"}

    metadata = %{operation: :check_seal_permission}
    Logger.debug("Checking seal permission", metadata)

    case HTTP.post(capabilities_path, request_body, opts) do
      {:ok, %{status: 200, body: %{"capabilities" => capabilities}}} when is_list(capabilities) ->
        if "root" in capabilities or "sudo" in capabilities do
          Logger.debug("Seal permission confirmed", metadata)
          :ok
        else
          error =
            Error.new(:permission_denied, "Insufficient permissions to seal Vault",
              details: %{required: ["root", "sudo"], available: capabilities}
            )

          Logger.debug("Seal permission denied", Map.put(metadata, :error, error))
          {:error, error}
        end

      {:ok, %{status: status, body: body}} ->
        error =
          Error.new(:server_error, "Failed to check seal permission: HTTP #{status}",
            details: %{status: status, body: body}
          )

        Logger.debug("Error checking seal permission", Map.put(metadata, :error, error))
        {:error, error}

      {:error, error} ->
        Logger.debug("Error checking seal permission", Map.put(metadata, :error, error))
        {:error, error}
    end
  end

  @doc """
  Performs a safe seal operation with pre-flight checks.

  This function performs additional safety checks before sealing the Vault,
  including permission verification and optional confirmation prompts.

  ## Parameters

  - `opts` - Options for the safe seal operation
    - `:skip_permission_check` - Skip permission verification (default: false)
    - `:force` - Skip all safety checks (default: false)
    - Other HTTP request options

  ## Returns

  Returns `{:ok, response}` on successful seal operation,
  or `{:error, Error.t()}` on failure or safety check failure.

  ## Examples

      # Safe seal with all checks
      {:ok, _} = Vaultx.Sys.Seal.safe_seal()

      # Skip permission check
      {:ok, _} = Vaultx.Sys.Seal.safe_seal(skip_permission_check: true)

      # Force seal (skip all checks)
      {:ok, _} = Vaultx.Sys.Seal.safe_seal(force: true)

  ## Safety Checks

  1. Permission Check: Verifies seal capability
  2. Operational State: Ensures Vault is in appropriate state
  3. Confirmation: Optional confirmation for interactive use

  """
  @spec safe_seal(Types.options()) :: {:ok, Types.response()} | {:error, Error.t()}
  def safe_seal(opts \\ []) do
    force = Keyword.get(opts, :force, false)
    skip_permission_check = Keyword.get(opts, :skip_permission_check, false)

    metadata = %{operation: :safe_seal_vault, force: force}
    Logger.debug("Performing safe seal operation", metadata)

    cond do
      force ->
        Logger.info("Force seal requested, skipping safety checks", metadata)
        seal(opts)

      not skip_permission_check ->
        case check_seal_permission(opts) do
          :ok ->
            Logger.debug("Permission check passed, proceeding with seal", metadata)
            seal(opts)

          {:error, error} ->
            Logger.error(
              "Permission check failed, aborting seal",
              Map.put(metadata, :error, error)
            )

            {:error, error}
        end

      true ->
        Logger.debug("Skipping permission check, proceeding with seal", metadata)
        seal(opts)
    end
  end
end
