defmodule Vaultx.Sys.Remount do
  @moduledoc """
  HashiCorp Vault mount migration and remount operations.

  This module provides comprehensive mount migration capabilities for Vault,
  allowing you to move mounted backends (both secrets engines and auth methods)
  to new mount points with full migration tracking and status monitoring.

  ## Mount Migration Features

  ### Core Operations
  - Move Backend: Relocate mounted backends to new paths
  - Migration Tracking: Monitor migration progress with unique IDs
  - Status Monitoring: Real-time migration status updates
  - Cross-Namespace Support: Move mounts across Vault namespaces

  ### Migration Types
  - Secrets Engine Migration: Move KV, database, and other secrets engines
  - Auth Method Migration: Relocate authentication backends
  - Cross-Namespace Migration: Move mounts between different namespaces
  - Within-Namespace Migration: Rename mounts within the same namespace

  ### Enterprise Features
  - Namespace Support: Full multi-tenant migration capabilities
  - Migration Auditing: Complete audit trail of mount movements
  - Rollback Support: Migration status tracking for recovery operations

  ## Important Notes

  Security Requirements
  - Requires both `sudo` and `update` capabilities to `sys/remount`
  - Mount migration revokes ALL leases for secrets engines
  - Mount migration revokes ALL tokens for auth methods

  Impact Considerations
  - All existing leases/tokens are revoked during migration
  - Applications must be updated to use new mount paths
  - Migration is irreversible once completed

  ## API Compliance

  Fully implements HashiCorp Vault Remount API:
  - [Remount API](https://developer.hashicorp.com/vault/api-docs/system/remount)
  - [Mount Migration](https://developer.hashicorp.com/vault/docs/concepts/mount-migration)

  ## Usage Examples

  ### Basic Mount Migration

      # Move a secrets engine
      {:ok, %{migration_id: id}} = Vaultx.Sys.Remount.move("secret", "new-secret")

      # Monitor migration progress
      {:ok, status} = Vaultx.Sys.Remount.status(id)
      status.migration_info.status #=> "in-progress" | "success" | "failure"

  ### Cross-Namespace Migration

      # Move mount between namespaces
      {:ok, %{migration_id: id}} = Vaultx.Sys.Remount.move(
        "ns1/ns2/secret",
        "ns1/ns3/new-secret"
      )

  ### Auth Method Migration

      # Move auth method
      {:ok, %{migration_id: id}} = Vaultx.Sys.Remount.move(
        "auth/approle",
        "auth/new-approle"
      )

  ### Migration Status Monitoring

      # Check migration status
      {:ok, status} = Vaultx.Sys.Remount.status("ef3ba21c-8be8-4e5f-8d00-cb46a532c665")

      case status.migration_info.status do
        "success" -> IO.puts("Migration completed successfully")
        "in-progress" -> IO.puts("Migration still running...")
        "failure" -> IO.puts("Migration failed")
      end

  ## Migration Workflow

  1. Initiate Migration: Call `move/3` with source and target paths
  2. Receive Migration ID: Vault returns a unique migration identifier
  3. Monitor Progress: Use `status/2` to track migration progress
  4. Handle Completion: Process success/failure based on final status
  5. Update Applications: Modify client configurations for new paths
  """

  alias Vaultx.Base.{Error, Logger, Telemetry}
  alias Vaultx.Transport.HTTP
  alias Vaultx.Types

  @typedoc """
  Migration information structure.
  """
  @type migration_info :: %{
          :source_mount => String.t(),
          :target_mount => String.t(),
          :status => String.t()
        }

  @typedoc """
  Migration status response.
  """
  @type migration_status :: %{
          :migration_id => String.t(),
          :migration_info => migration_info()
        }

  @typedoc """
  Migration initiation response.
  """
  @type migration_response :: %{
          :migration_id => String.t()
        }

  @doc """
  Move a mounted backend to a new mount point.

  This operation moves an already-mounted backend (secrets engine or auth method)
  to a new mount point. The operation works for both secrets engines and auth methods,
  and supports cross-namespace migrations in Vault Enterprise.

  ## Parameters

  - `from_path` - The current mount path to move from
  - `to_path` - The new destination mount path
  - `opts` - Request options (optional)

  ## Returns

  Returns `{:ok, migration_response()}` with a migration ID on success,
  or `{:error, Error.t()}` on failure.

  ## Examples

      # Move secrets engine within namespace
      {:ok, %{migration_id: id}} = Vaultx.Sys.Remount.move("secret", "new-secret")

      # Move auth method
      {:ok, %{migration_id: id}} = Vaultx.Sys.Remount.move(
        "auth/approle",
        "auth/new-approle"
      )

      # Cross-namespace migration (Enterprise)
      {:ok, %{migration_id: id}} = Vaultx.Sys.Remount.move(
        "ns1/ns2/secret",
        "ns1/ns3/new-secret"
      )

  ## Important Notes

  - All existing leases (for secrets engines) or tokens (for auth methods) are revoked
  - The operation requires both `sudo` and `update` capabilities
  - Migration is tracked via the returned migration ID
  - Use `status/2` to monitor migration progress

  """
  @spec move(String.t(), String.t(), Types.options()) ::
          {:ok, migration_response()} | {:error, Error.t()}
  def move(from_path, to_path, opts \\ []) do
    path = "sys/remount"

    request_body = %{
      from: from_path,
      to: to_path
    }

    metadata = %{
      operation: :remount,
      from_path: from_path,
      to_path: to_path
    }

    Logger.debug("Initiating mount migration", metadata)
    Telemetry.operation_start(metadata)

    start_time = System.monotonic_time()

    case HTTP.post(path, request_body, opts) do
      {:ok, %{status: status, body: %{"migration_id" => migration_id}}}
      when status in [200, 204] ->
        duration = System.monotonic_time() - start_time

        response = %{migration_id: migration_id}

        Logger.info(
          "Successfully initiated mount migration",
          Map.put(metadata, :migration_id, migration_id)
        )

        Telemetry.operation_success(duration, metadata)

        {:ok, response}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:server_error, "Failed to initiate mount migration: HTTP #{status}",
            details: %{status: status, body: body}
          )

        Logger.error("Failed to initiate mount migration", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Error initiating mount migration", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Monitor the status of a mount migration operation.

  This endpoint monitors the status of a mount migration using the migration ID
  returned from the `move/3` operation. The response contains the migration ID,
  source and target mounts, and a status field indicating the current state.

  ## Parameters

  - `migration_id` - The unique migration identifier from `move/3`
  - `opts` - Request options (optional)

  ## Returns

  Returns `{:ok, migration_status()}` with detailed migration information,
  or `{:error, Error.t()}` on failure.

  ## Status Values

  - `"in-progress"` - Migration is currently running
  - `"success"` - Migration completed successfully
  - `"failure"` - Migration failed

  ## Examples

      # Check migration status
      {:ok, status} = Vaultx.Sys.Remount.status("ef3ba21c-8be8-4e5f-8d00-cb46a532c665")

      status.migration_id #=> "ef3ba21c-8be8-4e5f-8d00-cb46a532c665"
      status.migration_info.source_mount #=> "secret"
      status.migration_info.target_mount #=> "new-secret"
      status.migration_info.status #=> "success"

      # Handle different status values
      case status.migration_info.status do
        "success" ->
          IO.puts("Migration completed successfully")
        "in-progress" ->
          IO.puts("Migration still running, check again later")
        "failure" ->
          IO.puts("Migration failed, check Vault logs")
      end

  """
  @spec status(String.t(), Types.options()) ::
          {:ok, migration_status()} | {:error, Error.t()}
  def status(migration_id, opts \\ []) do
    path = "sys/remount/status/#{migration_id}"

    metadata = %{
      operation: :remount_status,
      migration_id: migration_id
    }

    Logger.debug("Checking migration status", metadata)
    Telemetry.operation_start(metadata)

    start_time = System.monotonic_time()

    case HTTP.get(path, opts) do
      {:ok, %{status: 200, body: response}} ->
        duration = System.monotonic_time() - start_time

        migration_status = parse_migration_status(response)

        Logger.info(
          "Successfully retrieved migration status",
          Map.merge(metadata, %{
            status: migration_status.migration_info.status,
            source_mount: migration_status.migration_info.source_mount,
            target_mount: migration_status.migration_info.target_mount
          })
        )

        Telemetry.operation_success(duration, metadata)

        {:ok, migration_status}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:server_error, "Failed to get migration status: HTTP #{status}",
            details: %{status: status, body: body}
          )

        Logger.error("Failed to get migration status", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Error getting migration status", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  # Private helper functions

  defp parse_migration_status(response) do
    migration_info = response["migration_info"]

    %{
      migration_id: response["migration_id"],
      migration_info: %{
        source_mount: migration_info["source_mount"],
        target_mount: migration_info["target_mount"],
        status: migration_info["status"]
      }
    }
  end
end
