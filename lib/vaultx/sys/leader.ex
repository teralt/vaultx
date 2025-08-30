defmodule Vaultx.Sys.Leader do
  @moduledoc """
  HashiCorp Vault leader operations.

  This module provides high availability status and leader information for Vault
  clusters. It allows you to check the current leader, HA status, and various
  cluster-related metrics for monitoring and operational purposes.

  ## Leader Features

  ### Core Information
  - HA Status: Whether high availability is enabled
  - Leader Identity: Current leader node information
  - Self Status: Whether the current node is the leader
  - Active Time: When the current leader became active
  - Address Information: Leader's API and cluster addresses

  ### Performance Metrics
  - Performance Standby: Whether node is a performance standby
  - WAL Information: Write-Ahead Log status and indices
  - Raft Metrics: Raft consensus algorithm status (when using Raft storage)
  - Remote WAL: Performance standby WAL synchronization status

  ## Important Notes

  **Unauthenticated Endpoint**
  - No authentication required to check leader status
  - Safe to call from monitoring and health check systems
  - Provides operational visibility without exposing secrets

  **High Availability Context**
  - Information varies based on HA configuration
  - Single-node deployments show limited HA information
  - Cluster topology affects available metrics

  **Performance Standby Information**
  - Performance standby metrics available in Vault Enterprise
  - Shows replication lag and synchronization status
  - Useful for monitoring Enterprise HA deployments

  ## API Compliance

  Fully implements HashiCorp Vault Leader API:
  - [Leader API](https://developer.hashicorp.com/vault/api-docs/system/leader)
  - [Vault High Availability](https://developer.hashicorp.com/vault/docs/concepts/ha)

  ## Usage Examples

  ### Basic Leader Status

      {:ok, status} = Vaultx.Sys.Leader.get_status()

      if status.ha_enabled do
        if status.is_self do
          IO.puts("This node is the leader")
        else
          IO.puts("Leader is at: \#{status.leader_address}")
        end
      else
        IO.puts("HA not enabled")
      end

  ### Monitoring Integration

      case Vaultx.Sys.Leader.get_status() do
        {:ok, status} ->
          if status.ha_enabled and not status.is_self do
            # This is a standby node
            monitor_standby_status(status)
          end
        {:error, _} ->
          send_alert("Cannot reach Vault leader endpoint")
      end

  ### Performance Standby Monitoring

      {:ok, status} = Vaultx.Sys.Leader.get_status()

      if status.performance_standby do
        lag = status.performance_standby_last_remote_wal - status.last_wal
        if lag > 1000 do
          send_alert("Performance standby lag: \#{lag}")
        end
      end

  ### Leader Change Detection

      {:ok, current_leader} = Vaultx.Sys.Leader.get_leader_address()

      if current_leader != previous_leader do
        IO.puts("Leader changed from \#{previous_leader} to \#{current_leader}")
        handle_leader_change(current_leader)
      end

  ## Status Information

  The leader status response includes:

  ### Always Present
  - `ha_enabled`: Whether HA is enabled
  - `is_self`: Whether current node is the leader
  - `leader_address`: API address of the leader
  - `leader_cluster_address`: Cluster address of the leader

  ### When Available
  - `active_time`: When current leader became active
  - `performance_standby`: Whether node is performance standby
  - `performance_standby_last_remote_wal`: Last remote WAL index
  - `last_wal`: Last local WAL index
  - `raft_committed_index`: Raft committed index (Raft storage)
  - `raft_applied_index`: Raft applied index (Raft storage)

  ## Use Cases

  ### Cluster Monitoring
  - Monitor leader election and changes
  - Track cluster health and availability
  - Detect split-brain scenarios
  - Monitor replication lag

  ### Load Balancing
  - Direct write operations to leader
  - Route read operations appropriately
  - Handle leader failover scenarios
  - Implement client-side load balancing

  ### Operational Automation
  - Automate backup operations on leader
  - Coordinate cluster maintenance
  - Implement custom failover logic
  - Monitor performance metrics

  ### Health Checking
  - Verify cluster connectivity
  - Monitor HA functionality
  - Track performance standby status
  - Implement health dashboards
  """

  alias Vaultx.Base.{Error, Logger, Telemetry}
  alias Vaultx.Transport.HTTP
  alias Vaultx.Types

  @typedoc """
  Leader status information.
  """
  @type leader_status :: %{
          :ha_enabled => boolean(),
          :is_self => boolean(),
          :leader_address => String.t(),
          :leader_cluster_address => String.t(),
          optional(:active_time) => String.t(),
          optional(:performance_standby) => boolean(),
          optional(:performance_standby_last_remote_wal) => integer(),
          optional(:last_wal) => integer(),
          optional(:raft_committed_index) => integer(),
          optional(:raft_applied_index) => integer()
        }

  @doc """
  Get the high availability status and current leader.

  This endpoint returns the high availability status and current leader instance
  of Vault.

  ## Parameters

  - `opts` - Request options (optional)

  ## Returns

  Returns `{:ok, leader_status()}` with leader information,
  or `{:error, Error.t()}` on failure.

  ## Examples

      {:ok, status} = Vaultx.Sys.Leader.get_status()

      IO.puts("HA Enabled: \#{status.ha_enabled}")
      IO.puts("Is Leader: \#{status.is_self}")
      IO.puts("Leader Address: \#{status.leader_address}")

      if status.performance_standby do
        IO.puts("Performance Standby: true")
        IO.puts("WAL Lag: \#{status.performance_standby_last_remote_wal - status.last_wal}")
      end

  """
  @spec get_status(Types.options()) :: {:ok, leader_status()} | {:error, Error.t()}
  def get_status(opts \\ []) do
    path = "sys/leader"

    metadata = %{operation: :get_leader_status}
    Logger.debug("Getting leader status", metadata)
    Telemetry.operation_start(metadata)

    start_time = System.monotonic_time()

    case HTTP.get(path, opts) do
      {:ok, %{status: 200, body: body}} ->
        duration = System.monotonic_time() - start_time

        status = parse_leader_status(body)

        Logger.info(
          "Successfully retrieved leader status",
          Map.merge(metadata, %{
            ha_enabled: status.ha_enabled,
            is_self: status.is_self,
            leader_address: status.leader_address
          })
        )

        Telemetry.operation_success(duration, metadata)

        {:ok, status}

      {:ok, %{status: status_code, body: body}} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:server_error, "Failed to get leader status: HTTP #{status_code}",
            details: %{status: status_code, body: body}
          )

        Logger.error("Failed to get leader status", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Error getting leader status", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Check if high availability is enabled.

  This is a convenience function that returns a simple boolean
  indicating whether HA is enabled.

  ## Parameters

  - `opts` - Request options (optional)

  ## Returns

  Returns `{:ok, boolean()}` where true means HA is enabled,
  or `{:error, Error.t()}` on failure.

  ## Examples

      case Vaultx.Sys.Leader.is_ha_enabled?() do
        {:ok, true} -> IO.puts("HA is enabled")
        {:ok, false} -> IO.puts("HA is not enabled")
        {:error, error} -> IO.puts("Error: \#{error.message}")
      end

  """
  @spec is_ha_enabled?(Types.options()) :: {:ok, boolean()} | {:error, Error.t()}
  def is_ha_enabled?(opts \\ []) do
    case get_status(opts) do
      {:ok, status} -> {:ok, status.ha_enabled}
      {:error, error} -> {:error, error}
    end
  end

  @doc """
  Check if the current node is the leader.

  This is a convenience function that returns a simple boolean
  indicating whether the current node is the active leader.

  ## Parameters

  - `opts` - Request options (optional)

  ## Returns

  Returns `{:ok, boolean()}` where true means this node is the leader,
  or `{:error, Error.t()}` on failure.

  ## Examples

      case Vaultx.Sys.Leader.is_leader?() do
        {:ok, true} -> IO.puts("This node is the leader")
        {:ok, false} -> IO.puts("This node is a standby")
        {:error, error} -> IO.puts("Error: \#{error.message}")
      end

  """
  @spec is_leader?(Types.options()) :: {:ok, boolean()} | {:error, Error.t()}
  def is_leader?(opts \\ []) do
    case get_status(opts) do
      {:ok, status} -> {:ok, status.is_self}
      {:error, error} -> {:error, error}
    end
  end

  @doc """
  Get the current leader's address.

  This function returns the API address of the current leader node.

  ## Parameters

  - `opts` - Request options (optional)

  ## Returns

  Returns `{:ok, String.t()}` with the leader's address,
  or `{:error, Error.t()}` on failure.

  ## Examples

      {:ok, leader_address} = Vaultx.Sys.Leader.get_leader_address()
      IO.puts("Leader is at: \#{leader_address}")

  """
  @spec get_leader_address(Types.options()) :: {:ok, String.t()} | {:error, Error.t()}
  def get_leader_address(opts \\ []) do
    case get_status(opts) do
      {:ok, status} -> {:ok, status.leader_address}
      {:error, error} -> {:error, error}
    end
  end

  @doc """
  Get performance standby information.

  This function returns performance standby status and metrics,
  useful for monitoring Enterprise HA deployments.

  ## Parameters

  - `opts` - Request options (optional)

  ## Returns

  Returns `{:ok, performance_info}` with standby information,
  or `{:error, Error.t()}` on failure.

  ## Examples

      {:ok, perf_info} = Vaultx.Sys.Leader.get_performance_standby_info()

      if perf_info.is_performance_standby do
        IO.puts("WAL lag: \#{perf_info.wal_lag}")
      end

  """
  @spec get_performance_standby_info(Types.options()) ::
          {:ok, %{is_performance_standby: boolean(), wal_lag: integer()}}
          | {:error, Error.t()}
  def get_performance_standby_info(opts \\ []) do
    case get_status(opts) do
      {:ok, status} ->
        is_performance_standby = Map.get(status, :performance_standby, false)

        wal_lag =
          if is_performance_standby do
            remote_wal = Map.get(status, :performance_standby_last_remote_wal, 0)
            local_wal = Map.get(status, :last_wal, 0)
            max(0, remote_wal - local_wal)
          else
            0
          end

        performance_info = %{
          is_performance_standby: is_performance_standby,
          wal_lag: wal_lag
        }

        {:ok, performance_info}

      {:error, error} ->
        {:error, error}
    end
  end

  @doc """
  Get Raft consensus information.

  This function returns Raft-specific metrics when Vault is using
  Raft as the storage backend.

  ## Parameters

  - `opts` - Request options (optional)

  ## Returns

  Returns `{:ok, raft_info}` with Raft metrics,
  or `{:error, Error.t()}` on failure.

  ## Examples

      {:ok, raft_info} = Vaultx.Sys.Leader.get_raft_info()

      if raft_info.has_raft_info do
        IO.puts("Committed: \#{raft_info.committed_index}")
        IO.puts("Applied: \#{raft_info.applied_index}")
      end

  """
  @spec get_raft_info(Types.options()) ::
          {:ok, %{has_raft_info: boolean(), committed_index: integer(), applied_index: integer()}}
          | {:error, Error.t()}
  def get_raft_info(opts \\ []) do
    case get_status(opts) do
      {:ok, status} ->
        committed_index = Map.get(status, :raft_committed_index)
        applied_index = Map.get(status, :raft_applied_index)

        raft_info = %{
          has_raft_info: committed_index != nil and applied_index != nil,
          committed_index: committed_index || 0,
          applied_index: applied_index || 0
        }

        {:ok, raft_info}

      {:error, error} ->
        {:error, error}
    end
  end

  # Private helper functions

  defp parse_leader_status(body) when is_map(body) do
    %{
      ha_enabled: body["ha_enabled"],
      is_self: body["is_self"],
      leader_address: body["leader_address"] || "",
      leader_cluster_address: body["leader_cluster_address"] || ""
    }
    |> maybe_add_optional_fields(body)
  end

  defp parse_leader_status(_body) do
    # Handle invalid/malformed response body
    %{
      ha_enabled: false,
      is_self: false,
      leader_address: "",
      leader_cluster_address: ""
    }
  end

  defp maybe_add_optional_fields(status, body) do
    status
    |> maybe_put(:active_time, body["active_time"])
    |> maybe_put(:performance_standby, body["performance_standby"])
    |> maybe_put(
      :performance_standby_last_remote_wal,
      body["performance_standby_last_remote_wal"]
    )
    |> maybe_put(:last_wal, body["last_wal"])
    |> maybe_put(:raft_committed_index, body["raft_committed_index"])
    |> maybe_put(:raft_applied_index, body["raft_applied_index"])
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)
end
