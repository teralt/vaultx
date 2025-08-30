defmodule Vaultx.Sys.Health do
  @moduledoc """
  Comprehensive HashiCorp Vault system health monitoring.

  This module provides enterprise-grade health checking capabilities for Vault
  servers and clusters, supporting all health monitoring scenarios including
  load balancer integration, HA cluster monitoring, and enterprise features.

  ## Health Monitoring Features

  ### Core Health Checks
  - Server Status: Initialization and seal status
  - HA Leadership: Active/standby node detection
  - Performance Standby: Enterprise performance standby monitoring
  - Cluster Health: Multi-node cluster status

  ### Load Balancer Integration
  - Customizable Status Codes: Configure response codes for different states
  - Standby Handling: Flexible standby node status reporting
  - Health Check Endpoints: Optimized for load balancer health checks

  ### Enterprise Features
  - Namespace Support: Multi-tenant health monitoring
  - DR Replication: Disaster recovery cluster status
  - Performance Replication: Performance replication monitoring

  ## HTTP Status Code Reference

  Standard Vault health status codes:
  - `200` - Initialized, unsealed, and active
  - `429` - Unsealed and standby
  - `472` - Disaster recovery secondary (active and standby)
  - `473` - Performance standby
  - `474` - Standby node unable to connect to active node
  - `501` - Not initialized
  - `503` - Sealed
  - `530` - Removed from cluster

  ## API Compliance

  Fully implements HashiCorp Vault Health API:
  - [Health API](https://developer.hashicorp.com/vault/api-docs/system/health)
  - [HA Concepts](https://developer.hashicorp.com/vault/docs/concepts/ha)

  ## Usage Examples

      # Basic health check
      {:ok, health} = Vaultx.Sys.Health.check()
      health.initialized #=> true
      health.sealed #=> false

      # Health check with custom status codes for load balancer
      {:ok, health} = Vaultx.Sys.Health.check([
        standbyok: true,
        perfstandbyok: true
      ])



  ## Load Balancer Integration

  For load balancers that only understand 200-level responses:

      {:ok, health} = Vaultx.Sys.Health.check([
        standbyok: true,        # Return 200 for standby nodes
        perfstandbyok: true,    # Return 200 for performance standby
        activecode: 200,        # Status code for active nodes
        standbycode: 200        # Override standby status code
      ])

  ## Security Considerations

  - Health endpoints are typically unauthenticated for monitoring purposes
  - Seal status information is safe to expose publicly
  - Leader status may reveal cluster topology information
  - Use appropriate network controls to limit access to health endpoints

  """

  alias Vaultx.Base.{Error, Logger, Telemetry}
  alias Vaultx.Transport.HTTP
  alias Vaultx.Types

  @typedoc """
  Health check options.
  """
  @type health_opts :: [
          # Status code customization
          standbyok: boolean(),
          perfstandbyok: boolean(),
          activecode: pos_integer(),
          standbycode: pos_integer(),
          drsecondarycode: pos_integer(),
          haunhealthycode: pos_integer(),
          performancestandbycode: pos_integer(),
          removedcode: pos_integer(),
          sealedcode: pos_integer(),
          uninitcode: pos_integer(),

          # Base options
          timeout: pos_integer(),
          retry_attempts: non_neg_integer(),
          namespace: String.t()
        ]

  @typedoc """
  Health status response structure.
  """
  @type health_status :: %{
          # Core status
          initialized: boolean(),
          sealed: boolean(),
          standby: boolean(),
          performance_standby: boolean(),

          # Server information
          server_time_utc: integer(),
          version: String.t(),

          # Cluster information
          cluster_name: String.t(),
          cluster_id: String.t(),

          # Replication status (Enterprise)
          replication_performance_mode: String.t(),
          replication_dr_mode: String.t(),
          replication_primary_canary_age_ms: integer(),

          # HA information
          ha_connection_healthy: boolean(),
          last_request_forwarding_heartbeat_ms: integer(),
          removed_from_cluster: boolean(),

          # Performance metrics
          clock_skew_ms: integer(),
          echo_duration_ms: integer(),

          # Enterprise features
          enterprise: boolean(),
          license: map() | nil,
          last_wal: integer() | nil
        }

  @doc """
  Check Vault server health status.

  This endpoint returns the health status of Vault. It matches the semantics
  of a Consul HTTP health check and provides a simple way to monitor the
  health of a Vault instance.

  ## Options

  - `:standbyok` - Return active status code for standby nodes (default: false)
  - `:perfstandbyok` - Return active status code for performance standby (default: false)
  - `:activecode` - Status code for active nodes (default: 200)
  - `:standbycode` - Status code for standby nodes (default: 429)

  ## Examples

      # Basic health check
      {:ok, health} = Vaultx.Sys.Health.check()

      # Load balancer friendly check
      {:ok, health} = Vaultx.Sys.Health.check([standbyok: true])

  """
  @spec check(health_opts()) :: Types.result(health_status())
  def check(opts \\ []) do
    start_time = System.monotonic_time()

    metadata = %{
      operation: :health_check,
      module: __MODULE__
    }

    Logger.debug("Checking Vault health status", metadata)
    Telemetry.operation_start(metadata)

    query_params = build_health_query_params(opts)
    path = if query_params == "", do: "sys/health", else: "sys/health?#{query_params}"

    case HTTP.get(path, opts) do
      {:ok, %{status: status, body: body}}
      when status in [200, 429, 472, 473, 474, 501, 503, 530] ->
        duration = System.monotonic_time() - start_time

        health_status = parse_health_response(body)

        Logger.info("Health check completed", Map.put(metadata, :status, status))
        Telemetry.operation_success(duration, Map.put(metadata, :status, status))

        {:ok, health_status}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:unexpected_response, "Unexpected health status: #{status}",
            details: %{status: status, body: body}
          )

        Logger.warning("Unexpected health status", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Health check failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  # Private functions

  defp build_health_query_params(opts) do
    params = []

    params =
      if Keyword.get(opts, :standbyok, false), do: ["standbyok=true" | params], else: params

    params =
      if Keyword.get(opts, :perfstandbyok, false),
        do: ["perfstandbyok=true" | params],
        else: params

    # Custom status codes
    params = add_status_code_param(params, opts, :activecode, "activecode")
    params = add_status_code_param(params, opts, :standbycode, "standbycode")
    params = add_status_code_param(params, opts, :drsecondarycode, "drsecondarycode")
    params = add_status_code_param(params, opts, :haunhealthycode, "haunhealthycode")

    params =
      add_status_code_param(params, opts, :performancestandbycode, "performancestandbycode")

    params = add_status_code_param(params, opts, :removedcode, "removedcode")
    params = add_status_code_param(params, opts, :sealedcode, "sealedcode")
    params = add_status_code_param(params, opts, :uninitcode, "uninitcode")

    params
    |> Enum.reverse()
    |> Enum.join("&")
  end

  defp add_status_code_param(params, opts, key, param_name) do
    case Keyword.get(opts, key) do
      nil -> params
      code when is_integer(code) -> ["#{param_name}=#{code}" | params]
      _ -> params
    end
  end

  defp parse_health_response(body) when is_map(body) do
    %{
      # Core status
      initialized: Map.get(body, "initialized", false),
      sealed: Map.get(body, "sealed", true),
      standby: Map.get(body, "standby", false),
      performance_standby: Map.get(body, "performance_standby", false),

      # Server information
      server_time_utc: Map.get(body, "server_time_utc", 0),
      version: Map.get(body, "version", "unknown"),

      # Cluster information
      cluster_name: Map.get(body, "cluster_name", ""),
      cluster_id: Map.get(body, "cluster_id", ""),

      # Replication status
      replication_performance_mode: Map.get(body, "replication_performance_mode", "disabled"),
      replication_dr_mode: Map.get(body, "replication_dr_mode", "disabled"),
      replication_primary_canary_age_ms: Map.get(body, "replication_primary_canary_age_ms", 0),

      # HA information
      ha_connection_healthy: Map.get(body, "ha_connection_healthy", true),
      last_request_forwarding_heartbeat_ms:
        Map.get(body, "last_request_forwarding_heartbeat_ms", 0),
      removed_from_cluster: Map.get(body, "removed_from_cluster", false),

      # Performance metrics
      clock_skew_ms: Map.get(body, "clock_skew_ms", 0),
      echo_duration_ms: Map.get(body, "echo_duration_ms", 0),

      # Enterprise features
      enterprise: Map.get(body, "enterprise", false),
      license: Map.get(body, "license"),
      last_wal: Map.get(body, "last_wal")
    }
  end
end
