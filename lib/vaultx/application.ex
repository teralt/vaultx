defmodule Vaultx.Application do
  @moduledoc """
  OTP Application for VaultX HashiCorp Vault client.

  This application manages the lifecycle of VaultX infrastructure components
  with a focus on simplicity, reliability, and fast startup.

  ## Architecture

  - Core Components: HTTP connection pool (required)
  - Optional Components: Cache, token renewal, rate limiting, hot reload
  - Fault Tolerance: Optional components can fail without affecting core functionality
  - Fast Startup: Minimal validation during startup, comprehensive analysis on demand

  ## Startup Process

  1. Load configuration with basic validation
  2. Start HTTP connection pool
  3. Start optional components based on configuration
  4. Setup telemetry if enabled

  """

  use Application

  alias Vaultx.Base.{Config, Logger}

  @doc false
  def start(_type, _args) do
    Logger.info("[Vaultx] Starting application")

    with {:ok, config} <- load_config(),
         {:ok, children} <- build_children(config),
         {:ok, supervisor_pid} <- start_supervisor(children) do
      setup_telemetry_if_enabled()
      log_startup_success(children)
      {:ok, supervisor_pid}
    else
      # coveralls-ignore-start
      # This error path requires complex mocking of Config.get/0 or Supervisor.start_link/2
      # to trigger failures, which would make tests brittle and environment-dependent
      {:error, reason} = error ->
        Logger.error("[Vaultx] Application startup failed", error: reason)
        error
        # coveralls-ignore-stop
    end
  end

  @doc false
  def stop(_state) do
    Logger.info("[Vaultx] Stopping application")
    cleanup_telemetry_if_enabled()
    :ok
  end

  @doc "Returns the current version of VaultX."
  @spec version() :: String.t()
  def version do
    Application.spec(:vaultx, :vsn) |> to_string()
  end

  @doc "Returns a summary of the current configuration."
  @spec config_summary() :: map()
  def config_summary do
    config = Config.get()

    %{
      url: config.url,
      timeout: config.timeout,
      ssl_verify: config.ssl_verify,
      features_enabled: Config.enabled_features()
    }
  end

  # ============================================================================
  # Private Functions - Startup
  # ============================================================================

  defp load_config do
    try do
      # Set startup context to avoid complex analysis during boot
      Process.put(:vaultx_startup_context, :application_startup)

      config = Config.get()
      Logger.info("[Vaultx] Configuration loaded", url: config.url)
      {:ok, config}
    rescue
      # coveralls-ignore-start
      # This error path is difficult to test without mocking Config.get/0
      # and is primarily for defensive programming
      error ->
        Logger.error("[Vaultx] Failed to load configuration", error: Exception.message(error))
        {:error, {:config_load_failed, error}}
        # coveralls-ignore-stop
    end
  end

  defp build_children(config) do
    try do
      children = [
        # Core component - HTTP pool (required)
        build_finch_spec(config)
        # Optional components
        | build_optional_components(config)
      ]

      Logger.debug("[Vaultx] Built #{length(children)} child specifications")
      {:ok, children}
    rescue
      # coveralls-ignore-start
      # This error path is difficult to test without complex mocking
      # and is primarily for defensive programming
      error ->
        Logger.error("[Vaultx] Failed to build child specifications",
          error: Exception.message(error)
        )

        {:error, {:child_spec_failed, error}}
        # coveralls-ignore-stop
    end
  end

  defp start_supervisor(children) do
    opts = [strategy: :one_for_one, name: Vaultx.Supervisor]

    case Supervisor.start_link(children, opts) do
      {:ok, pid} = success ->
        Logger.debug("[Vaultx] Supervisor started", pid: inspect(pid))
        success

      # coveralls-ignore-start
      # Supervisor start failure is difficult to test without breaking the system
      {:error, reason} = error ->
        Logger.error("[Vaultx] Failed to start supervisor", error: reason)
        error
        # coveralls-ignore-stop
    end
  end

  defp setup_telemetry_if_enabled do
    if Config.feature_enabled?(:telemetry) do
      case setup_telemetry() do
        :ok -> Logger.debug("[Vaultx] Telemetry enabled")
        # Telemetry setup failure is environment-dependent and hard to test
        # coveralls-ignore-next-line
        _error -> Logger.warn("[Vaultx] Telemetry setup failed")
      end
    end
  end

  defp log_startup_success(children) do
    Logger.info("[Vaultx] Application started successfully",
      components: length(children),
      version: version()
    )
  end

  # ============================================================================
  # Private Functions - Component Management
  # ============================================================================

  defp build_optional_components(config) do
    [
      maybe_build_cache(config),
      maybe_build_token_renewal(config),
      maybe_build_rate_limiter(config),
      maybe_build_hot_reload(config)
    ]
    |> Enum.reject(&is_nil/1)
  end

  defp maybe_build_cache(config) do
    # coveralls-ignore-start
    # Cache is disabled in test environment, making this branch untestable in tests
    if config.cache_enabled and Mix.env() != :test do
      Logger.debug("[Vaultx] Adding cache system")
      {Vaultx.Cache.Manager, []}
    end

    # coveralls-ignore-stop
  end

  defp maybe_build_token_renewal(config) do
    if config.token_renewal_enabled and not is_nil(Config.get_token()) do
      Logger.debug("[Vaultx] Adding token renewal")
      {Vaultx.Auth.TokenRenewal, []}
    end
  end

  defp maybe_build_rate_limiter(config) do
    if config.rate_limit_enabled do
      Logger.debug("[Vaultx] Adding rate limiter")

      {Vaultx.Base.RateLimiter,
       [rate: config.rate_limit_requests, burst: config.rate_limit_burst]}
    end
  end

  defp maybe_build_hot_reload(config) do
    hot_reload_enabled = Map.get(config, :hot_reload_enabled, false)

    # coveralls-ignore-start
    # Hot reload is disabled in test environment, making this branch untestable in tests
    if hot_reload_enabled and Mix.env() != :test do
      Logger.debug("[Vaultx] Adding hot reload")
      {Vaultx.Config.HotReload, []}
    end

    # coveralls-ignore-stop
  end

  defp build_finch_spec(config) do
    pools = [
      {:default,
       [
         size: config.pool_size,
         count: 1,
         conn_max_idle_time: config.pool_max_idle_time
       ]}
    ]

    {Finch, name: Vaultx.Finch, pools: pools}
  end

  # ============================================================================
  # Private Functions - Telemetry
  # ============================================================================

  defp setup_telemetry do
    # Core events
    core_events = [
      [:vaultx, :http, :request, :start],
      [:vaultx, :http, :request, :stop],
      [:vaultx, :http, :request, :exception],
      [:vaultx, :auth, :start],
      [:vaultx, :auth, :success],
      [:vaultx, :auth, :failure]
    ]

    # Enhanced telemetry events
    enhanced_events = [
      [:vaultx, :cache, :metrics],
      [:vaultx, :cache, :hit],
      [:vaultx, :cache, :miss],
      [:vaultx, :cache, :eviction],
      [:vaultx, :pool, :metrics],
      [:vaultx, :pool, :exhaustion],
      [:vaultx, :security, :event],
      [:vaultx, :security, :anomaly],
      [:vaultx, :business, :secret_access],
      [:vaultx, :business, :engine_usage],
      [:vaultx, :performance]
    ]

    all_events = core_events ++ enhanced_events

    case Vaultx.Base.Telemetry.attach_many("vaultx-handler", all_events, &handle_telemetry/4, %{}) do
      :ok ->
        :ok

      # coveralls-ignore-start
      # Telemetry error paths are environment-dependent and hard to test
      {:error, :telemetry_not_available} ->
        :ok

      {:error, _error} ->
        :error
        # coveralls-ignore-stop
    end
  end

  defp cleanup_telemetry_if_enabled do
    if Config.feature_enabled?(:telemetry) do
      case Vaultx.Base.Telemetry.detach("vaultx-handler") do
        :ok -> Logger.debug("[Vaultx] Telemetry cleaned up")
        # Telemetry cleanup failure is environment-dependent and hard to test
        # coveralls-ignore-next-line
        _error -> :ok
      end
    end
  end

  def handle_telemetry(event, measurements, metadata, _config) do
    case event do
      # Core HTTP and auth events
      [:vaultx, :http, :request, _] ->
        Logger.debug("[Vaultx] HTTP event",
          event: event,
          duration: measurements[:duration],
          status: metadata[:status],
          method: metadata[:method],
          path: metadata[:path]
        )

      [:vaultx, :auth, _] ->
        Logger.debug("[Vaultx] Auth event",
          event: event,
          duration: measurements[:duration],
          result: metadata[:result]
        )

      # Enhanced telemetry events
      [:vaultx, :cache, :metrics] ->
        Logger.info("[Vaultx] Cache metrics",
          hit_rate: measurements[:hit_rate],
          size: measurements[:size],
          memory_mb: div(measurements[:memory_usage] || 0, 1024 * 1024)
        )

      [:vaultx, :cache, event_type] when event_type in [:hit, :miss, :eviction] ->
        Logger.debug("[Vaultx] Cache event",
          event_type: event_type,
          key: metadata[:key]
        )

      [:vaultx, :pool, :metrics] ->
        Logger.info("[Vaultx] Pool metrics",
          active: measurements[:active_connections],
          idle: measurements[:idle_connections],
          pending: measurements[:pending_requests],
          avg_response_time: measurements[:avg_response_time]
        )

      [:vaultx, :pool, :exhaustion] ->
        Logger.warn("[Vaultx] Pool exhaustion",
          pool_name: metadata[:pool_name]
        )

      [:vaultx, :security, :event] ->
        Logger.info("[Vaultx] Security event",
          event_type: metadata[:event_type],
          severity: measurements[:severity_level]
        )

      [:vaultx, :security, :anomaly] ->
        Logger.warn("[Vaultx] Security anomaly",
          description: metadata[:description],
          severity: measurements[:severity_level]
        )

      [:vaultx, :business, metric_type] ->
        Logger.debug("[Vaultx] Business metric",
          metric_type: metric_type,
          value: measurements[:value]
        )

      [:vaultx, :performance] ->
        Logger.debug("[Vaultx] Performance metric",
          operation: metadata[:operation],
          duration: measurements[:duration],
          success: measurements[:success] == 1
        )

      _ ->
        Logger.debug("[Vaultx] Telemetry event",
          event: event,
          measurements: measurements,
          metadata: metadata
        )
    end
  end
end
