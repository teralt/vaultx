defmodule Vaultx.Application do
  @moduledoc """
  OTP Application for Vaultx HashiCorp Vault client.

  This application manages the lifecycle of Vaultx infrastructure components,
  including HTTP connection pools, telemetry handlers, and optional background
  processes. It follows OTP principles for fault tolerance and graceful startup.

  ## Architecture

  The application uses a robust supervision tree with fault tolerance:
  - HTTP connection pool (Finch) for efficient connection reuse
  - Optional cache system for performance optimization
  - Optional telemetry handlers for observability
  - Optional background services (token renewal, rate limiting)
  - Graceful degradation when optional components fail

  ## Startup Process

  1. Load and validate configuration
  2. Start core infrastructure (HTTP pool)
  3. Start optional components based on configuration
  4. Setup telemetry handlers if enabled
  5. Log startup summary with component status

  ## Error Handling

  - Core components (HTTP pool) must start successfully
  - Optional components can fail without stopping the application
  - Comprehensive logging for troubleshooting
  - Graceful shutdown with proper cleanup

  ## References

  - [OTP Application Behavior](https://hexdocs.pm/elixir/Application.html)
  - [Supervisor Strategies](https://hexdocs.pm/elixir/Supervisor.html)
  """

  use Application

  alias Vaultx.Base.{Config, Logger, Security}

  @type child_spec :: Supervisor.child_spec() | {module(), term()} | module()
  @type startup_result :: {:ok, pid()} | {:error, term()}

  @doc false
  def start(_type, _args) do
    start_time = System.monotonic_time()

    with :ok <- log_startup_begin(),
         {:ok, config} <- load_and_validate_config(),
         {:ok, children} <- build_children_safely(config),
         {:ok, supervisor_pid} <- start_supervisor(children),
         :ok <- setup_post_startup_components(config) do
      duration = System.monotonic_time() - start_time
      log_startup_success(children, duration)
      {:ok, supervisor_pid}
    else
      {:error, reason} = error ->
        duration = System.monotonic_time() - start_time
        log_startup_failure(reason, duration)
        error
    end
  end

  @doc false
  def stop(_state) do
    Logger.info("Stopping Vaultx application")

    # Cleanup telemetry handlers if enabled
    if Config.feature_enabled?(:telemetry) do
      cleanup_telemetry()
      Logger.debug("Telemetry cleanup completed")
    end

    Logger.info("Vaultx application stopped successfully")
    :ok
  end

  @doc """
  Returns the current version of Vaultx.
  """
  @spec version() :: String.t()
  def version do
    Application.spec(:vaultx, :vsn) |> to_string()
  end

  @doc """
  Returns the application configuration summary.
  """
  @spec config_summary() :: map()
  def config_summary do
    config = Config.get()

    %{
      url: config.url,
      timeout: config.timeout,
      retry_attempts: config.retry_attempts,
      ssl_verify: config.ssl_verify,
      logger_level: config.logger_level,
      telemetry_enabled: config.telemetry_enabled,
      features: Config.features_status()
    }
  end

  # Private functions - Startup Process

  defp log_startup_begin do
    Logger.info("Starting Vaultx application", %{version: version()})
    :ok
  end

  defp load_and_validate_config do
    try do
      # Set startup context to skip connectivity tests
      Process.put(:vaultx_startup_context, :application_startup)

      # Use modern configuration system with comprehensive validation
      case Config.get_modern() do
        {:ok, config} ->
          Logger.info("Configuration loaded with modern validation", %{
            url: config.url,
            features_enabled: length(Config.enabled_features()),
            validation_system: :modern
          })

          # Run comprehensive analysis for startup diagnostics
          try do
            {:ok, analysis} = Vaultx.Config.analyze()

            Logger.info("Configuration analysis completed", %{
              performance_score: analysis.performance_score,
              security_score: analysis.security_score,
              issues_count: length(analysis.issues),
              connectivity_status: analysis.connectivity_status
            })

            # Log warnings if any
            if not Enum.empty?(analysis.issues) do
              warnings = Enum.filter(analysis.issues, &(&1.type == :warning))
              errors = Enum.filter(analysis.issues, &(&1.type == :error))

              if not Enum.empty?(warnings) do
                Logger.warning("Configuration warnings detected", %{
                  count: length(warnings),
                  warnings: Enum.map(warnings, & &1.message)
                })
              end

              if not Enum.empty?(errors) do
                Logger.error("Configuration errors detected", %{
                  count: length(errors),
                  errors: Enum.map(errors, & &1.message)
                })
              end
            end
          rescue
            analysis_error ->
              Logger.warning("Configuration analysis failed",
                error: Exception.message(analysis_error)
              )
          end

          {:ok, config}

        {:error, config_error} ->
          Logger.warning("Modern configuration validation failed, falling back to legacy",
            error: config_error
          )

          # Fallback to legacy configuration
          config = Config.get()

          Logger.debug("Configuration loaded with legacy validation", %{
            url: config.url,
            features_enabled: length(Config.enabled_features()),
            validation_system: :legacy
          })

          {:ok, config}
      end
    rescue
      error ->
        Logger.error("Failed to load configuration", error: error)
        {:error, {:config_load_failed, error}}
    end
  end

  defp build_children_safely(config) do
    try do
      children = build_children(config)
      Logger.debug("Child specifications built", %{count: length(children)})
      {:ok, children}
    rescue
      error ->
        Logger.error("Failed to build child specifications", error: error)
        {:error, {:child_spec_failed, error}}
    end
  end

  defp start_supervisor(children) do
    opts = [strategy: :one_for_one, name: Vaultx.Supervisor]

    case Supervisor.start_link(children, opts) do
      {:ok, pid} = success ->
        Logger.debug("Supervisor started successfully", %{pid: inspect(pid)})
        success

      {:error, reason} = error ->
        Logger.error("Failed to start supervisor", error: reason)
        error
    end
  end

  defp setup_post_startup_components(_config) do
    if Config.feature_enabled?(:telemetry) do
      setup_telemetry()
      Logger.debug("Telemetry setup completed")
    end

    # Perform post-startup configuration health check
    perform_post_startup_health_check()

    :ok
  end

  defp perform_post_startup_health_check do
    try do
      health_status = Vaultx.Config.get_health_status()

      case health_status do
        :healthy ->
          Logger.info("Configuration health check: HEALTHY")

        :degraded ->
          Logger.warning("Configuration health check: DEGRADED - Some issues detected")

        :unhealthy ->
          Logger.error("Configuration health check: UNHEALTHY - Multiple issues detected")
      end

      # Run diagnostics if not healthy
      if health_status != :healthy do
        try do
          {:ok, optimization} = Vaultx.Config.validate_and_optimize()

          if not Enum.empty?(optimization.suggestions) do
            Logger.info("Configuration optimization suggestions available", %{
              count: length(optimization.suggestions),
              optimization_potential: optimization.optimization_potential
            })
          end
        rescue
          error ->
            Logger.warning("Failed to get optimization suggestions",
              error: Exception.message(error)
            )
        end
      end
    rescue
      error ->
        Logger.warning("Configuration health check failed", error: Exception.message(error))
    end
  end

  defp log_startup_success(children, duration) do
    duration_ms = System.convert_time_unit(duration, :native, :millisecond)

    Logger.info("Vaultx application started successfully", %{
      children_count: length(children),
      startup_time_ms: duration_ms,
      features: Config.features_status()
    })
  end

  defp log_startup_failure(reason, duration) do
    duration_ms = System.convert_time_unit(duration, :native, :millisecond)

    Logger.error("Vaultx application startup failed", %{
      reason: reason,
      startup_time_ms: duration_ms
    })
  end

  # Private functions - Child Management

  defp build_children(config) do
    []
    |> add_core_components(config)
    |> add_optional_components(config)
    |> Enum.reverse()
  end

  defp add_core_components(children, config) do
    # HTTP pool is required for all operations
    [build_finch_child_spec(config) | children]
  end

  defp add_optional_components(children, config) do
    children
    |> maybe_add_component(:cache_system, config)
    |> maybe_add_component(:token_renewal, config)
    |> maybe_add_component(:rate_limiter, config)
    |> maybe_add_component(:config_hot_reload, config)
  end

  defp setup_telemetry do
    # Attach default telemetry handlers if telemetry is available
    case Vaultx.Base.Telemetry.attach_many(
           "vaultx-default-handler",
           [
             [:vaultx, :http, :request, :start],
             [:vaultx, :http, :request, :stop],
             [:vaultx, :http, :request, :exception],
             [:vaultx, :auth, :start],
             [:vaultx, :auth, :success],
             [:vaultx, :auth, :failure]
           ],
           &__MODULE__.handle_telemetry_event/4,
           %{}
         ) do
      :ok ->
        Logger.debug("Telemetry handlers attached successfully")
        :ok

      {:error, :telemetry_not_available} ->
        # coveralls-ignore-next-line
        Logger.debug("Telemetry not available, skipping handler setup")
        :ok

      {:error, error} ->
        # coveralls-ignore-next-line
        Logger.warning("Failed to attach telemetry handlers", error: error)
        :ok
    end
  end

  # NOTE: This cleanup_telemetry function is only called during application shutdown.
  # In test environments, the telemetry handlers may not be attached when this is called,
  # or the application may not go through a clean shutdown process. Testing this would
  # require complex application lifecycle setup that doesn't provide meaningful value
  # for these simple telemetry cleanup operations.
  defp cleanup_telemetry do
    # coveralls-ignore-start
    case Vaultx.Base.Telemetry.detach("vaultx-default-handler") do
      :ok ->
        Logger.debug("Telemetry handlers detached successfully")

      {:error, :telemetry_not_available} ->
        Logger.debug("Telemetry not available, skipping cleanup")

      {:error, _error} ->
        Logger.debug("Telemetry handlers already detached or not found")
    end

    :ok
    # coveralls-ignore-stop
  end

  def handle_telemetry_event(event, measurements, metadata, _config) do
    Logger.debug("Telemetry event", %{
      event: event,
      measurements: measurements,
      metadata: sanitize_metadata(metadata)
    })
  end

  defp sanitize_metadata(metadata) do
    Security.sanitize_for_logging(metadata)
  end

  # New component management functions

  defp maybe_add_component(children, component_type, config) do
    case should_start_component?(component_type, config) do
      {true, reason} ->
        {:ok, child_spec} = build_component_spec(component_type, config)

        Logger.debug("Adding component to supervision tree", %{
          component: component_type,
          reason: reason
        })

        [child_spec | children]

      {false, reason} ->
        Logger.debug("Skipping component", %{
          component: component_type,
          reason: reason
        })

        children
    end
  end

  defp should_start_component?(:cache_system, config) do
    cond do
      Mix.env() == :test ->
        {false, "disabled in test environment"}

      not config.cache_enabled ->
        {false, "disabled by configuration"}

      true ->
        {true, "enabled by configuration"}
    end
  end

  defp should_start_component?(:token_renewal, config) do
    cond do
      not config.token_renewal_enabled ->
        {false, "disabled by configuration"}

      is_nil(Config.get_token()) ->
        {false, "no token available"}

      true ->
        {true, "enabled with valid token"}
    end
  end

  defp should_start_component?(:rate_limiter, config) do
    if config.rate_limit_enabled do
      {true, "enabled with valid configuration"}
    else
      {false, "disabled by configuration"}
    end
  end

  defp should_start_component?(:config_hot_reload, config) do
    hot_reload_enabled = Map.get(config, :hot_reload_enabled, false)

    cond do
      Mix.env() == :test ->
        {false, "disabled in test environment"}

      not hot_reload_enabled ->
        {false, "disabled by configuration"}

      true ->
        {true, "enabled for runtime configuration updates"}
    end
  end

  defp build_component_spec(:cache_system, _config) do
    {:ok, {Vaultx.Cache.Manager, []}}
  end

  defp build_component_spec(:token_renewal, _config) do
    {:ok, {Vaultx.Auth.TokenRenewal, []}}
  end

  defp build_component_spec(:rate_limiter, config) do
    spec = {
      Vaultx.Base.RateLimiter,
      [rate: config.rate_limit_requests, burst: config.rate_limit_burst]
    }

    {:ok, spec}
  end

  defp build_component_spec(:config_hot_reload, _config) do
    {:ok, {Vaultx.Config.HotReload, []}}
  end

  defp build_finch_child_spec(config) do
    finch_pools = [
      {:default,
       [
         size: config.pool_size,
         count: 1,
         conn_max_idle_time: config.pool_max_idle_time
       ]}
    ]

    {Finch, name: Vaultx.Finch, pools: finch_pools}
  end
end
