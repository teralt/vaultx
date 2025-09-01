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
      {:error, reason} = error ->
        Logger.error("[Vaultx] Application startup failed", error: reason)
        error
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
      error ->
        Logger.error("[Vaultx] Failed to load configuration", error: Exception.message(error))
        {:error, {:config_load_failed, error}}
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
      error ->
        Logger.error("[Vaultx] Failed to build child specifications",
          error: Exception.message(error)
        )

        {:error, {:child_spec_failed, error}}
    end
  end

  defp start_supervisor(children) do
    opts = [strategy: :one_for_one, name: Vaultx.Supervisor]

    case Supervisor.start_link(children, opts) do
      {:ok, pid} = success ->
        Logger.debug("[Vaultx] Supervisor started", pid: inspect(pid))
        success

      {:error, reason} = error ->
        Logger.error("[Vaultx] Failed to start supervisor", error: reason)
        error
    end
  end

  defp setup_telemetry_if_enabled do
    if Config.feature_enabled?(:telemetry) do
      case setup_telemetry() do
        :ok -> Logger.debug("[Vaultx] Telemetry enabled")
        _error -> Logger.warning("[Vaultx] Telemetry setup failed")
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
    if config.cache_enabled and Mix.env() != :test do
      Logger.debug("[Vaultx] Adding cache system")
      {Vaultx.Cache.Manager, []}
    end
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

    if hot_reload_enabled and Mix.env() != :test do
      Logger.debug("[Vaultx] Adding hot reload")
      {Vaultx.Config.HotReload, []}
    end
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
    events = [
      [:vaultx, :http, :request, :start],
      [:vaultx, :http, :request, :stop],
      [:vaultx, :http, :request, :exception],
      [:vaultx, :auth, :start],
      [:vaultx, :auth, :success],
      [:vaultx, :auth, :failure]
    ]

    case Vaultx.Base.Telemetry.attach_many("vaultx-handler", events, &handle_telemetry/4, %{}) do
      :ok -> :ok
      {:error, :telemetry_not_available} -> :ok
      {:error, _error} -> :error
    end
  end

  defp cleanup_telemetry_if_enabled do
    if Config.feature_enabled?(:telemetry) do
      case Vaultx.Base.Telemetry.detach("vaultx-handler") do
        :ok -> Logger.debug("[Vaultx] Telemetry cleaned up")
        _error -> :ok
      end
    end
  end

  def handle_telemetry(event, measurements, metadata, _config) do
    Logger.debug("[Vaultx] Telemetry event",
      event: event,
      duration: measurements[:duration],
      status: metadata[:status]
    )
  end
end
