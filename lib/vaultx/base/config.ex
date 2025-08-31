defmodule Vaultx.Base.Config do
  @moduledoc """
  Dynamic configuration management for Vaultx HashiCorp Vault client.

  This module provides stateless, runtime configuration reading that follows
  modern Elixir library conventions. Configuration is resolved dynamically
  on each request, enabling immediate runtime updates without process restarts.

  ## Design Philosophy

  - Stateless: No GenServer or caching, pure function-based configuration
  - Dynamic: Configuration changes take effect immediately
  - Hierarchical: Environment variables override application configuration
  - Validated: Comprehensive validation using NimbleOptions
  - Secure: Built-in security validation and best practices

  ## Configuration Sources

  Configuration is resolved in the following priority order:
  1. Environment variables (highest priority)
  2. Application configuration
  3. Default values (lowest priority)

  ## Supported Configuration

  1. System environment variables (highest priority)
  2. Application configuration
  3. Default values (lowest priority)

  ## Environment Variables

  ### Core Configuration
  - `VAULTX_URL` or `VAULT_ADDR` - Vault server URL
  - `VAULTX_TOKEN` or `VAULT_TOKEN` - Authentication token
  - `VAULTX_NAMESPACE` or `VAULT_NAMESPACE` - Vault namespace (Enterprise feature)

  ### Network & Timeouts
  - `VAULTX_TIMEOUT` - Request timeout in milliseconds (default: 30000)
  - `VAULTX_CONNECT_TIMEOUT` - Connection timeout in milliseconds (default: 10000)
  - `VAULTX_RETRY_ATTEMPTS` - Number of retry attempts (default: 3)
  - `VAULTX_RETRY_DELAY` - Delay between retries in milliseconds (default: 1000)
  - `VAULTX_RETRY_BACKOFF` - Retry backoff strategy (linear/exponential, default: exponential)
  - `VAULTX_MAX_RETRY_DELAY` - Maximum retry delay in milliseconds (default: 30000)

  ### SSL/TLS Configuration
  - `VAULTX_SSL_VERIFY` - Enable SSL verification (true/false, default: true)
  - `VAULTX_CACERT` or `VAULT_CACERT` - Path to CA certificate file
  - `VAULTX_CACERTS_DIR` - Path to a directory containing CA certificates (.pem)
  - `VAULTX_CLIENT_CERT` or `VAULT_CLIENT_CERT` - Path to client certificate file
  - `VAULTX_CLIENT_KEY` or `VAULT_CLIENT_KEY` - Path to client private key file
  - `VAULTX_TLS_SERVER_NAME` - TLS server name for SNI
  - `VAULTX_TLS_MIN_VERSION` - Minimum TLS version (1.2/1.3, default: 1.2)

  ### Connection Pool
  - `VAULTX_POOL_SIZE` - Connection pool size (default: 10)
  - `VAULTX_POOL_MAX_IDLE_TIME` - Maximum idle time for connections in milliseconds (default: 300000)

  ### Logging & Telemetry
  - `VAULTX_LOGGER_LEVEL` - Logger level (debug/info/warn/error/none, default: info)
  - `VAULTX_TELEMETRY_ENABLED` - Enable telemetry (true/false, default: true)
  - `VAULTX_AUDIT_ENABLED` - Enable audit logging (true/false, default: false)
  - `VAULTX_METRICS_ENABLED` - Enable metrics collection (true/false, default: true)

  ### Security & Compliance
  - `VAULTX_RATE_LIMIT_ENABLED` - Enable client-side rate limiting (true/false, default: false)
  - `VAULTX_RATE_LIMIT_REQUESTS` - Requests per second limit (default: 100)
  - `VAULTX_TOKEN_RENEWAL_ENABLED` - Enable automatic token renewal (true/false, default: true)
  - `VAULTX_TOKEN_RENEWAL_THRESHOLD` - Token renewal threshold percentage (default: 80)
  - `VAULTX_SECURITY_HEADERS_ENABLED` - Enable security headers validation (true/false, default: true)

  ## Examples

      # Get complete configuration
      config = Vaultx.Base.Config.get()

      # Get specific configuration value
      url = Vaultx.Base.Config.get_url()
      timeout = Vaultx.Base.Config.get_timeout()

      # Validate configuration
      case Vaultx.Base.Config.validate() do
        :ok -> :ok
        {:error, errors} -> handle_errors(errors)
      end
  """

  alias Vaultx.Base.Error

  @type retry_backoff :: :linear | :exponential

  @type t :: %{
          # Core configuration
          url: String.t(),
          token: String.t() | nil,
          namespace: String.t() | nil,

          # Network & timeouts
          timeout: pos_integer(),
          connect_timeout: pos_integer(),
          retry_attempts: non_neg_integer(),
          retry_delay: pos_integer(),
          retry_backoff: retry_backoff(),
          max_retry_delay: pos_integer(),

          # SSL/TLS configuration
          ssl_verify: boolean(),
          cacert: String.t() | nil,
          cacerts_dir: String.t() | nil,
          client_cert: String.t() | nil,
          client_key: String.t() | nil,
          tls_server_name: String.t() | nil,
          tls_min_version: String.t(),

          # Connection pool
          pool_size: pos_integer(),
          pool_max_idle_time: pos_integer(),

          # Logging & telemetry
          logger_level: atom(),
          telemetry_enabled: boolean(),
          audit_enabled: boolean(),
          metrics_enabled: boolean(),

          # Security & compliance
          rate_limit_enabled: boolean(),
          rate_limit_requests: pos_integer(),
          rate_limit_burst: non_neg_integer(),
          token_renewal_enabled: boolean(),
          token_renewal_threshold: pos_integer(),
          security_headers_enabled: boolean()
        }

  @default_config %{
    # Core configuration
    url: "http://localhost:8200",
    token: nil,
    namespace: nil,

    # Network & timeouts
    timeout: 30_000,
    connect_timeout: 10_000,
    retry_attempts: 3,
    retry_delay: 1_000,
    retry_backoff: :exponential,
    max_retry_delay: 30_000,

    # SSL/TLS configuration
    ssl_verify: true,
    cacert: nil,
    cacerts_dir: nil,
    client_cert: nil,
    client_key: nil,
    tls_server_name: nil,
    tls_min_version: "1.2",

    # Connection pool
    pool_size: 10,
    pool_max_idle_time: 300_000,

    # Logging & telemetry
    logger_level: :info,
    telemetry_enabled: true,
    audit_enabled: false,
    metrics_enabled: true,

    # Security & compliance
    rate_limit_enabled: false,
    rate_limit_requests: 100,
    rate_limit_burst: 0,
    token_renewal_enabled: true,
    token_renewal_threshold: 80,
    security_headers_enabled: false
  }

  @config_schema [
    # Core configuration
    url: [
      type: :string,
      required: true,
      doc: "Vault server URL (e.g., https://vault.example.com:8200)"
    ],
    token: [
      type: {:or, [:string, nil]},
      doc: "Authentication token (hvs.*, s.*, or legacy format)"
    ],
    namespace: [
      type: {:or, [:string, nil]},
      doc: "Vault namespace for Enterprise installations"
    ],

    # Network & timeouts
    timeout: [
      type: :pos_integer,
      default: 30_000,
      doc: "Request timeout in milliseconds"
    ],
    connect_timeout: [
      type: :pos_integer,
      default: 10_000,
      doc: "Connection timeout in milliseconds"
    ],
    retry_attempts: [
      type: :non_neg_integer,
      default: 3,
      doc: "Number of retry attempts for failed requests"
    ],
    retry_delay: [
      type: :pos_integer,
      default: 1_000,
      doc: "Initial delay between retries in milliseconds"
    ],
    retry_backoff: [
      type: {:in, [:linear, :exponential]},
      default: :exponential,
      doc: "Retry backoff strategy"
    ],
    max_retry_delay: [
      type: :pos_integer,
      default: 30_000,
      doc: "Maximum delay between retries in milliseconds"
    ],

    # SSL/TLS configuration
    ssl_verify: [
      type: :boolean,
      default: true,
      doc: "Enable SSL certificate verification"
    ],
    cacert: [
      type: {:or, [:string, nil]},
      doc: "Path to CA certificate file for SSL verification"
    ],
    cacerts_dir: [
      type: {:or, [:string, nil]},
      doc: "Path to directory containing CA certificates (.pem) to be loaded into :cacerts"
    ],
    client_cert: [
      type: {:or, [:string, nil]},
      doc: "Path to client certificate file for mutual TLS"
    ],
    client_key: [
      type: {:or, [:string, nil]},
      doc: "Path to client private key file for mutual TLS"
    ],
    tls_server_name: [
      type: {:or, [:string, nil]},
      doc: "Server name for TLS SNI (Server Name Indication)"
    ],
    tls_min_version: [
      type: {:in, ["1.2", "1.3"]},
      default: "1.2",
      doc: "Minimum TLS version to accept"
    ],

    # Connection pool
    pool_size: [
      type: :pos_integer,
      default: 10,
      doc: "Maximum number of connections in the pool"
    ],
    pool_max_idle_time: [
      type: :pos_integer,
      default: 300_000,
      doc: "Maximum idle time for connections in milliseconds before cleanup"
    ],

    # Logging & telemetry
    logger_level: [
      type: {:in, [:debug, :info, :warn, :error, :none]},
      default: :info,
      doc: "Logger level for Vaultx operations"
    ],
    telemetry_enabled: [
      type: :boolean,
      default: true,
      doc: "Enable telemetry events for monitoring and observability"
    ],
    audit_enabled: [
      type: :boolean,
      default: false,
      doc: "Enable audit logging for security compliance"
    ],
    metrics_enabled: [
      type: :boolean,
      default: true,
      doc: "Enable metrics collection for performance monitoring"
    ],

    # Security & compliance
    rate_limit_enabled: [
      type: :boolean,
      default: false,
      doc: "Enable client-side rate limiting to prevent overwhelming Vault"
    ],
    rate_limit_requests: [
      type: :pos_integer,
      default: 100,
      doc: "Maximum requests per second when rate limiting is enabled"
    ],
    token_renewal_enabled: [
      type: :boolean,
      default: true,
      doc: "Enable automatic token renewal before expiration"
    ],
    token_renewal_threshold: [
      type: {:custom, __MODULE__, :validate_percentage, []},
      default: 80,
      doc: "Percentage of token TTL at which to trigger renewal (1-99)"
    ],
    security_headers_enabled: [
      type: :boolean,
      default: false,
      doc: "Enable validation of security headers in responses"
    ],
    rate_limit_burst: [
      type: :non_neg_integer,
      default: 0,
      doc: "Additional burst tokens allowed on top of steady rate"
    ]
  ]

  @doc """
  Gets the complete configuration with all resolved values.

  ## Examples

      iex> config = Vaultx.Base.Config.get()
      iex> config.url
      "https://vault.example.com:8200"

  """
  @spec get() :: t()
  def get do
    @default_config
    |> merge_app_config()
    |> merge_env_config()
    |> validate_config!()
  end

  @doc """
  Gets the Vault server URL.

  ## Examples

      iex> Vaultx.Base.Config.get_url()
      "https://vault.example.com:8200"

  """
  @spec get_url() :: String.t()
  def get_url do
    get_env_var(["VAULTX_URL", "VAULT_ADDR"]) ||
      Application.get_env(:vaultx, :url) ||
      @default_config.url
  end

  @doc """
  Gets the authentication token.

  ## Examples

      iex> Vaultx.Base.Config.get_token()
      "hvs.CAESIJ..."

  """
  @spec get_token() :: String.t() | nil
  def get_token do
    case get_env_var(["VAULTX_TOKEN", "VAULT_TOKEN"]) do
      nil -> Application.get_env(:vaultx, :token, @default_config.token)
      token -> token
    end
  end

  @doc """
  Gets the request timeout in milliseconds.

  ## Examples

      iex> Vaultx.Base.Config.get_timeout()
      30000

  """
  @spec get_timeout() :: pos_integer()
  def get_timeout do
    case get_env_var_as_integer(["VAULTX_TIMEOUT"]) do
      nil -> Application.get_env(:vaultx, :timeout, @default_config.timeout)
      timeout -> timeout
    end
  end

  @doc """
  Gets the number of retry attempts.

  ## Examples

      iex> Vaultx.Base.Config.get_retry_attempts()
      3

  """
  @spec get_retry_attempts() :: non_neg_integer()
  def get_retry_attempts do
    get_env_var_as_integer(["VAULTX_RETRY_ATTEMPTS"]) ||
      Application.get_env(:vaultx, :retry_attempts) ||
      @default_config.retry_attempts
  end

  @doc """
  Gets the retry delay in milliseconds.

  ## Examples

      iex> Vaultx.Base.Config.get_retry_delay()
      1000

  """
  @spec get_retry_delay() :: pos_integer()
  def get_retry_delay do
    get_env_var_as_integer(["VAULTX_RETRY_DELAY"]) ||
      Application.get_env(:vaultx, :retry_delay) ||
      @default_config.retry_delay
  end

  @doc """
  Gets the SSL verification setting.

  ## Examples

      iex> Vaultx.Base.Config.get_ssl_verify()
      true

  """
  @spec get_ssl_verify() :: boolean()
  def get_ssl_verify do
    case get_env_var_as_boolean(["VAULTX_SSL_VERIFY"]) do
      nil -> Application.get_env(:vaultx, :ssl_verify, @default_config.ssl_verify)
      ssl_verify -> ssl_verify
    end
  end

  @doc """
  Gets the CA certificate path.

  ## Examples

      iex> Vaultx.Base.Config.get_cacert()
      "/path/to/ca.pem"

  """
  @spec get_cacert() :: String.t() | nil
  def get_cacert do
    get_env_var(["VAULTX_CACERT"]) ||
      Application.get_env(:vaultx, :cacert) ||
      @default_config.cacert
  end

  @doc """
  Gets the Vault namespace.

  ## Examples

      iex> Vaultx.Base.Config.get_namespace()
      "my-namespace"

  """
  @spec get_namespace() :: String.t() | nil
  def get_namespace do
    get_env_var(["VAULTX_NAMESPACE", "VAULT_NAMESPACE"]) ||
      Application.get_env(:vaultx, :namespace) ||
      @default_config.namespace
  end

  @doc """
  Gets a configuration value by key with fallback to default.

  ## Examples

      iex> Vaultx.Base.Config.get_value(:timeout)
      30000

      iex> Vaultx.Base.Config.get_value(:unknown_key, "default")
      "default"

  """
  @spec get_value(atom(), any()) :: any()
  def get_value(key, default \\ nil) do
    config = get()
    Map.get(config, key, default)
  end

  @doc """
  Checks if SSL/TLS is properly configured.

  ## Examples

      iex> Vaultx.Base.Config.ssl_configured?()
      true

  """
  @spec ssl_configured?() :: boolean()
  def ssl_configured? do
    url = get_url()
    String.starts_with?(url, "https://") and get_ssl_verify()
  end

  @doc """
  Checks if mutual TLS (mTLS) is configured.

  ## Examples

      iex> Vaultx.Base.Config.mtls_configured?()
      false

  """
  @spec mtls_configured?() :: boolean()
  def mtls_configured? do
    ssl_configured?() and
      not is_nil(get_client_cert()) and
      not is_nil(get_client_key())
  end

  @doc """
  Gets the effective retry configuration as a map.

  ## Examples

      iex> Vaultx.Base.Config.get_retry_config()
      %{
        attempts: 3,
        delay: 1000,
        backoff: :exponential,
        max_delay: 30000
      }

  """
  @spec get_retry_config() :: %{
          attempts: non_neg_integer(),
          delay: pos_integer(),
          backoff: retry_backoff(),
          max_delay: pos_integer()
        }
  def get_retry_config do
    %{
      attempts: get_retry_attempts(),
      delay: get_retry_delay(),
      backoff: get_retry_backoff(),
      max_delay: get_max_retry_delay()
    }
  end

  @doc """
  Gets the effective pool configuration as a map.

  ## Examples

      iex> Vaultx.Base.Config.get_pool_config()
      %{
        size: 10,
        max_overflow: 5,
        timeout: 5000,
        max_idle_time: 300000
      }

  """
  @spec get_pool_config() :: %{
          size: pos_integer(),
          max_idle_time: pos_integer()
        }
  def get_pool_config do
    %{
      size: get_pool_size(),
      max_idle_time: get_pool_max_idle_time()
    }
  end

  @doc """
  Gets the logger level.

  ## Examples

      iex> Vaultx.Base.Config.get_logger_level()
      :info

  """
  @spec get_logger_level() :: atom()
  def get_logger_level do
    case get_env_var(["VAULTX_LOGGER_LEVEL"]) do
      nil ->
        Application.get_env(:vaultx, :logger_level, @default_config.logger_level)

      level_str ->
        case level_str do
          "debug" -> :debug
          "info" -> :info
          "warn" -> :warn
          "error" -> :error
          "none" -> :none
          _ -> @default_config.logger_level
        end
    end
  end

  @doc """
  Gets the telemetry enabled setting.

  ## Examples

      iex> Vaultx.Base.Config.get_telemetry_enabled()
      true

  """
  @spec get_telemetry_enabled() :: boolean()
  def get_telemetry_enabled do
    case get_env_var_as_boolean(["VAULTX_TELEMETRY_ENABLED"]) do
      nil -> Application.get_env(:vaultx, :telemetry_enabled, @default_config.telemetry_enabled)
      telemetry_enabled -> telemetry_enabled
    end
  end

  @doc """
  Gets the connection pool size.

  ## Examples

      iex> Vaultx.Base.Config.get_pool_size()
      10

  """
  @spec get_pool_size() :: pos_integer()
  def get_pool_size do
    get_env_var_as_integer(["VAULTX_POOL_SIZE"]) ||
      Application.get_env(:vaultx, :pool_size) ||
      @default_config.pool_size
  end

  @doc """
  Gets the connection timeout in milliseconds.

  ## Examples

      iex> Vaultx.Base.Config.get_connect_timeout()
      10000

  """
  @spec get_connect_timeout() :: pos_integer()
  def get_connect_timeout do
    get_env_var_as_integer(["VAULTX_CONNECT_TIMEOUT"]) ||
      Application.get_env(:vaultx, :connect_timeout) ||
      @default_config.connect_timeout
  end

  @doc """
  Gets the retry backoff strategy.

  ## Examples

      iex> Vaultx.Base.Config.get_retry_backoff()
      :exponential

  """
  @spec get_retry_backoff() :: retry_backoff()
  def get_retry_backoff do
    case get_env_var(["VAULTX_RETRY_BACKOFF"]) do
      nil -> Application.get_env(:vaultx, :retry_backoff, @default_config.retry_backoff)
      "linear" -> :linear
      "exponential" -> :exponential
      _ -> @default_config.retry_backoff
    end
  end

  @doc """
  Gets the maximum retry delay in milliseconds.

  ## Examples

      iex> Vaultx.Base.Config.get_max_retry_delay()
      30000

  """
  @spec get_max_retry_delay() :: pos_integer()
  def get_max_retry_delay do
    get_env_var_as_integer(["VAULTX_MAX_RETRY_DELAY"]) ||
      Application.get_env(:vaultx, :max_retry_delay) ||
      @default_config.max_retry_delay
  end

  @doc """
  Gets the CA certificates directory to be loaded into :cacerts.
  Returns nil if not configured.
  """
  @spec get_cacerts_dir() :: String.t() | nil
  def get_cacerts_dir do
    get_env_var(["VAULTX_CACERTS_DIR"]) ||
      Application.get_env(:vaultx, :cacerts_dir) ||
      @default_config.cacerts_dir
  end

  @doc """
  Gets the client certificate path.

  ## Examples

      iex> Vaultx.Base.Config.get_client_cert()
      "/path/to/client.pem"

  """
  @spec get_client_cert() :: String.t() | nil
  def get_client_cert do
    get_env_var(["VAULTX_CLIENT_CERT", "VAULT_CLIENT_CERT"]) ||
      Application.get_env(:vaultx, :client_cert) ||
      @default_config.client_cert
  end

  @doc """
  Gets the client private key path.

  ## Examples

      iex> Vaultx.Base.Config.get_client_key()
      "/path/to/client-key.pem"

  """
  @spec get_client_key() :: String.t() | nil
  def get_client_key do
    get_env_var(["VAULTX_CLIENT_KEY", "VAULT_CLIENT_KEY"]) ||
      Application.get_env(:vaultx, :client_key) ||
      @default_config.client_key
  end

  @doc """
  Gets the TLS server name for SNI.

  ## Examples

      iex> Vaultx.Base.Config.get_tls_server_name()
      "vault.example.com"

  """
  @spec get_tls_server_name() :: String.t() | nil
  def get_tls_server_name do
    get_env_var(["VAULTX_TLS_SERVER_NAME"]) ||
      Application.get_env(:vaultx, :tls_server_name) ||
      @default_config.tls_server_name
  end

  @doc """
  Gets the minimum TLS version.

  ## Examples

      iex> Vaultx.Base.Config.get_tls_min_version()
      "1.2"

  """
  @spec get_tls_min_version() :: String.t()
  def get_tls_min_version do
    case get_env_var(["VAULTX_TLS_MIN_VERSION"]) do
      nil -> Application.get_env(:vaultx, :tls_min_version, @default_config.tls_min_version)
      version when version in ["1.2", "1.3"] -> version
      _ -> @default_config.tls_min_version
    end
  end

  @doc """
  Validates the current configuration.

  ## Examples

      iex> Vaultx.Base.Config.validate()
      :ok

      iex> Vaultx.Base.Config.validate()
      {:error, [url: "is required"]}

  """
  @spec validate() :: :ok | {:error, keyword()}
  def validate do
    config = get()

    case NimbleOptions.validate(Map.to_list(config), @config_schema) do
      {:ok, _} -> :ok
      # coveralls-ignore-next-line
      {:error, error} -> {:error, [error]}
    end
  rescue
    error -> {:error, [config_error: Exception.message(error)]}
  end

  @doc """
  Performs comprehensive configuration validation and returns detailed diagnostics.

  ## Examples

      iex> Vaultx.Base.Config.diagnose()
      %{
        valid: true,
        warnings: [],
        errors: [],
        recommendations: []
      }

  """
  @spec diagnose() :: %{
          valid: boolean(),
          warnings: [String.t()],
          errors: [String.t()],
          recommendations: [String.t()]
        }
  def diagnose do
    warnings = []
    errors = []
    recommendations = []

    # Basic validation first, so we can return structured diagnostics even if config is invalid
    {errors, warnings, recommendations} =
      case validate() do
        :ok -> {errors, warnings, recommendations}
        {:error, validation_errors} -> {validation_errors ++ errors, warnings, recommendations}
      end

    # If validation already reported errors, return early without calling get()/further checks
    if errors != [] do
      %{
        valid: false,
        warnings: warnings,
        errors: errors,
        recommendations: recommendations
      }
    else
      config = get()

      # Security checks
      {warnings, recommendations} = check_security_config(config, warnings, recommendations)

      # Performance checks
      {warnings, recommendations} = check_performance_config(config, warnings, recommendations)

      # SSL/TLS checks
      {warnings, recommendations} = check_ssl_config(config, warnings, recommendations)

      %{
        valid: Enum.empty?(errors),
        warnings: warnings,
        errors: errors,
        recommendations: recommendations
      }
    end
  end

  @doc """
  Prints a human-readable configuration summary.

  ## Examples

      iex> Vaultx.Base.Config.print_summary()
      # Outputs formatted configuration summary

  """
  @spec print_summary() :: :ok
  def print_summary do
    config = get()

    IO.puts("\n=== VaultX Configuration Summary ===")
    IO.puts("URL: #{config.url}")
    IO.puts("Namespace: #{config.namespace || "none"}")
    IO.puts("SSL Verify: #{config.ssl_verify}")
    IO.puts("Timeout: #{config.timeout}ms")
    IO.puts("Retry Attempts: #{config.retry_attempts}")
    IO.puts("Pool Size: #{config.pool_size}")
    IO.puts("Logger Level: #{config.logger_level}")
    IO.puts("Telemetry: #{config.telemetry_enabled}")

    if config.token do
      token_preview = String.slice(config.token, 0, 10) <> "..."
      IO.puts("Token: #{token_preview}")
    else
      IO.puts("Token: not configured")
    end

    IO.puts("=====================================\n")
    :ok
  end

  @doc """
  Gets the maximum idle time for pool connections in milliseconds.

  ## Examples

      iex> Vaultx.Base.Config.get_pool_max_idle_time()
      300000

  """
  @spec get_pool_max_idle_time() :: pos_integer()
  def get_pool_max_idle_time do
    get_env_var_as_integer(["VAULTX_POOL_MAX_IDLE_TIME"]) ||
      Application.get_env(:vaultx, :pool_max_idle_time) ||
      @default_config.pool_max_idle_time
  end

  @doc """
  Gets the audit logging enabled setting.

  ## Examples

      iex> Vaultx.Base.Config.get_audit_enabled()
      false

  """
  @spec get_audit_enabled() :: boolean()
  def get_audit_enabled do
    case get_env_var_as_boolean(["VAULTX_AUDIT_ENABLED"]) do
      nil -> Application.get_env(:vaultx, :audit_enabled, @default_config.audit_enabled)
      audit_enabled -> audit_enabled
    end
  end

  @doc """
  Gets the metrics collection enabled setting.

  ## Examples

      iex> Vaultx.Base.Config.get_metrics_enabled()
      true

  """
  @spec get_metrics_enabled() :: boolean()
  def get_metrics_enabled do
    case get_env_var_as_boolean(["VAULTX_METRICS_ENABLED"]) do
      nil -> Application.get_env(:vaultx, :metrics_enabled, @default_config.metrics_enabled)
      metrics_enabled -> metrics_enabled
    end
  end

  @doc """
  Gets the rate limiting enabled setting.

  ## Examples

      iex> Vaultx.Base.Config.get_rate_limit_enabled()
      false

  """
  @spec get_rate_limit_enabled() :: boolean()
  def get_rate_limit_enabled do
    case get_env_var_as_boolean(["VAULTX_RATE_LIMIT_ENABLED"]) do
      nil -> Application.get_env(:vaultx, :rate_limit_enabled, @default_config.rate_limit_enabled)
      rate_limit_enabled -> rate_limit_enabled
    end
  end

  @doc """
  Gets the rate limit requests per second.

  ## Examples

      iex> Vaultx.Base.Config.get_rate_limit_requests()
      100

  """
  @spec get_rate_limit_requests() :: pos_integer()
  def get_rate_limit_requests do
    get_env_var_as_integer(["VAULTX_RATE_LIMIT_REQUESTS"]) ||
      Application.get_env(:vaultx, :rate_limit_requests) ||
      @default_config.rate_limit_requests
  end

  @doc """
  Gets the token renewal enabled setting.

  ## Examples

      iex> Vaultx.Base.Config.get_token_renewal_enabled()
      true

  """
  @spec get_token_renewal_enabled() :: boolean()
  def get_token_renewal_enabled do
    case get_env_var_as_boolean(["VAULTX_TOKEN_RENEWAL_ENABLED"]) do
      nil ->
        Application.get_env(
          :vaultx,
          :token_renewal_enabled,
          @default_config.token_renewal_enabled
        )

      token_renewal_enabled ->
        token_renewal_enabled
    end
  end

  @doc """
  Gets the token renewal threshold percentage.

  ## Examples

      iex> Vaultx.Base.Config.get_token_renewal_threshold()
      80

  """
  @spec get_token_renewal_threshold() :: pos_integer()
  def get_token_renewal_threshold do
    get_env_var_as_integer(["VAULTX_TOKEN_RENEWAL_THRESHOLD"]) ||
      Application.get_env(:vaultx, :token_renewal_threshold) ||
      @default_config.token_renewal_threshold
  end

  @doc """
  Gets the rate limit burst size.
  """
  @spec get_rate_limit_burst() :: non_neg_integer()
  def get_rate_limit_burst do
    get_env_var_as_integer(["VAULTX_RATE_LIMIT_BURST"]) ||
      Application.get_env(:vaultx, :rate_limit_burst) ||
      @default_config.rate_limit_burst
  end

  @doc """
  Gets the security headers validation enabled setting.

  ## Examples

      iex> Vaultx.Base.Config.get_security_headers_enabled()
      true

  """
  @spec get_security_headers_enabled() :: boolean()
  def get_security_headers_enabled do
    case get_env_var_as_boolean(["VAULTX_SECURITY_HEADERS_ENABLED"]) do
      nil ->
        Application.get_env(
          :vaultx,
          :security_headers_enabled,
          @default_config.security_headers_enabled
        )

      security_headers_enabled ->
        security_headers_enabled
    end
  end

  @doc false
  def validate_percentage(value) when is_integer(value) and value >= 1 and value <= 99,
    do: {:ok, value}

  def validate_percentage(value),
    do: {:error, "must be an integer between 1 and 99, got: #{inspect(value)}"}

  # Private functions

  defp merge_app_config(config) do
    app_config = Application.get_all_env(:vaultx)

    Enum.reduce(app_config, config, fn {key, value}, acc ->
      if Map.has_key?(acc, key) do
        Map.put(acc, key, value)
      else
        acc
      end
    end)
  end

  defp merge_env_config(config) do
    %{
      config
      | # Core configuration
        url: get_url(),
        token: get_token(),
        namespace: get_namespace(),

        # Network & timeouts
        timeout: get_timeout(),
        connect_timeout: get_connect_timeout(),
        retry_attempts: get_retry_attempts(),
        retry_delay: get_retry_delay(),
        retry_backoff: get_retry_backoff(),
        max_retry_delay: get_max_retry_delay(),

        # SSL/TLS configuration
        ssl_verify: get_ssl_verify(),
        cacert: get_cacert(),
        cacerts_dir: get_cacerts_dir(),
        client_cert: get_client_cert(),
        client_key: get_client_key(),
        tls_server_name: get_tls_server_name(),
        tls_min_version: get_tls_min_version(),

        # Connection pool
        pool_size: get_pool_size(),
        pool_max_idle_time: get_pool_max_idle_time(),

        # Logging & telemetry
        logger_level: get_logger_level(),
        telemetry_enabled: get_telemetry_enabled(),
        audit_enabled: get_audit_enabled(),
        metrics_enabled: get_metrics_enabled(),

        # Security & compliance
        rate_limit_enabled: get_rate_limit_enabled(),
        rate_limit_requests: get_rate_limit_requests(),
        rate_limit_burst: get_rate_limit_burst(),
        token_renewal_enabled: get_token_renewal_enabled(),
        token_renewal_threshold: get_token_renewal_threshold(),
        security_headers_enabled: get_security_headers_enabled()
    }
  end

  defp validate_config!(config) do
    case NimbleOptions.validate(Map.to_list(config), @config_schema) do
      {:ok, validated_config} ->
        Map.new(validated_config)

      {:error, error} ->
        raise Error.new(:configuration_error, "Invalid configuration: #{inspect(error)}")
    end
  end

  defp get_env_var(var_names) when is_list(var_names) do
    Enum.find_value(var_names, &System.get_env/1)
  end

  defp get_env_var_as_integer(var_names) do
    case get_env_var(var_names) do
      nil -> nil
      value -> String.to_integer(value)
    end
  rescue
    ArgumentError -> nil
  end

  defp get_env_var_as_boolean(var_names) do
    case get_env_var(var_names) do
      nil -> nil
      value -> String.downcase(value) in ["true", "1", "yes", "on"]
    end
  end

  # Configuration diagnostic helpers

  defp check_security_config(config, warnings, recommendations) do
    warnings =
      cond do
        not config.ssl_verify and String.starts_with?(config.url, "https://") ->
          ["SSL verification is disabled for HTTPS connection" | warnings]

        String.starts_with?(config.url, "http://") and
            not String.contains?(config.url, "localhost") ->
          ["Using unencrypted HTTP connection to remote server" | warnings]

        true ->
          warnings
      end

    recommendations =
      cond do
        not config.security_headers_enabled ->
          ["Consider enabling security headers validation" | recommendations]

        not config.audit_enabled ->
          ["Consider enabling audit logging for compliance" | recommendations]

        true ->
          recommendations
      end

    {warnings, recommendations}
  end

  defp check_performance_config(config, warnings, recommendations) do
    warnings =
      cond do
        config.timeout > 60_000 ->
          ["Request timeout is very high (#{config.timeout}ms)" | warnings]

        config.pool_size > 50 ->
          ["Connection pool size is very large (#{config.pool_size})" | warnings]

        true ->
          warnings
      end

    recommendations =
      cond do
        config.retry_attempts > 5 ->
          [
            "Consider reducing retry attempts (currently #{config.retry_attempts})"
            | recommendations
          ]

        not config.metrics_enabled ->
          ["Consider enabling metrics for performance monitoring" | recommendations]

        true ->
          recommendations
      end

    {warnings, recommendations}
  end

  defp check_ssl_config(config, warnings, recommendations) do
    warnings =
      cond do
        config.tls_min_version == "1.2" and String.starts_with?(config.url, "https://") ->
          ["Using TLS 1.2 - consider upgrading to TLS 1.3" | warnings]

        true ->
          warnings
      end

    recommendations =
      cond do
        config.ssl_verify and is_nil(config.cacert) and is_nil(config.cacerts_dir) ->
          ["Consider specifying CA certificates for better SSL validation" | recommendations]

        true ->
          recommendations
      end

    {warnings, recommendations}
  end
end
