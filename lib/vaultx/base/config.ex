defmodule Vaultx.Base.Config do
  @moduledoc """
  Simplified configuration interface for VaultX.

  This module provides a clean, backward-compatible interface to the modern
  configuration system. All functionality is delegated to the specialized
  configuration modules for better maintainability.

  ## Design Philosophy

  - **Delegation**: All functionality delegates to modern config system
  - **Backward Compatibility**: Maintains existing API for legacy code
  - **Simplicity**: No duplicate logic, single source of truth
  - **Performance**: Direct delegation without overhead

  ## Configuration Sources

  Configuration is resolved in the following priority order:
  1. Environment variables (highest priority)
  2. Application configuration
  3. Default values (lowest priority)

  ## Usage Examples

      # Get complete configuration
      config = Vaultx.Base.Config.get()

      # Get specific values
      url = Vaultx.Base.Config.get_url()
      token = Vaultx.Base.Config.get_token()

      # Get multiple values efficiently
      %{url: url, timeout: timeout} = Vaultx.Base.Config.get_values([:url, :timeout])

  """

  alias Vaultx.Base.{Error, Logger}
  alias Vaultx.Config

  require Logger

  # Type definitions for backward compatibility
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
          # Cache configuration
          cache_enabled: boolean(),
          # Security & compliance
          rate_limit_enabled: boolean(),
          rate_limit_requests: pos_integer(),
          rate_limit_burst: non_neg_integer(),
          token_renewal_enabled: boolean(),
          token_renewal_threshold: pos_integer(),
          security_headers_enabled: boolean()
        }

  # ============================================================================
  # Primary Configuration API
  # ============================================================================

  @doc """
  Gets the complete configuration with all resolved values.

  This function delegates to the modern configuration system.

  ## Examples

      iex> config = Vaultx.Base.Config.get()
      iex> config.url
      "https://vault.example.com:8200"

  """
  @spec get() :: t()
  def get do
    # Delegate directly to Config module
    Config.get()
  end

  @doc """
  Gets configuration using the modern system with comprehensive validation.

  This is the preferred method for new code.
  """
  @spec get_modern() :: {:ok, t()} | {:error, Error.t()}
  def get_modern do
    # Delegate to Config with error handling
    try do
      config = Config.get()
      {:ok, config}
    rescue
      error ->
        {:error, Error.from_exception(error)}
    end
  end

  @doc """
  Gets a specific configuration value by key.

  This delegates to the modern configuration system for better performance
  and type safety.
  """
  @spec get_value(atom(), any()) :: any()
  def get_value(key, default \\ nil) do
    Config.get_value(key, default)
  end

  @doc """
  Gets multiple configuration values efficiently.

  This is more efficient than multiple get_value/2 calls.
  """
  @spec get_values([atom()]) :: %{atom() => any()}
  def get_values(keys) when is_list(keys) do
    Config.get_values(keys)
  end

  # ============================================================================
  # Backward Compatibility API - Individual Getters
  # ============================================================================

  @doc "Gets the Vault server URL."
  @spec get_url() :: String.t()
  def get_url, do: get_value(:url)

  @doc "Gets the authentication token."
  @spec get_token() :: String.t() | nil
  def get_token, do: get_value(:token)

  @doc "Gets the request timeout in milliseconds."
  @spec get_timeout() :: pos_integer()
  def get_timeout, do: get_value(:timeout)

  @doc "Gets the number of retry attempts."
  @spec get_retry_attempts() :: non_neg_integer()
  def get_retry_attempts, do: get_value(:retry_attempts)

  @doc "Gets the retry delay in milliseconds."
  @spec get_retry_delay() :: pos_integer()
  def get_retry_delay, do: get_value(:retry_delay)

  @doc "Gets whether SSL verification is enabled."
  @spec get_ssl_verify() :: boolean()
  def get_ssl_verify, do: get_value(:ssl_verify)

  @doc "Gets the CA certificate file path."
  @spec get_cacert() :: String.t() | nil
  def get_cacert, do: get_value(:cacert)

  @doc "Gets the Vault namespace."
  @spec get_namespace() :: String.t() | nil
  def get_namespace, do: get_value(:namespace)

  @doc "Gets the connection timeout in milliseconds."
  @spec get_connect_timeout() :: pos_integer()
  def get_connect_timeout, do: get_value(:connect_timeout)

  @doc "Gets the retry backoff strategy."
  @spec get_retry_backoff() :: retry_backoff()
  def get_retry_backoff, do: get_value(:retry_backoff)

  @doc "Gets the maximum retry delay in milliseconds."
  @spec get_max_retry_delay() :: pos_integer()
  def get_max_retry_delay, do: get_value(:max_retry_delay)

  @doc "Gets the CA certificates directory."
  @spec get_cacerts_dir() :: String.t() | nil
  def get_cacerts_dir, do: get_value(:cacerts_dir)

  @doc "Gets the client certificate file path."
  @spec get_client_cert() :: String.t() | nil
  def get_client_cert, do: get_value(:client_cert)

  @doc "Gets the client private key file path."
  @spec get_client_key() :: String.t() | nil
  def get_client_key, do: get_value(:client_key)

  @doc "Gets the TLS server name for verification."
  @spec get_tls_server_name() :: String.t() | nil
  def get_tls_server_name, do: get_value(:tls_server_name)

  @doc "Gets the minimum TLS version."
  @spec get_tls_min_version() :: String.t()
  def get_tls_min_version, do: get_value(:tls_min_version)

  @doc "Gets the connection pool size."
  @spec get_pool_size() :: pos_integer()
  def get_pool_size, do: get_value(:pool_size)

  @doc "Gets the pool maximum idle time in milliseconds."
  @spec get_pool_max_idle_time() :: pos_integer()
  def get_pool_max_idle_time, do: get_value(:pool_max_idle_time)

  @doc "Gets the logger level."
  @spec get_logger_level() :: atom()
  def get_logger_level, do: get_value(:logger_level)

  @doc "Gets whether telemetry is enabled."
  @spec get_telemetry_enabled() :: boolean()
  def get_telemetry_enabled, do: get_value(:telemetry_enabled)

  @doc "Gets whether audit logging is enabled."
  @spec get_audit_enabled() :: boolean()
  def get_audit_enabled, do: get_value(:audit_enabled)

  @doc "Gets whether metrics collection is enabled."
  @spec get_metrics_enabled() :: boolean()
  def get_metrics_enabled, do: get_value(:metrics_enabled)

  @doc "Gets whether caching is enabled."
  @spec get_cache_enabled() :: boolean()
  def get_cache_enabled, do: get_value(:cache_enabled)

  @doc "Gets whether rate limiting is enabled."
  @spec get_rate_limit_enabled() :: boolean()
  def get_rate_limit_enabled, do: get_value(:rate_limit_enabled)

  @doc "Gets the rate limit requests per second."
  @spec get_rate_limit_requests() :: pos_integer()
  def get_rate_limit_requests, do: get_value(:rate_limit_requests)

  @doc "Gets the rate limit burst size."
  @spec get_rate_limit_burst() :: non_neg_integer()
  def get_rate_limit_burst, do: get_value(:rate_limit_burst)

  @doc "Gets whether token renewal is enabled."
  @spec get_token_renewal_enabled() :: boolean()
  def get_token_renewal_enabled, do: get_value(:token_renewal_enabled)

  @doc "Gets the token renewal threshold percentage."
  @spec get_token_renewal_threshold() :: pos_integer()
  def get_token_renewal_threshold, do: get_value(:token_renewal_threshold)

  @doc "Gets whether security headers are enabled."
  @spec get_security_headers_enabled() :: boolean()
  def get_security_headers_enabled, do: get_value(:security_headers_enabled)

  # ============================================================================
  # Convenience Functions
  # ============================================================================

  @doc """
  Gets retry configuration as a map.
  """
  @spec get_retry_config() :: %{
          attempts: non_neg_integer(),
          delay: pos_integer(),
          backoff: retry_backoff(),
          max_delay: pos_integer()
        }
  def get_retry_config do
    get_values([:retry_attempts, :retry_delay, :retry_backoff, :max_retry_delay])
    |> Map.new(fn
      {:retry_attempts, v} -> {:attempts, v}
      {:retry_delay, v} -> {:delay, v}
      {:retry_backoff, v} -> {:backoff, v}
      {:max_retry_delay, v} -> {:max_delay, v}
    end)
  end

  @doc """
  Gets pool configuration as a map.
  """
  @spec get_pool_config() :: %{
          size: pos_integer(),
          max_idle_time: pos_integer()
        }
  def get_pool_config do
    get_values([:pool_size, :pool_max_idle_time])
    |> Map.new(fn
      {:pool_size, v} -> {:size, v}
      {:pool_max_idle_time, v} -> {:max_idle_time, v}
    end)
  end

  @doc """
  Checks if SSL/TLS is properly configured.
  """
  @spec ssl_configured?() :: boolean()
  def ssl_configured? do
    url = get_url()

    case URI.parse(url) do
      %URI{scheme: "https"} -> true
      _ -> false
    end
  end

  @doc """
  Checks if authentication is configured.
  """
  @spec auth_configured?() :: boolean()
  def auth_configured? do
    not is_nil(get_token())
  end

  @doc """
  Checks if a specific feature is enabled.
  """
  @spec feature_enabled?(atom()) :: boolean()
  def feature_enabled?(feature) when is_atom(feature) do
    Config.feature_enabled?(feature)
  end

  @doc """
  Gets the status of all features.
  """
  @spec features_status() :: %{
          enabled: [atom()],
          disabled: [atom()],
          recommendations: [String.t()]
        }
  def features_status do
    Config.features_status()
  end

  @doc """
  Gets a list of enabled features.
  """
  @spec enabled_features() :: [atom()]
  def enabled_features do
    features_status().enabled
  end
end
