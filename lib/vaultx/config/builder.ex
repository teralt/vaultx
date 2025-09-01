defmodule Vaultx.Config.Builder do
  @moduledoc """
  Configuration builder for VaultX.

  This module handles the construction of configuration from multiple sources:
  - Default values
  - Application environment
  - System environment variables
  - Runtime overrides

  ## Design Principles

  - Layered Configuration: Multiple sources with clear precedence
  - Environment Awareness: Different defaults per environment
  - Type Safety: Proper type conversion and validation
  - Performance: Efficient configuration building

  """

  @doc """
  Builds the complete configuration from all sources.

  Configuration precedence (highest to lowest):
  1. Runtime overrides
  2. System environment variables
  3. Application environment
  4. Default values

  """
  @spec build() :: map()
  def build do
    # Start with default configuration
    config = get_defaults()

    # Apply application environment settings
    config = merge_app_config(config)

    # Apply environment variables
    config = merge_env_config(config)

    # Basic validation
    validate_required!(config)

    config
  end

  @doc """
  Gets the default configuration for the current environment.
  """
  @spec get_defaults() :: map()
  def get_defaults do
    base_defaults()
    |> Map.merge(environment_defaults())
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  # Base default configuration
  defp base_defaults do
    %{
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
      # Cache configuration
      cache_enabled: true,
      cache_l1_enabled: true,
      cache_l1_max_size: 1000,
      cache_l1_ttl_default: 300_000,
      cache_l1_cleanup_interval: 60_000,
      cache_l2_enabled: false,
      cache_l2_adapter: :ets,
      cache_l2_max_size: 10_000,
      cache_l2_ttl_default: 600_000,
      cache_l2_cleanup_interval: 300_000,
      cache_l3_enabled: false,
      cache_l3_storage_path: "/tmp/vaultx_cache",
      cache_l3_ttl_default: 3_600_000,
      cache_l3_cleanup_interval: 1_800_000,
      cache_l3_encryption: false,
      cache_eviction_policy: :lru,
      cache_max_memory_usage: 100_000_000,
      cache_warming_enabled: false,
      cache_metrics_enabled: true,
      cache_manager_cleanup_interval: 300_000,
      # Security & compliance
      rate_limit_enabled: false,
      rate_limit_requests: 100,
      rate_limit_burst: 10,
      token_renewal_enabled: true,
      token_renewal_threshold: 80,
      security_headers_enabled: true
    }
  end

  # Environment-specific defaults
  defp environment_defaults do
    case Mix.env() do
      :dev -> development_defaults()
      :test -> test_defaults()
      :prod -> production_defaults()
      _ -> production_defaults()
    end
  end

  defp development_defaults do
    %{
      ssl_verify: false,
      logger_level: :debug,
      telemetry_enabled: false,
      audit_enabled: false,
      rate_limit_enabled: false
    }
  end

  defp test_defaults do
    %{
      ssl_verify: false,
      logger_level: :warning,
      telemetry_enabled: false,
      audit_enabled: false,
      rate_limit_enabled: false,
      timeout: 5_000
    }
  end

  defp production_defaults do
    %{
      ssl_verify: true,
      logger_level: :info,
      telemetry_enabled: true,
      audit_enabled: true,
      rate_limit_enabled: true
    }
  end

  # Merge application environment configuration
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

  # Merge system environment variables
  defp merge_env_config(config) do
    %{
      config
      | # Core configuration
        url: get_env_var(["VAULTX_URL", "VAULT_ADDR"]) || config.url,
        token: get_env_var(["VAULTX_TOKEN", "VAULT_TOKEN"]) || config.token,
        namespace: get_env_var(["VAULTX_NAMESPACE", "VAULT_NAMESPACE"]) || config.namespace,
        # Network & timeouts
        timeout: get_env_var_as_integer(["VAULTX_TIMEOUT"]) || config.timeout,
        connect_timeout:
          get_env_var_as_integer(["VAULTX_CONNECT_TIMEOUT"]) || config.connect_timeout,
        retry_attempts:
          get_env_var_as_integer(["VAULTX_RETRY_ATTEMPTS"]) || config.retry_attempts,
        retry_delay: get_env_var_as_integer(["VAULTX_RETRY_DELAY"]) || config.retry_delay,
        # SSL/TLS configuration
        ssl_verify: get_env_var_as_boolean(["VAULTX_SSL_VERIFY"]) || config.ssl_verify,
        cacert: get_env_var(["VAULTX_CACERT"]) || config.cacert,
        cacerts_dir: get_env_var(["VAULTX_CACERTS_DIR"]) || config.cacerts_dir,
        client_cert: get_env_var(["VAULTX_CLIENT_CERT"]) || config.client_cert,
        client_key: get_env_var(["VAULTX_CLIENT_KEY"]) || config.client_key,
        tls_server_name: get_env_var(["VAULTX_TLS_SERVER_NAME"]) || config.tls_server_name,
        tls_min_version: get_env_var(["VAULTX_TLS_MIN_VERSION"]) || config.tls_min_version,
        # Connection pool
        pool_size: get_env_var_as_integer(["VAULTX_POOL_SIZE"]) || config.pool_size,
        pool_max_idle_time:
          get_env_var_as_integer(["VAULTX_POOL_MAX_IDLE_TIME"]) || config.pool_max_idle_time,
        # Logging & telemetry
        logger_level: get_env_var_as_atom(["VAULTX_LOGGER_LEVEL"]) || config.logger_level,
        telemetry_enabled:
          get_env_var_as_boolean(["VAULTX_TELEMETRY_ENABLED"]) || config.telemetry_enabled,
        audit_enabled: get_env_var_as_boolean(["VAULTX_AUDIT_ENABLED"]) || config.audit_enabled,
        metrics_enabled:
          get_env_var_as_boolean(["VAULTX_METRICS_ENABLED"]) || config.metrics_enabled,
        # Cache configuration
        cache_enabled: get_env_var_as_boolean(["VAULTX_CACHE_ENABLED"]) || config.cache_enabled,
        # Security & compliance
        rate_limit_enabled:
          get_env_var_as_boolean(["VAULTX_RATE_LIMIT_ENABLED"]) || config.rate_limit_enabled,
        rate_limit_requests:
          get_env_var_as_integer(["VAULTX_RATE_LIMIT_REQUESTS"]) || config.rate_limit_requests,
        rate_limit_burst:
          get_env_var_as_integer(["VAULTX_RATE_LIMIT_BURST"]) || config.rate_limit_burst,
        token_renewal_enabled:
          get_env_var_as_boolean(["VAULTX_TOKEN_RENEWAL_ENABLED"]) || config.token_renewal_enabled,
        token_renewal_threshold:
          get_env_var_as_integer(["VAULTX_TOKEN_RENEWAL_THRESHOLD"]) ||
            config.token_renewal_threshold,
        security_headers_enabled:
          get_env_var_as_boolean(["VAULTX_SECURITY_HEADERS_ENABLED"]) ||
            config.security_headers_enabled
    }
  end

  # Basic validation of required fields
  defp validate_required!(config) do
    case URI.parse(config.url) do
      %URI{scheme: scheme, host: host} when scheme in ["http", "https"] and not is_nil(host) ->
        config

      _ ->
        raise ArgumentError, "Invalid URL format: #{config.url}"
    end
  end

  # Environment variable helpers
  defp get_env_var(env_vars) when is_list(env_vars) do
    Enum.find_value(env_vars, &System.get_env/1)
  end

  defp get_env_var_as_integer(env_vars) do
    case get_env_var(env_vars) do
      nil ->
        nil

      value when is_binary(value) ->
        case Integer.parse(value) do
          {int_value, ""} -> int_value
          _ -> nil
        end

      value when is_integer(value) ->
        value

      _ ->
        nil
    end
  end

  defp get_env_var_as_boolean(env_vars) do
    case get_env_var(env_vars) do
      nil ->
        nil

      value when is_binary(value) ->
        case String.downcase(value) do
          v when v in ["true", "1", "yes", "on"] -> true
          v when v in ["false", "0", "no", "off"] -> false
          _ -> nil
        end

      value when is_boolean(value) ->
        value

      _ ->
        nil
    end
  end

  defp get_env_var_as_atom(env_vars) do
    case get_env_var(env_vars) do
      nil ->
        nil

      value when is_binary(value) ->
        try do
          String.to_existing_atom(value)
        rescue
          ArgumentError -> nil
        end

      value when is_atom(value) ->
        value

      _ ->
        nil
    end
  end
end
