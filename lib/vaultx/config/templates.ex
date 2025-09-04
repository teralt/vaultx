defmodule Vaultx.Config.Templates do
  @moduledoc """
  Environment-specific configuration template generation for VaultX.

  This module provides intelligent configuration template generation for different
  environments and use cases. Templates are optimized for specific deployment
  scenarios and include best practices for security, performance, and reliability.

  ## Features

  - Environment-Specific Templates: Optimized templates for development, testing, staging, and production
  - Feature-Based Configuration: Templates can be customized based on required features
  - Security Level Adaptation: Different security levels from basic to enterprise-grade
  - Best Practice Integration: Templates incorporate industry best practices
  - Customizable Options: Flexible template generation with customizable parameters

  ## Template Types

  ### Development Templates
  - Optimized for fast iteration and debugging
  - Relaxed security settings for local development
  - Enhanced logging and debugging features
  - Local Vault server configuration

  ### Testing Templates
  - Optimized for automated testing
  - Minimal external dependencies
  - Fast execution and cleanup
  - Mock-friendly configuration

  ### Staging Templates
  - Production-like configuration with safety nets
  - Enhanced monitoring and logging
  - Security settings similar to production
  - Performance testing optimizations

  ### Production Templates
  - Maximum security and reliability
  - Optimized performance settings
  - Comprehensive monitoring and auditing
  - Enterprise-grade security features

  ## Usage

      # Generate production template
      {:ok, template} = Vaultx.Config.Templates.generate(:production)

      # Generate development template with specific features
      {:ok, template} = Vaultx.Config.Templates.generate(:development,
        features: [:cache, :telemetry],
        security_level: :basic
      )

  """

  alias Vaultx.Base.Logger

  @type environment :: :development | :testing | :staging | :production
  @type security_level :: :basic | :enhanced | :enterprise
  @type feature :: :cache | :telemetry | :audit | :metrics | :rate_limiting | :token_renewal

  @type template_options :: [
          features: [feature()],
          security_level: security_level(),
          vault_version: String.t(),
          custom_settings: map()
        ]

  @doc """
  Generates a configuration template for the specified environment.

  ## Parameters

  - `environment` - Target environment (`:development`, `:testing`, `:staging`, `:production`)
  - `opts` - Template generation options

  ## Returns

  Generated configuration template as a map.

  ## Examples

      # Basic production template
      template = Vaultx.Config.Templates.generate(:production)

      # Development template with caching
      template = Vaultx.Config.Templates.generate(:development,
        features: [:cache, :telemetry]
      )

      # Enterprise production template
      template = Vaultx.Config.Templates.generate(:production,
        security_level: :enterprise,
        features: [:cache, :telemetry, :audit, :metrics]
      )

  """
  @spec generate(environment(), template_options()) :: map()
  def generate(environment, opts \\ []) do
    features = Keyword.get(opts, :features, default_features_for_environment(environment))
    security_level = Keyword.get(opts, :security_level, default_security_level(environment))
    custom_settings = Keyword.get(opts, :custom_settings, %{})

    environment
    |> base_template_for_environment()
    |> apply_security_level(security_level)
    |> apply_features(features)
    |> apply_custom_settings(custom_settings)
    |> validate_template()
  end

  @doc """
  Generates multiple templates for comparison or migration planning.

  ## Parameters

  - `environments` - List of environments to generate templates for
  - `opts` - Common template options

  ## Returns

  Map with environment names as keys and templates as values.

  ## Examples

      templates = Vaultx.Config.Templates.generate_multiple(
        [:development, :production],
        features: [:cache, :telemetry]
      )

      dev_template = templates.development
      prod_template = templates.production

  """
  @spec generate_multiple([environment()], template_options()) :: map()
  def generate_multiple(environments, opts \\ []) do
    environments
    |> Enum.map(fn env -> {env, generate(env, opts)} end)
    |> Map.new()
  end

  @doc """
  Generates a migration template from one environment to another.

  This function analyzes the differences between environments and provides
  a template that highlights the changes needed for migration.

  ## Parameters

  - `from_env` - Source environment
  - `to_env` - Target environment
  - `opts` - Template options

  ## Returns

  Migration template with change annotations.

  ## Examples

      migration = Vaultx.Config.Templates.generate_migration(
        :development,
        :production,
        features: [:cache, :audit]
      )

  """
  @spec generate_migration(environment(), environment(), template_options()) :: map()
  def generate_migration(from_env, to_env, opts \\ []) do
    from_template = generate(from_env, opts)
    to_template = generate(to_env, opts)

    %{
      from_environment: from_env,
      to_environment: to_env,
      from_template: from_template,
      to_template: to_template,
      changes: calculate_template_changes(from_template, to_template),
      migration_notes: generate_migration_notes(from_env, to_env)
    }
  end

  # Private template generation functions

  defp base_template_for_environment(:development) do
    %{
      # Core configuration
      url: "http://localhost:8200",
      # Will be set via environment variable
      token: nil,
      namespace: nil,

      # Network & timeouts - relaxed for development
      timeout: 30_000,
      connect_timeout: 10_000,
      retry_attempts: 2,
      retry_delay: 1_000,
      retry_backoff: :linear,
      max_retry_delay: 5_000,

      # SSL/TLS - relaxed for local development
      ssl_verify: false,
      cacert: nil,
      cacerts_dir: nil,
      client_cert: nil,
      client_key: nil,
      tls_server_name: nil,
      tls_min_version: "1.2",

      # Connection pool - small for development
      pool_size: 5,
      pool_max_idle_time: 60_000,

      # Logging & telemetry - verbose for debugging
      logger_level: :debug,
      telemetry_enabled: true,
      audit_enabled: false,
      metrics_enabled: true,

      # Development-specific settings
      environment: :development,
      debug_mode: true,
      hot_reload: true
    }
  end

  defp base_template_for_environment(:testing) do
    %{
      # Core configuration
      url: "http://localhost:8200",
      # Fixed token for testing
      token: "test-token",
      namespace: nil,

      # Network & timeouts - fast for testing
      timeout: 5_000,
      connect_timeout: 2_000,
      retry_attempts: 1,
      retry_delay: 100,
      retry_backoff: :linear,
      max_retry_delay: 1_000,

      # SSL/TLS - disabled for testing
      ssl_verify: false,
      cacert: nil,
      cacerts_dir: nil,
      client_cert: nil,
      client_key: nil,
      tls_server_name: nil,
      tls_min_version: "1.2",

      # Connection pool - minimal for testing
      pool_size: 2,
      pool_max_idle_time: 30_000,

      # Logging & telemetry - minimal for testing
      logger_level: :warn,
      telemetry_enabled: false,
      audit_enabled: false,
      metrics_enabled: false,

      # Testing-specific settings
      environment: :testing,
      test_mode: true,
      cleanup_on_exit: true
    }
  end

  defp base_template_for_environment(:staging) do
    %{
      # Core configuration
      url: "https://vault-staging.company.com:8200",
      # Will be set via environment variable
      token: nil,
      namespace: "staging",

      # Network & timeouts - production-like
      timeout: 15_000,
      connect_timeout: 5_000,
      retry_attempts: 3,
      retry_delay: 1_000,
      retry_backoff: :exponential,
      max_retry_delay: 10_000,

      # SSL/TLS - production-like security
      ssl_verify: true,
      cacert: "/etc/ssl/certs/vault-ca.pem",
      cacerts_dir: "/etc/ssl/certs",
      client_cert: nil,
      client_key: nil,
      tls_server_name: "vault-staging.company.com",
      tls_min_version: "1.2",

      # Connection pool - moderate for staging
      pool_size: 15,
      pool_max_idle_time: 300_000,

      # Logging & telemetry - enhanced monitoring
      logger_level: :info,
      telemetry_enabled: true,
      audit_enabled: true,
      metrics_enabled: true,

      # Staging-specific settings
      environment: :staging,
      monitoring_enhanced: true,
      performance_testing: true
    }
  end

  defp base_template_for_environment(:production) do
    %{
      # Core configuration
      url: "https://vault.company.com:8200",
      # Will be set via environment variable
      token: nil,
      namespace: "production",

      # Network & timeouts - optimized for production
      timeout: 10_000,
      connect_timeout: 3_000,
      retry_attempts: 5,
      retry_delay: 1_000,
      retry_backoff: :exponential,
      max_retry_delay: 30_000,

      # SSL/TLS - maximum security
      ssl_verify: true,
      cacert: "/etc/ssl/certs/vault-ca.pem",
      cacerts_dir: "/etc/ssl/certs",
      client_cert: "/etc/ssl/certs/client.pem",
      client_key: "/etc/ssl/private/client-key.pem",
      tls_server_name: "vault.company.com",
      tls_min_version: "1.2",

      # Connection pool - optimized for production load
      pool_size: 25,
      pool_max_idle_time: 300_000,

      # Logging & telemetry - production monitoring
      logger_level: :info,
      telemetry_enabled: true,
      audit_enabled: true,
      metrics_enabled: true,

      # Production-specific settings
      environment: :production,
      high_availability: true,
      security_hardened: true
    }
  end

  defp default_features_for_environment(:development), do: [:cache, :telemetry]
  defp default_features_for_environment(:testing), do: []
  defp default_features_for_environment(:staging), do: [:cache, :telemetry, :audit, :metrics]

  defp default_features_for_environment(:production),
    do: [:cache, :telemetry, :audit, :metrics, :rate_limiting]

  defp default_security_level(:development), do: :basic
  defp default_security_level(:testing), do: :basic
  defp default_security_level(:staging), do: :enhanced
  defp default_security_level(:production), do: :enterprise

  defp apply_security_level(template, :basic) do
    # Basic security - minimal requirements
    template
    |> Map.merge(%{
      ssl_verify: Map.get(template, :ssl_verify, false),
      tls_min_version: "1.2",
      audit_enabled: false,
      security_level: :basic
    })
  end

  defp apply_security_level(template, :enhanced) do
    # Enhanced security - recommended for staging/production
    template
    |> Map.merge(%{
      ssl_verify: true,
      tls_min_version: "1.2",
      audit_enabled: true,
      security_level: :enhanced,
      # Enhanced security settings
      token_renewal_enabled: true,
      # 5 minutes before expiry
      token_renewal_threshold: 300,
      request_signing: true
    })
  end

  defp apply_security_level(template, :enterprise) do
    # Enterprise security - maximum security for production
    template
    |> Map.merge(%{
      ssl_verify: true,
      # Require TLS 1.3 for enterprise
      tls_min_version: "1.3",
      audit_enabled: true,
      security_level: :enterprise,
      # Enterprise security settings
      token_renewal_enabled: true,
      # 10 minutes before expiry
      token_renewal_threshold: 600,
      request_signing: true,
      mutual_tls: true,
      security_headers: true,
      rate_limiting_enabled: true,
      ip_whitelist_enabled: true,
      # 1 hour
      session_timeout: 3600,
      max_concurrent_sessions: 5
    })
  end

  defp apply_features(template, features) do
    features
    |> Enum.reduce(template, fn feature, acc ->
      apply_feature(acc, feature)
    end)
  end

  defp apply_feature(template, :cache) do
    template
    |> Map.merge(%{
      cache_enabled: true,
      cache_l1_enabled: true,
      cache_l1_max_size:
        case template.environment do
          :development -> 5_000
          :testing -> 1_000
          :staging -> 20_000
          :production -> 50_000
        end,
      cache_l1_ttl_default:
        case template.environment do
          # 5 minutes
          :development -> 300_000
          # 1 minute
          :testing -> 60_000
          # 15 minutes
          :staging -> 900_000
          # 30 minutes
          :production -> 1_800_000
        end,
      cache_l2_enabled: template.environment in [:staging, :production],
      cache_l2_max_size:
        case template.environment do
          :staging -> 100_000
          :production -> 200_000
          _ -> 0
        end,
      cache_l2_ttl_default:
        case template.environment do
          # 1 hour
          :staging -> 3_600_000
          # 2 hours
          :production -> 7_200_000
          _ -> 0
        end
    })
  end

  defp apply_feature(template, :telemetry) do
    template
    |> Map.merge(%{
      telemetry_enabled: true,
      telemetry_metrics: [:request_count, :request_duration, :error_count, :cache_hits],
      telemetry_sampling_rate:
        case template.environment do
          # 100% sampling
          :development -> 1.0
          # 10% sampling
          :testing -> 0.1
          # 50% sampling
          :staging -> 0.5
          # 10% sampling
          :production -> 0.1
        end,
      # 30 seconds
      telemetry_export_interval: 30_000
    })
  end

  defp apply_feature(template, :audit) do
    template
    |> Map.merge(%{
      audit_enabled: true,
      audit_log_level: :info,
      audit_log_format: :json,
      audit_include_request_body: template.environment != :production,
      audit_include_response_body: false,
      audit_retention_days:
        case template.environment do
          :development -> 7
          :testing -> 1
          :staging -> 30
          :production -> 90
        end
    })
  end

  defp apply_feature(template, :metrics) do
    template
    |> Map.merge(%{
      metrics_enabled: true,
      metrics_port: 9090,
      metrics_path: "/metrics",
      metrics_collectors: [:vault_requests, :cache_stats, :connection_pool, :system_metrics],
      metrics_histogram_buckets: [0.1, 0.5, 1.0, 2.5, 5.0, 10.0]
    })
  end

  defp apply_feature(template, :rate_limiting) do
    template
    |> Map.merge(%{
      rate_limiting_enabled: true,
      rate_limit_requests_per_second:
        case template.environment do
          :development -> 100
          :testing -> 50
          :staging -> 500
          :production -> 1000
        end,
      rate_limit_burst_size:
        case template.environment do
          :development -> 20
          :testing -> 10
          :staging -> 100
          :production -> 200
        end,
      # 1 minute
      rate_limit_window_size: 60_000
    })
  end

  defp apply_feature(template, :token_renewal) do
    template
    |> Map.merge(%{
      token_renewal_enabled: true,
      token_renewal_threshold:
        case template.environment do
          # 5 minutes
          :development -> 300
          # 1 minute
          :testing -> 60
          # 10 minutes
          :staging -> 600
          # 15 minutes
          :production -> 900
        end,
      token_renewal_retry_attempts: 3,
      token_renewal_retry_delay: 5_000
    })
  end

  defp apply_feature(template, _unknown_feature) do
    # Ignore unknown features
    template
  end

  defp apply_custom_settings(template, custom_settings) do
    Map.merge(template, custom_settings)
  end

  defp validate_template(template) do
    # Basic template validation
    required_fields = [:url, :timeout, :pool_size, :environment]

    missing_fields =
      required_fields
      |> Enum.filter(fn field -> not Map.has_key?(template, field) end)

    if Enum.empty?(missing_fields) do
      template
    else
      Logger.warn("Template missing required fields: #{inspect(missing_fields)}")
      template
    end
  end

  defp calculate_template_changes(from_template, to_template) do
    all_keys =
      (Map.keys(from_template) ++ Map.keys(to_template))
      |> Enum.uniq()

    all_keys
    |> Enum.map(fn key ->
      from_value = Map.get(from_template, key)
      to_value = Map.get(to_template, key)

      cond do
        from_value == to_value -> nil
        is_nil(from_value) -> {:added, key, to_value}
        is_nil(to_value) -> {:removed, key, from_value}
        true -> {:changed, key, from_value, to_value}
      end
    end)
    |> Enum.reject(&is_nil/1)
  end

  defp generate_migration_notes(:development, :production) do
    [
      "Enable SSL verification and use HTTPS URLs",
      "Configure proper SSL certificates",
      "Enable audit logging for compliance",
      "Increase connection pool size for production load",
      "Set appropriate timeouts for production environment",
      "Enable security features like rate limiting",
      "Configure proper token renewal settings",
      "Set production-appropriate logging levels"
    ]
  end

  defp generate_migration_notes(:development, :staging) do
    [
      "Enable SSL verification",
      "Configure staging SSL certificates",
      "Enable audit logging",
      "Increase connection pool size",
      "Enable telemetry and metrics",
      "Configure appropriate timeouts"
    ]
  end

  defp generate_migration_notes(:staging, :production) do
    [
      "Update SSL certificates for production",
      "Enable enterprise security features",
      "Increase connection pool for production load",
      "Configure production monitoring",
      "Enable rate limiting",
      "Set production token renewal settings"
    ]
  end

  defp generate_migration_notes(_from_env, _to_env) do
    [
      "Review and update environment-specific settings",
      "Verify SSL/TLS configuration",
      "Check timeout and retry settings",
      "Validate security configuration",
      "Test connectivity and performance"
    ]
  end
end
