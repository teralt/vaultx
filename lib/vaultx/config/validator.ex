defmodule Vaultx.Config.Validator do
  @moduledoc """
  Advanced configuration validation with comprehensive error reporting.

  This module provides intelligent configuration validation that goes beyond
  basic type checking to include security analysis, performance validation,
  compatibility checks, and best practice recommendations.

  ## Features

  - Comprehensive Validation: Deep validation of all configuration aspects
  - Security Analysis: Security-focused configuration validation
  - Performance Validation: Performance impact analysis
  - Compatibility Checks: Version and feature compatibility validation
  - Best Practice Recommendations: Industry best practice validation

  ## Validation Categories

  ### Core Configuration
  - URL format and accessibility validation
  - Authentication configuration validation
  - Network and timeout configuration validation

  ### Security Configuration
  - SSL/TLS configuration security analysis
  - Authentication method security validation
  - Sensitive data exposure prevention

  ### Performance Configuration
  - Connection pool optimization validation
  - Cache configuration performance analysis
  - Timeout and retry configuration optimization

  ### Compatibility Configuration
  - Vault version compatibility checks
  - Feature availability validation
  - Environment-specific configuration validation

  ## Usage

      # Comprehensive validation
      issues = Vaultx.Config.Validator.validate_comprehensive(config)

      # Security-focused validation
      warnings = Vaultx.Config.Validator.check_security_configuration(config)

      # Compatibility validation
      compatibility = Vaultx.Config.Validator.check_compatibility(config)

  """

  alias Vaultx.Base.{Config, Logger}

  @type validation_issue :: %{
          type: :error | :warning | :info,
          category: atom(),
          field: String.t(),
          message: String.t(),
          suggestion: String.t() | nil,
          severity: :low | :medium | :high | :critical
        }

  @type security_warning :: %{
          type: :security_warning,
          category: atom(),
          message: String.t(),
          recommendation: String.t(),
          severity: :low | :medium | :high | :critical,
          compliance_impact: [String.t()]
        }

  @type compatibility_result :: %{
          vault_version_compatible: boolean(),
          feature_compatibility: map(),
          environment_compatibility: map(),
          deprecation_warnings: [String.t()]
        }

  # Validation rules and thresholds
  @min_timeout 1_000
  @max_timeout 300_000
  @min_pool_size 1
  @max_pool_size 100
  @min_retry_attempts 0
  @max_retry_attempts 10

  @secure_tls_versions ["1.2", "1.3"]

  @doc """
  Performs comprehensive configuration validation.

  This function validates all aspects of the configuration including core settings,
  security configuration, performance settings, and compatibility requirements.

  ## Parameters

  - `config` - Configuration map to validate

  ## Returns

  List of validation issues, empty list if configuration is valid.

  ## Examples

      config = Vaultx.Base.Config.get()
      issues = Vaultx.Config.Validator.validate_comprehensive(config)

      if Enum.empty?(issues) do
        IO.puts("Configuration is valid")
      else
        Enum.each(issues, fn issue ->
          IO.puts("\#{issue.severity}: \#{issue.message}")
        end)
      end

  """
  @spec validate_comprehensive(Config.t()) :: [validation_issue()]
  def validate_comprehensive(config) when is_map(config) do
    [
      validate_core_configuration(config),
      validate_network_configuration(config),
      validate_ssl_configuration(config),
      validate_authentication_configuration(config),
      validate_performance_configuration(config),
      validate_cache_configuration(config),
      validate_logging_configuration(config)
    ]
    |> List.flatten()
    |> Enum.reject(&is_nil/1)
  end

  @doc """
  Performs security-focused configuration validation.

  This function specifically validates security-related configuration settings
  and identifies potential security risks or compliance issues.

  ## Parameters

  - `config` - Configuration map to validate

  ## Returns

  List of security warnings and recommendations.

  ## Examples

      config = Vaultx.Base.Config.get()
      warnings = Vaultx.Config.Validator.check_security_configuration(config)

      Enum.each(warnings, fn warning ->
        IO.puts("Security Warning: \#{warning.message}")
        IO.puts("Recommendation: \#{warning.recommendation}")
      end)

  """
  @spec check_security_configuration(Config.t()) :: [security_warning()]
  def check_security_configuration(config) when is_map(config) do
    [
      check_protocol_security(config),
      check_ssl_security(config),
      check_authentication_security(config),
      check_sensitive_data_exposure(config),
      check_audit_configuration(config),
      check_compliance_requirements(config)
    ]
    |> List.flatten()
    |> Enum.reject(&is_nil/1)
  end

  @doc """
  Checks configuration compatibility with Vault versions and features.

  ## Parameters

  - `config` - Configuration map to validate

  ## Returns

  Compatibility analysis results.

  ## Examples

      config = Vaultx.Base.Config.get()
      compatibility = Vaultx.Config.Validator.check_compatibility(config)

      unless compatibility.vault_version_compatible do
        IO.puts("Warning: Configuration may not be compatible with target Vault version")
      end

  """
  @spec check_compatibility(Config.t()) :: compatibility_result()
  def check_compatibility(config) when is_map(config) do
    %{
      vault_version_compatible: check_vault_version_compatibility(config),
      feature_compatibility: check_feature_compatibility(config),
      environment_compatibility: check_environment_compatibility(config),
      deprecation_warnings: check_deprecation_warnings(config)
    }
  end

  # Private validation functions

  defp validate_core_configuration(config) do
    [
      validate_url(config.url),
      validate_namespace(config.namespace),
      validate_required_fields(config)
    ]
    |> Enum.reject(&is_nil/1)
  end

  defp validate_url(url) when is_binary(url) do
    case URI.parse(url) do
      %URI{scheme: scheme, host: host} when scheme in ["http", "https"] and not is_nil(host) ->
        if String.starts_with?(url, "http://") do
          %{
            type: :warning,
            category: :security,
            field: "url",
            message: "Using HTTP instead of HTTPS is not recommended for production",
            suggestion: "Use HTTPS for secure communication",
            severity: :high
          }
        end

      _ ->
        %{
          type: :error,
          category: :core,
          field: "url",
          message: "Invalid Vault URL format",
          suggestion: "Use format: https://vault.example.com:8200",
          severity: :critical
        }
    end
  end

  defp validate_url(_), do: nil

  defp validate_namespace(nil), do: nil

  defp validate_namespace(namespace) when is_binary(namespace) do
    if String.match?(namespace, ~r/^[a-zA-Z0-9_-]+$/) do
      nil
    else
      %{
        type: :error,
        category: :core,
        field: "namespace",
        message: "Invalid namespace format",
        suggestion: "Use alphanumeric characters, hyphens, and underscores only",
        severity: :medium
      }
    end
  end

  defp validate_required_fields(config) do
    required_fields = [:url]

    missing_fields =
      required_fields
      |> Enum.filter(fn field ->
        value = Map.get(config, field)
        is_nil(value) or (is_binary(value) and String.trim(value) == "")
      end)

    if Enum.empty?(missing_fields) do
      nil
    else
      %{
        type: :error,
        category: :core,
        field: "required_fields",
        message: "Missing required configuration fields: #{Enum.join(missing_fields, ", ")}",
        suggestion: "Provide values for all required fields",
        severity: :critical
      }
    end
  end

  defp validate_network_configuration(config) do
    [
      validate_timeout(config.timeout, "timeout"),
      validate_timeout(config.connect_timeout, "connect_timeout"),
      validate_retry_attempts(config.retry_attempts),
      validate_pool_size(config.pool_size)
    ]
    |> Enum.reject(&is_nil/1)
  end

  defp validate_timeout(timeout, field_name) when is_integer(timeout) do
    cond do
      timeout < @min_timeout ->
        %{
          type: :warning,
          category: :performance,
          field: field_name,
          message: "#{field_name} is very low (#{timeout}ms), may cause premature timeouts",
          suggestion: "Consider increasing to at least #{@min_timeout}ms",
          severity: :medium
        }

      timeout > @max_timeout ->
        %{
          type: :warning,
          category: :performance,
          field: field_name,
          message: "#{field_name} is very high (#{timeout}ms), may cause slow responses",
          suggestion: "Consider reducing to under #{@max_timeout}ms",
          severity: :low
        }

      true ->
        nil
    end
  end

  defp validate_timeout(_, _), do: nil

  defp validate_retry_attempts(attempts) when is_integer(attempts) do
    cond do
      attempts < @min_retry_attempts ->
        %{
          type: :error,
          category: :core,
          field: "retry_attempts",
          message: "retry_attempts cannot be negative",
          suggestion: "Set to 0 or positive integer",
          severity: :high
        }

      attempts > @max_retry_attempts ->
        %{
          type: :warning,
          category: :performance,
          field: "retry_attempts",
          message: "Very high retry attempts (#{attempts}) may cause long delays",
          suggestion: "Consider reducing to #{@max_retry_attempts} or less",
          severity: :medium
        }

      true ->
        nil
    end
  end

  defp validate_retry_attempts(_), do: nil

  defp validate_pool_size(size) when is_integer(size) do
    cond do
      size < @min_pool_size ->
        %{
          type: :error,
          category: :performance,
          field: "pool_size",
          message: "pool_size must be at least #{@min_pool_size}",
          suggestion: "Increase pool_size to handle concurrent requests",
          severity: :high
        }

      size > @max_pool_size ->
        %{
          type: :warning,
          category: :performance,
          field: "pool_size",
          message: "Very large pool_size (#{size}) may consume excessive resources",
          suggestion: "Consider reducing to #{@max_pool_size} or less",
          severity: :low
        }

      true ->
        nil
    end
  end

  defp validate_pool_size(_), do: nil

  defp validate_ssl_configuration(config) do
    [
      validate_ssl_verify(config.ssl_verify, config.url),
      validate_tls_version(config.tls_min_version),
      validate_ssl_certificates(config)
    ]
    |> Enum.reject(&is_nil/1)
  end

  defp validate_ssl_verify(false, url) do
    if String.starts_with?(url || "", "https://") do
      %{
        type: :warning,
        category: :security,
        field: "ssl_verify",
        message: "SSL verification is disabled for HTTPS connection",
        suggestion: "Enable SSL verification for production environments",
        severity: :high
      }
    end
  end

  defp validate_ssl_verify(_, _), do: nil

  defp validate_tls_version(version) when is_binary(version) do
    if version in @secure_tls_versions do
      nil
    else
      %{
        type: :warning,
        category: :security,
        field: "tls_min_version",
        message: "TLS version #{version} may not be secure",
        suggestion: "Use TLS 1.2 or 1.3 for better security",
        severity: :medium
      }
    end
  end

  defp validate_tls_version(_), do: nil

  defp validate_ssl_certificates(config) do
    # Validate certificate file paths if provided
    cert_fields = [:cacert, :client_cert, :client_key]

    cert_fields
    |> Enum.map(fn field ->
      case Map.get(config, field) do
        nil ->
          nil

        path when is_binary(path) ->
          if File.exists?(path) do
            nil
          else
            %{
              type: :error,
              category: :security,
              field: to_string(field),
              message: "Certificate file not found: #{path}",
              suggestion: "Verify the certificate file path exists and is readable",
              severity: :high
            }
          end

        _ ->
          nil
      end
    end)
    |> Enum.reject(&is_nil/1)
  end

  defp validate_authentication_configuration(config) do
    [
      validate_token_configuration(config.token),
      validate_auth_method_configuration(config)
    ]
    |> Enum.reject(&is_nil/1)
  end

  defp validate_token_configuration(nil), do: nil

  defp validate_token_configuration(token) when is_binary(token) do
    cond do
      String.starts_with?(token, "hvs.") ->
        # Vault service token format
        if String.length(token) < 20 do
          %{
            type: :warning,
            category: :security,
            field: "token",
            message: "Token appears to be too short for a valid Vault service token",
            suggestion: "Verify token format and validity",
            severity: :medium
          }
        end

      String.starts_with?(token, "s.") ->
        # Legacy Vault token format
        %{
          type: :warning,
          category: :security,
          field: "token",
          message: "Using legacy token format, consider upgrading to service tokens",
          suggestion: "Use hvs.* format tokens for better security",
          severity: :low
        }

      String.length(token) < 10 ->
        %{
          type: :error,
          category: :security,
          field: "token",
          message: "Token is too short to be valid",
          suggestion: "Provide a valid Vault token",
          severity: :critical
        }

      true ->
        nil
    end
  end

  defp validate_auth_method_configuration(config) do
    # Check if both token and auth method are configured
    if config.token && Map.has_key?(config, :auth_method) do
      %{
        type: :info,
        category: :authentication,
        field: "auth_method",
        message: "Both token and auth_method configured, token will take precedence",
        suggestion: "Use either token or auth_method, not both",
        severity: :low
      }
    end
  end

  defp validate_performance_configuration(config) do
    [
      validate_connection_pool_performance(config),
      validate_timeout_performance(config),
      validate_retry_performance(config)
    ]
    |> Enum.reject(&is_nil/1)
  end

  defp validate_connection_pool_performance(config) do
    pool_size = config.pool_size
    timeout = config.timeout

    # Check if pool size is appropriate for timeout
    if pool_size && timeout && pool_size < 5 && timeout > 30_000 do
      %{
        type: :warning,
        category: :performance,
        field: "pool_size",
        message: "Small pool size with high timeout may cause request queuing",
        suggestion: "Increase pool_size or reduce timeout for better performance",
        severity: :medium
      }
    end
  end

  defp validate_timeout_performance(config) do
    connect_timeout = config.connect_timeout
    request_timeout = config.timeout

    # Connect timeout should be less than request timeout
    if connect_timeout && request_timeout && connect_timeout >= request_timeout do
      %{
        type: :warning,
        category: :performance,
        field: "connect_timeout",
        message: "Connect timeout should be less than request timeout",
        suggestion: "Set connect_timeout to be 30-50% of timeout value",
        severity: :medium
      }
    end
  end

  defp validate_retry_performance(config) do
    retry_attempts = config.retry_attempts
    retry_delay = config.retry_delay
    timeout = config.timeout

    # Check if retry configuration is reasonable
    if retry_attempts && retry_delay && timeout do
      total_retry_time = retry_attempts * retry_delay

      if total_retry_time > timeout do
        %{
          type: :warning,
          category: :performance,
          field: "retry_delay",
          message: "Total retry time exceeds request timeout",
          suggestion: "Reduce retry_delay or retry_attempts to fit within timeout",
          severity: :medium
        }
      end
    end
  end

  defp validate_cache_configuration(config) do
    cache_fields = [
      :cache_enabled,
      :cache_l1_enabled,
      :cache_l2_enabled,
      :cache_l3_enabled,
      :cache_l1_max_size,
      :cache_l2_max_size,
      :cache_l1_ttl_default,
      :cache_l2_ttl_default
    ]

    # Only validate if cache configuration is present
    if Enum.any?(cache_fields, &Map.has_key?(config, &1)) do
      [
        validate_cache_size_configuration(config),
        validate_cache_ttl_configuration(config),
        validate_cache_layer_configuration(config)
      ]
      |> Enum.reject(&is_nil/1)
    else
      []
    end
  end

  defp validate_cache_size_configuration(config) do
    l1_size = Map.get(config, :cache_l1_max_size, 0)
    l2_size = Map.get(config, :cache_l2_max_size, 0)

    # L2 cache should typically be larger than L1
    if l1_size > 0 && l2_size > 0 && l1_size >= l2_size do
      %{
        type: :warning,
        category: :performance,
        field: "cache_l2_max_size",
        message: "L2 cache size should typically be larger than L1 cache size",
        suggestion: "Increase L2 cache size or reduce L1 cache size",
        severity: :low
      }
    end
  end

  defp validate_cache_ttl_configuration(config) do
    l1_ttl = Map.get(config, :cache_l1_ttl_default, 0)
    l2_ttl = Map.get(config, :cache_l2_ttl_default, 0)

    # L2 cache TTL should typically be longer than L1
    if l1_ttl > 0 && l2_ttl > 0 && l1_ttl >= l2_ttl do
      %{
        type: :warning,
        category: :performance,
        field: "cache_l2_ttl_default",
        message: "L2 cache TTL should typically be longer than L1 cache TTL",
        suggestion: "Increase L2 TTL or reduce L1 TTL for better cache hierarchy",
        severity: :low
      }
    end
  end

  defp validate_cache_layer_configuration(config) do
    l1_enabled = Map.get(config, :cache_l1_enabled, false)
    l2_enabled = Map.get(config, :cache_l2_enabled, false)
    l3_enabled = Map.get(config, :cache_l3_enabled, false)

    # Warn if higher-level caches are enabled without lower levels
    cond do
      l3_enabled && !l2_enabled ->
        %{
          type: :warning,
          category: :performance,
          field: "cache_l3_enabled",
          message: "L3 cache enabled without L2 cache may not be optimal",
          suggestion: "Enable L2 cache for better cache hierarchy",
          severity: :low
        }

      l2_enabled && !l1_enabled ->
        %{
          type: :warning,
          category: :performance,
          field: "cache_l2_enabled",
          message: "L2 cache enabled without L1 cache may not be optimal",
          suggestion: "Enable L1 cache for better performance",
          severity: :low
        }

      true ->
        nil
    end
  end

  defp validate_logging_configuration(config) do
    logger_level = Map.get(config, :logger_level, :info)
    audit_enabled = Map.get(config, :audit_enabled, false)

    issues = []

    # Check if debug logging is enabled in production-like settings
    issues =
      if logger_level == :debug && production_environment?(config) do
        [
          %{
            type: :warning,
            category: :security,
            field: "logger_level",
            message: "Debug logging enabled in production environment",
            suggestion:
              "Use :info or :warn level for production to avoid sensitive data exposure",
            severity: :medium
          }
          | issues
        ]
      else
        issues
      end

    # Recommend audit logging for production
    issues =
      if !audit_enabled && production_environment?(config) do
        [
          %{
            type: :info,
            category: :compliance,
            field: "audit_enabled",
            message: "Audit logging is disabled in production environment",
            suggestion: "Enable audit logging for compliance and security monitoring",
            severity: :low
          }
          | issues
        ]
      else
        issues
      end

    issues
  end

  # Helper function to detect production environment
  defp production_environment?(config) do
    url = Map.get(config, :url, "")
    ssl_verify = Map.get(config, :ssl_verify, false)

    # Heuristics to detect production environment
    String.contains?(url, "prod") ||
      String.contains?(url, "production") ||
      (String.starts_with?(url, "https://") && ssl_verify)
  end

  # Security validation functions

  defp check_protocol_security(config) do
    url = Map.get(config, :url, "")

    if String.starts_with?(url, "http://") do
      [
        %{
          type: :security_warning,
          category: :protocol,
          message: "Using insecure HTTP protocol for Vault communication",
          recommendation: "Use HTTPS protocol for secure communication",
          severity: :critical,
          compliance_impact: ["SOC2", "PCI DSS", "HIPAA"]
        }
      ]
    else
      []
    end
  end

  defp check_ssl_security(config) do
    warnings = []

    # Check SSL verification
    warnings =
      if !Map.get(config, :ssl_verify, true) do
        [
          %{
            type: :security_warning,
            category: :ssl,
            message: "SSL certificate verification is disabled",
            recommendation: "Enable SSL verification for production environments",
            severity: :high,
            compliance_impact: ["SOC2", "PCI DSS"]
          }
          | warnings
        ]
      else
        warnings
      end

    # Check TLS version
    tls_version = Map.get(config, :tls_min_version, "1.2")

    warnings =
      if tls_version not in @secure_tls_versions do
        [
          %{
            type: :security_warning,
            category: :ssl,
            message: "Insecure TLS version configured: #{tls_version}",
            recommendation: "Use TLS 1.2 or 1.3 for better security",
            severity: :medium,
            compliance_impact: ["PCI DSS"]
          }
          | warnings
        ]
      else
        warnings
      end

    warnings
  end

  defp check_authentication_security(config) do
    warnings = []
    token = Map.get(config, :token)

    # Check for weak or test tokens
    warnings =
      if token && String.length(token) < 20 do
        [
          %{
            type: :security_warning,
            category: :authentication,
            message: "Authentication token appears to be weak or for testing",
            recommendation: "Use strong, production-grade authentication tokens",
            severity: :high,
            compliance_impact: ["SOC2", "GDPR"]
          }
          | warnings
        ]
      else
        warnings
      end

    # Check for root token usage (if detectable)
    warnings =
      if token && String.starts_with?(token, "root") do
        [
          %{
            type: :security_warning,
            category: :authentication,
            message: "Root token usage detected",
            recommendation: "Use service tokens with limited privileges instead of root tokens",
            severity: :critical,
            compliance_impact: ["SOC2", "PCI DSS", "HIPAA"]
          }
          | warnings
        ]
      else
        warnings
      end

    warnings
  end

  defp check_sensitive_data_exposure(config) do
    warnings = []

    # Check if sensitive fields might be logged
    logger_level = Map.get(config, :logger_level, :info)

    warnings =
      if logger_level == :debug do
        [
          %{
            type: :security_warning,
            category: :data_exposure,
            message: "Debug logging enabled may expose sensitive configuration data",
            recommendation: "Use info or warn level logging in production",
            severity: :medium,
            compliance_impact: ["GDPR", "HIPAA"]
          }
          | warnings
        ]
      else
        warnings
      end

    warnings
  end

  defp check_audit_configuration(config) do
    warnings = []
    audit_enabled = Map.get(config, :audit_enabled, false)

    warnings =
      if !audit_enabled && production_environment?(config) do
        [
          %{
            type: :security_warning,
            category: :audit,
            message: "Audit logging is disabled in production environment",
            recommendation: "Enable audit logging for security monitoring and compliance",
            severity: :medium,
            compliance_impact: ["SOC2", "PCI DSS", "HIPAA"]
          }
          | warnings
        ]
      else
        warnings
      end

    warnings
  end

  defp check_compliance_requirements(config) do
    warnings = []

    # Check for SOC2 compliance requirements
    warnings =
      if production_environment?(config) do
        issues = []

        # SSL verification required
        issues =
          unless Map.get(config, :ssl_verify, false) do
            ["SSL verification disabled" | issues]
          else
            issues
          end

        # Audit logging required
        issues =
          unless Map.get(config, :audit_enabled, false) do
            ["Audit logging disabled" | issues]
          else
            issues
          end

        # Secure protocol required
        url = Map.get(config, :url, "")

        issues =
          unless String.starts_with?(url, "https://") do
            ["Insecure protocol used" | issues]
          else
            issues
          end

        if !Enum.empty?(issues) do
          [
            %{
              type: :security_warning,
              category: :compliance,
              message: "Configuration may not meet SOC2 compliance requirements",
              recommendation: "Address the following issues: #{Enum.join(issues, ", ")}",
              severity: :high,
              compliance_impact: ["SOC2"]
            }
            | warnings
          ]
        else
          warnings
        end
      else
        warnings
      end

    warnings
  end

  # Compatibility checking functions

  defp check_vault_version_compatibility(config) do
    # For now, assume compatibility unless specific incompatible features are detected
    # This could be enhanced to check against known Vault version requirements

    namespace = Map.get(config, :namespace)

    # Namespaces require Vault Enterprise
    if namespace && String.trim(namespace) != "" do
      # This is a heuristic - we can't know the actual Vault version
      # but we can warn about Enterprise features
      Logger.debug("Configuration uses Vault Enterprise features (namespace)")
    end

    true
  end

  defp check_feature_compatibility(config) do
    compatibility = %{}

    # Check cache feature compatibility
    cache_enabled = Map.get(config, :cache_enabled, false)

    compatibility =
      Map.put(compatibility, :cache, %{
        supported: true,
        notes: if(cache_enabled, do: "Cache enabled", else: "Cache disabled")
      })

    # Check telemetry compatibility
    telemetry_enabled = Map.get(config, :telemetry_enabled, false)

    compatibility =
      Map.put(compatibility, :telemetry, %{
        supported: true,
        notes: if(telemetry_enabled, do: "Telemetry enabled", else: "Telemetry disabled")
      })

    compatibility
  end

  defp check_environment_compatibility(config) do
    # Check if configuration is suitable for current environment
    env = Mix.env()

    case env do
      :prod ->
        issues = []

        # Production should use HTTPS
        url = Map.get(config, :url, "")

        issues =
          unless String.starts_with?(url, "https://") do
            ["HTTP protocol not recommended for production" | issues]
          else
            issues
          end

        # Production should have SSL verification
        issues =
          unless Map.get(config, :ssl_verify, false) do
            ["SSL verification should be enabled in production" | issues]
          else
            issues
          end

        %{
          production: %{
            suitable: Enum.empty?(issues),
            issues: issues
          }
        }

      :dev ->
        %{
          development: %{
            suitable: true,
            notes: "Development environment configuration"
          }
        }

      :test ->
        %{
          test: %{
            suitable: true,
            notes: "Test environment configuration"
          }
        }

      _ ->
        %{
          unknown: %{
            suitable: true,
            notes: "Unknown environment: #{env}"
          }
        }
    end
  end

  defp check_deprecation_warnings(config) do
    warnings = []

    # Check for legacy token format
    token = Map.get(config, :token)

    warnings =
      if token && String.starts_with?(token, "s.") do
        [
          "Legacy token format (s.*) is deprecated, use service tokens (hvs.*)" | warnings
        ]
      else
        warnings
      end

    # Check for deprecated configuration keys (currently none defined)
    deprecated_keys = []

    # Use reduce instead of each to properly accumulate warnings
    Enum.reduce(deprecated_keys, warnings, fn key, acc_warnings ->
      if Map.has_key?(config, key) do
        ["Configuration key '#{key}' is deprecated" | acc_warnings]
      else
        acc_warnings
      end
    end)
  end
end
