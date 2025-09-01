defmodule Vaultx.Config.Optimizer do
  @moduledoc """
  Intelligent configuration optimization with performance and security recommendations.

  This module analyzes VaultX configuration and provides intelligent optimization
  suggestions based on best practices, performance patterns, security requirements,
  and environment-specific recommendations.

  ## Features

  - Performance Optimization: Connection pool, timeout, and cache optimization
  - Security Enhancement: Security-focused configuration improvements
  - Environment Adaptation: Environment-specific optimization recommendations
  - Resource Efficiency: Memory and CPU usage optimization suggestions
  - Compliance Alignment: Compliance-focused configuration recommendations

  ## Optimization Categories

  ### Performance Optimization
  - Connection pool sizing and configuration
  - Timeout and retry optimization
  - Cache configuration optimization
  - Network performance improvements

  ### Security Optimization
  - SSL/TLS configuration hardening
  - Authentication method optimization
  - Audit and logging configuration
  - Sensitive data protection

  ### Resource Optimization
  - Memory usage optimization
  - CPU utilization improvements
  - Network bandwidth optimization
  - Storage efficiency improvements

  ## Usage

      # Generate optimization suggestions
      suggestions = Vaultx.Config.Optimizer.generate_suggestions(config)

      # Calculate performance score
      score = Vaultx.Config.Optimizer.calculate_performance_score(config)

      # Prioritize suggestions by impact
      prioritized = Vaultx.Config.Optimizer.prioritize_suggestions(suggestions)

  """

  alias Vaultx.Base.Config

  @type optimization_suggestion :: %{
          type: :performance | :security | :resource | :compliance,
          priority: :low | :medium | :high | :critical,
          category: atom(),
          title: String.t(),
          description: String.t(),
          current_value: any(),
          suggested_value: any(),
          expected_impact: String.t(),
          implementation_effort: :low | :medium | :high,
          config_changes: map()
        }

  @type performance_score :: %{
          overall: float(),
          categories: %{
            connection: float(),
            caching: float(),
            security: float(),
            reliability: float()
          },
          recommendations: [String.t()]
        }

  # Performance thresholds and recommendations
  @optimal_pool_size_range 10..50
  @optimal_timeout_range 10_000..60_000
  @optimal_retry_attempts_range 3..5

  @doc """
  Generates comprehensive optimization suggestions for the given configuration.

  This function analyzes all aspects of the configuration and provides prioritized
  optimization suggestions based on performance, security, and best practices.

  ## Parameters

  - `config` - Configuration map to analyze

  ## Returns

  List of optimization suggestions ordered by priority and impact.

  ## Examples

      config = Vaultx.Base.Config.get()
      suggestions = Vaultx.Config.Optimizer.generate_suggestions(config)

      Enum.each(suggestions, fn suggestion ->
        IO.puts("\#{suggestion.priority}: \#{suggestion.title}")
        IO.puts("Impact: \#{suggestion.expected_impact}")
      end)

  """
  @spec generate_suggestions(Config.t()) :: [optimization_suggestion()]
  def generate_suggestions(config) when is_map(config) do
    [
      generate_performance_suggestions(config),
      generate_security_suggestions(config),
      generate_resource_suggestions(config),
      generate_compliance_suggestions(config),
      generate_environment_suggestions(config)
    ]
    |> List.flatten()
    |> Enum.reject(&is_nil/1)
    |> sort_suggestions_by_priority()
  end

  @doc """
  Calculates a comprehensive performance score for the configuration.

  The score is calculated based on multiple factors including connection efficiency,
  caching effectiveness, security posture, and reliability configuration.

  ## Parameters

  - `config` - Configuration map to score

  ## Returns

  Performance score breakdown with overall score and category scores.

  ## Examples

      config = Vaultx.Base.Config.get()
      score = Vaultx.Config.Optimizer.calculate_performance_score(config)

      IO.puts("Overall Score: \#{score.overall}/100")
      IO.puts("Connection Score: \#{score.categories.connection}/100")

  """
  @spec calculate_performance_score(Config.t()) :: performance_score()
  def calculate_performance_score(config) when is_map(config) do
    connection_score = calculate_connection_score(config)
    caching_score = calculate_caching_score(config)
    security_score = calculate_security_score(config)
    reliability_score = calculate_reliability_score(config)

    overall_score = (connection_score + caching_score + security_score + reliability_score) / 4

    %{
      overall: Float.round(overall_score, 1),
      categories: %{
        connection: Float.round(connection_score, 1),
        caching: Float.round(caching_score, 1),
        security: Float.round(security_score, 1),
        reliability: Float.round(reliability_score, 1)
      },
      recommendations:
        generate_score_recommendations(overall_score, %{
          connection: connection_score,
          caching: caching_score,
          security: security_score,
          reliability: reliability_score
        })
    }
  end

  @doc """
  Prioritizes optimization suggestions based on impact and implementation effort.

  ## Parameters

  - `suggestions` - List of optimization suggestions

  ## Returns

  Prioritized list of suggestions with high-impact, low-effort suggestions first.

  ## Examples

      suggestions = Vaultx.Config.Optimizer.generate_suggestions(config)
      prioritized = Vaultx.Config.Optimizer.prioritize_suggestions(suggestions)

      # Apply top 3 suggestions
      Enum.take(prioritized, 3)
      |> Enum.each(&apply_suggestion/1)

  """
  @spec prioritize_suggestions([optimization_suggestion()]) :: [optimization_suggestion()]
  def prioritize_suggestions(suggestions) when is_list(suggestions) do
    suggestions
    |> Enum.sort_by(
      fn suggestion ->
        priority_weight = priority_to_weight(suggestion.priority)
        effort_weight = effort_to_weight(suggestion.implementation_effort)

        # Higher priority and lower effort get higher scores
        priority_weight - effort_weight
      end,
      :desc
    )
  end

  @doc """
  Calculates the optimization potential based on current configuration analysis.

  ## Parameters

  - `analysis` - Configuration analysis results

  ## Returns

  Optimization potential score and recommendations.

  ## Examples

      {:ok, analysis} = Vaultx.Config.analyze()
      potential = Vaultx.Config.Optimizer.calculate_optimization_potential(analysis)

      IO.puts("Optimization Potential: \#{potential.score}%")

  """
  @spec calculate_optimization_potential(map()) :: map()
  def calculate_optimization_potential(analysis) when is_map(analysis) do
    issues_count = length(analysis.issues || [])
    suggestions_count = length(analysis.suggestions || [])
    security_warnings_count = length(analysis.security_warnings || [])

    # Calculate potential based on number of issues and suggestions
    total_improvements = issues_count + suggestions_count + security_warnings_count

    potential_score =
      cond do
        # Already well optimized
        total_improvements == 0 -> 10
        # Minor optimizations possible
        total_improvements <= 3 -> 25
        # Moderate optimization potential
        total_improvements <= 7 -> 50
        # High optimization potential
        total_improvements <= 15 -> 75
        # Very high optimization potential
        true -> 90
      end

    %{
      score: potential_score,
      total_improvements: total_improvements,
      categories: %{
        issues: issues_count,
        suggestions: suggestions_count,
        security_warnings: security_warnings_count
      },
      recommendation:
        case potential_score do
          score when score <= 25 -> "Configuration is well optimized"
          score when score <= 50 -> "Minor optimizations recommended"
          score when score <= 75 -> "Moderate optimization recommended"
          _ -> "Significant optimization potential identified"
        end
    }
  end

  # Private optimization functions

  defp generate_performance_suggestions(config) do
    [
      suggest_connection_pool_optimization(config),
      suggest_timeout_optimization(config),
      suggest_retry_optimization(config),
      suggest_cache_optimization(config)
    ]
    |> Enum.reject(&is_nil/1)
  end

  defp suggest_connection_pool_optimization(config) do
    pool_size = config.pool_size

    cond do
      pool_size < @optimal_pool_size_range.first ->
        %{
          type: :performance,
          priority: :high,
          category: :connection_pool,
          title: "Increase connection pool size",
          description: "Current pool size (#{pool_size}) is below optimal range",
          current_value: pool_size,
          suggested_value: @optimal_pool_size_range.first,
          expected_impact: "Improved concurrent request handling, reduced connection wait times",
          implementation_effort: :low,
          config_changes: %{pool_size: @optimal_pool_size_range.first}
        }

      pool_size > @optimal_pool_size_range.last ->
        %{
          type: :performance,
          priority: :medium,
          category: :connection_pool,
          title: "Reduce connection pool size",
          description: "Current pool size (#{pool_size}) may consume excessive resources",
          current_value: pool_size,
          suggested_value: @optimal_pool_size_range.last,
          expected_impact: "Reduced memory usage, better resource utilization",
          implementation_effort: :low,
          config_changes: %{pool_size: @optimal_pool_size_range.last}
        }

      true ->
        nil
    end
  end

  defp suggest_timeout_optimization(config) do
    timeout = config.timeout
    connect_timeout = config.connect_timeout

    suggestions = []

    # Check request timeout
    suggestions =
      cond do
        timeout < @optimal_timeout_range.first ->
          [
            %{
              type: :performance,
              priority: :medium,
              category: :timeouts,
              title: "Increase request timeout",
              description: "Current timeout (#{timeout}ms) may cause premature failures",
              current_value: timeout,
              suggested_value: @optimal_timeout_range.first,
              expected_impact: "Reduced timeout errors, better reliability for slow operations",
              implementation_effort: :low,
              config_changes: %{timeout: @optimal_timeout_range.first}
            }
            | suggestions
          ]

        timeout > @optimal_timeout_range.last ->
          [
            %{
              type: :performance,
              priority: :low,
              category: :timeouts,
              title: "Reduce request timeout",
              description: "Current timeout (#{timeout}ms) may cause slow response times",
              current_value: timeout,
              suggested_value: @optimal_timeout_range.last,
              expected_impact: "Faster failure detection, improved user experience",
              implementation_effort: :low,
              config_changes: %{timeout: @optimal_timeout_range.last}
            }
            | suggestions
          ]

        true ->
          suggestions
      end

    # Check connect timeout ratio
    suggestions =
      if connect_timeout && timeout && connect_timeout > timeout * 0.5 do
        [
          %{
            type: :performance,
            priority: :medium,
            category: :timeouts,
            title: "Optimize connect timeout ratio",
            description: "Connect timeout should be 30-50% of request timeout",
            current_value: connect_timeout,
            suggested_value: div(timeout, 3),
            expected_impact: "Better timeout handling, improved connection efficiency",
            implementation_effort: :low,
            config_changes: %{connect_timeout: div(timeout, 3)}
          }
          | suggestions
        ]
      else
        suggestions
      end

    suggestions
  end

  defp suggest_retry_optimization(config) do
    retry_attempts = config.retry_attempts
    retry_delay = config.retry_delay

    cond do
      retry_attempts not in @optimal_retry_attempts_range ->
        optimal_attempts =
          if retry_attempts < @optimal_retry_attempts_range.first do
            @optimal_retry_attempts_range.first
          else
            @optimal_retry_attempts_range.last
          end

        %{
          type: :performance,
          priority: :medium,
          category: :retry,
          title: "Optimize retry attempts",
          description: "Current retry attempts (#{retry_attempts}) not in optimal range",
          current_value: retry_attempts,
          suggested_value: optimal_attempts,
          expected_impact: "Better balance between reliability and performance",
          implementation_effort: :low,
          config_changes: %{retry_attempts: optimal_attempts}
        }

      retry_delay && retry_delay < 500 ->
        %{
          type: :performance,
          priority: :low,
          category: :retry,
          title: "Increase retry delay",
          description: "Very short retry delay may overwhelm the server",
          current_value: retry_delay,
          suggested_value: 1000,
          expected_impact: "Reduced server load, better retry success rate",
          implementation_effort: :low,
          config_changes: %{retry_delay: 1000}
        }

      true ->
        nil
    end
  end

  defp suggest_cache_optimization(config) do
    cache_enabled = Map.get(config, :cache_enabled, false)

    if not cache_enabled do
      %{
        type: :performance,
        priority: :high,
        category: :caching,
        title: "Enable caching for better performance",
        description: "Caching can improve response times by 60-80%",
        current_value: false,
        suggested_value: true,
        expected_impact: "Significantly improved response times, reduced Vault server load",
        implementation_effort: :medium,
        config_changes: %{
          cache_enabled: true,
          cache_l1_enabled: true,
          cache_l1_max_size: 10_000,
          cache_l1_ttl_default: 900_000
        }
      }
    else
      # Cache is enabled, check for optimization opportunities
      l1_size = Map.get(config, :cache_l1_max_size, 0)
      l2_enabled = Map.get(config, :cache_l2_enabled, false)

      cond do
        l1_size < 5_000 ->
          %{
            type: :performance,
            priority: :medium,
            category: :caching,
            title: "Increase L1 cache size",
            description: "Small cache size may result in frequent cache misses",
            current_value: l1_size,
            suggested_value: 10_000,
            expected_impact: "Better cache hit ratio, improved performance",
            implementation_effort: :low,
            config_changes: %{cache_l1_max_size: 10_000}
          }

        not l2_enabled ->
          %{
            type: :performance,
            priority: :medium,
            category: :caching,
            title: "Enable L2 cache for better performance",
            description: "Multi-tier caching can further improve performance",
            current_value: false,
            suggested_value: true,
            expected_impact: "Extended cache coverage, better performance for repeated access",
            implementation_effort: :medium,
            config_changes: %{
              cache_l2_enabled: true,
              cache_l2_max_size: 50_000,
              cache_l2_ttl_default: 3_600_000
            }
          }

        true ->
          nil
      end
    end
  end

  defp generate_security_suggestions(config) do
    [
      suggest_ssl_hardening(config),
      suggest_authentication_improvements(config),
      suggest_audit_enhancements(config)
    ]
    |> Enum.reject(&is_nil/1)
  end

  defp suggest_ssl_hardening(config) do
    url = Map.get(config, :url, "")
    ssl_verify = Map.get(config, :ssl_verify, true)
    tls_version = Map.get(config, :tls_min_version, "1.2")

    cond do
      String.starts_with?(url, "http://") ->
        %{
          type: :security,
          priority: :critical,
          category: :ssl,
          title: "Upgrade to HTTPS",
          description: "HTTP protocol is insecure for production use",
          current_value: "http://",
          suggested_value: "https://",
          expected_impact: "Encrypted communication, protection against eavesdropping",
          implementation_effort: :medium,
          config_changes: %{url: String.replace(url, "http://", "https://")}
        }

      not ssl_verify ->
        %{
          type: :security,
          priority: :high,
          category: :ssl,
          title: "Enable SSL certificate verification",
          description: "SSL verification prevents man-in-the-middle attacks",
          current_value: false,
          suggested_value: true,
          expected_impact: "Protection against certificate-based attacks",
          implementation_effort: :low,
          config_changes: %{ssl_verify: true}
        }

      tls_version not in ["1.2", "1.3"] ->
        %{
          type: :security,
          priority: :medium,
          category: :ssl,
          title: "Upgrade TLS version",
          description: "Use TLS 1.2 or 1.3 for better security",
          current_value: tls_version,
          suggested_value: "1.2",
          expected_impact: "Improved encryption strength, better security posture",
          implementation_effort: :low,
          config_changes: %{tls_min_version: "1.2"}
        }

      true ->
        nil
    end
  end

  defp suggest_authentication_improvements(config) do
    token = Map.get(config, :token)

    cond do
      token && String.starts_with?(token, "s.") ->
        %{
          type: :security,
          priority: :medium,
          category: :authentication,
          title: "Upgrade to service tokens",
          description: "Service tokens (hvs.*) provide better security than legacy tokens",
          current_value: "Legacy token format",
          suggested_value: "Service token format (hvs.*)",
          expected_impact: "Improved token security, better audit trail",
          implementation_effort: :medium,
          config_changes: %{token: "Generate new service token"}
        }

      token && String.length(token) < 20 ->
        %{
          type: :security,
          priority: :high,
          category: :authentication,
          title: "Use stronger authentication token",
          description: "Current token appears weak or for testing only",
          current_value: "Weak token",
          suggested_value: "Strong production token",
          expected_impact: "Better authentication security, reduced breach risk",
          implementation_effort: :medium,
          config_changes: %{token: "Generate strong production token"}
        }

      true ->
        nil
    end
  end

  defp suggest_audit_enhancements(config) do
    audit_enabled = Map.get(config, :audit_enabled, false)
    logger_level = Map.get(config, :logger_level, :info)

    suggestions = []

    # Suggest enabling audit logging
    suggestions =
      if not audit_enabled and production_environment?(config) do
        [
          %{
            type: :security,
            priority: :high,
            category: :audit,
            title: "Enable audit logging",
            description: "Audit logging is essential for security monitoring and compliance",
            current_value: false,
            suggested_value: true,
            expected_impact: "Better security monitoring, compliance readiness",
            implementation_effort: :low,
            config_changes: %{audit_enabled: true}
          }
          | suggestions
        ]
      else
        suggestions
      end

    # Suggest appropriate logging level
    suggestions =
      if logger_level == :debug and production_environment?(config) do
        [
          %{
            type: :security,
            priority: :medium,
            category: :audit,
            title: "Adjust logging level for production",
            description: "Debug logging may expose sensitive information",
            current_value: :debug,
            suggested_value: :info,
            expected_impact: "Reduced sensitive data exposure, better security",
            implementation_effort: :low,
            config_changes: %{logger_level: :info}
          }
          | suggestions
        ]
      else
        suggestions
      end

    suggestions
  end

  defp generate_resource_suggestions(config) do
    [
      suggest_memory_optimization(config),
      suggest_connection_efficiency(config)
    ]
    |> Enum.reject(&is_nil/1)
  end

  defp suggest_memory_optimization(config) do
    cache_enabled = Map.get(config, :cache_enabled, false)
    l1_size = Map.get(config, :cache_l1_max_size, 0)
    l2_size = Map.get(config, :cache_l2_max_size, 0)

    if cache_enabled do
      total_cache_items = l1_size + l2_size

      if total_cache_items > 100_000 do
        %{
          type: :resource,
          priority: :medium,
          category: :memory,
          title: "Optimize cache memory usage",
          description: "Large cache sizes may consume excessive memory",
          current_value: total_cache_items,
          suggested_value: 50_000,
          expected_impact: "Reduced memory usage, better resource efficiency",
          implementation_effort: :low,
          config_changes: %{
            cache_l1_max_size: min(l1_size, 20_000),
            cache_l2_max_size: min(l2_size, 30_000)
          }
        }
      end
    end
  end

  defp suggest_connection_efficiency(config) do
    pool_size = config.pool_size
    timeout = config.timeout

    # Suggest connection pool optimization based on timeout
    if pool_size && timeout && pool_size * 1000 > timeout do
      %{
        type: :resource,
        priority: :low,
        category: :connection,
        title: "Balance pool size with timeout",
        description: "Large pool with short timeout may waste connections",
        current_value: pool_size,
        suggested_value: max(div(timeout, 2000), 5),
        expected_impact: "Better connection utilization, reduced resource waste",
        implementation_effort: :low,
        config_changes: %{pool_size: max(div(timeout, 2000), 5)}
      }
    end
  end

  defp generate_compliance_suggestions(config) do
    if production_environment?(config) do
      [
        suggest_soc2_compliance(config),
        suggest_pci_compliance(config)
      ]
      |> Enum.reject(&is_nil/1)
    else
      []
    end
  end

  defp suggest_soc2_compliance(config) do
    issues = []

    # Check SSL verification
    issues =
      unless Map.get(config, :ssl_verify, false) do
        ["Enable SSL verification" | issues]
      else
        issues
      end

    # Check audit logging
    issues =
      unless Map.get(config, :audit_enabled, false) do
        ["Enable audit logging" | issues]
      else
        issues
      end

    # Check secure protocol
    url = Map.get(config, :url, "")

    issues =
      unless String.starts_with?(url, "https://") do
        ["Use HTTPS protocol" | issues]
      else
        issues
      end

    if not Enum.empty?(issues) do
      %{
        type: :compliance,
        priority: :high,
        category: :soc2,
        title: "Improve SOC2 compliance",
        description: "Address security controls for SOC2 compliance",
        current_value: "Non-compliant",
        suggested_value: "SOC2 compliant",
        expected_impact: "Meet SOC2 security requirements, better audit readiness",
        implementation_effort: :medium,
        config_changes: %{
          ssl_verify: true,
          audit_enabled: true,
          url:
            if(String.starts_with?(url, "http://"),
              do: String.replace(url, "http://", "https://"),
              else: url
            )
        }
      }
    end
  end

  defp suggest_pci_compliance(config) do
    tls_version = Map.get(config, :tls_min_version, "1.2")
    ssl_verify = Map.get(config, :ssl_verify, false)

    if tls_version not in ["1.2", "1.3"] or not ssl_verify do
      %{
        type: :compliance,
        priority: :high,
        category: :pci,
        title: "Improve PCI DSS compliance",
        description: "Strengthen encryption for PCI DSS compliance",
        current_value: "Non-compliant encryption",
        suggested_value: "PCI DSS compliant encryption",
        expected_impact: "Meet PCI DSS encryption requirements",
        implementation_effort: :low,
        config_changes: %{
          tls_min_version: "1.2",
          ssl_verify: true
        }
      }
    end
  end

  defp generate_environment_suggestions(config) do
    env = Mix.env()

    case env do
      :prod -> generate_production_suggestions(config)
      :dev -> generate_development_suggestions(config)
      :test -> generate_test_suggestions(config)
      _ -> []
    end
  end

  defp generate_production_suggestions(config) do
    suggestions = []

    # Suggest production-appropriate settings
    suggestions =
      if Map.get(config, :logger_level, :info) == :debug do
        [
          %{
            type: :performance,
            priority: :medium,
            category: :environment,
            title: "Use production logging level",
            description: "Debug logging not recommended for production",
            current_value: :debug,
            suggested_value: :info,
            expected_impact: "Better performance, reduced log volume",
            implementation_effort: :low,
            config_changes: %{logger_level: :info}
          }
          | suggestions
        ]
      else
        suggestions
      end

    suggestions
  end

  defp generate_development_suggestions(config) do
    suggestions = []

    # Suggest development-friendly settings
    suggestions =
      if not Map.get(config, :cache_enabled, false) do
        [
          %{
            type: :performance,
            priority: :low,
            category: :environment,
            title: "Enable caching for development",
            description: "Caching can speed up development workflows",
            current_value: false,
            suggested_value: true,
            expected_impact: "Faster development iteration, better testing",
            implementation_effort: :low,
            config_changes: %{cache_enabled: true}
          }
          | suggestions
        ]
      else
        suggestions
      end

    suggestions
  end

  defp generate_test_suggestions(_config) do
    # Test environment typically needs minimal optimization
    []
  end

  # Helper function to detect production environment
  defp production_environment?(config) do
    url = Map.get(config, :url, "")
    ssl_verify = Map.get(config, :ssl_verify, false)

    String.contains?(url, "prod") ||
      String.contains?(url, "production") ||
      (String.starts_with?(url, "https://") && ssl_verify)
  end

  # Performance scoring functions

  defp calculate_connection_score(config) do
    pool_size = config.pool_size
    timeout = config.timeout
    connect_timeout = config.connect_timeout

    score = 100.0

    # Pool size scoring
    score =
      cond do
        pool_size in @optimal_pool_size_range -> score
        pool_size < @optimal_pool_size_range.first -> score - 20
        pool_size > @optimal_pool_size_range.last -> score - 10
        true -> score
      end

    # Timeout scoring
    score =
      cond do
        timeout in @optimal_timeout_range -> score
        timeout < @optimal_timeout_range.first -> score - 15
        timeout > @optimal_timeout_range.last -> score - 10
        true -> score
      end

    # Connect timeout ratio scoring
    score =
      if connect_timeout && timeout && connect_timeout > timeout * 0.5 do
        score - 10
      else
        score
      end

    max(score, 0.0)
  end

  defp calculate_caching_score(config) do
    cache_enabled = Map.get(config, :cache_enabled, false)

    if not cache_enabled do
      # Low score for no caching
      20.0
    else
      score = 100.0

      l1_enabled = Map.get(config, :cache_l1_enabled, false)
      l2_enabled = Map.get(config, :cache_l2_enabled, false)
      l1_size = Map.get(config, :cache_l1_max_size, 0)

      # L1 cache scoring
      score = if not l1_enabled, do: score - 20, else: score

      # L2 cache bonus
      score = if l2_enabled, do: score + 10, else: score

      # Cache size scoring
      score =
        cond do
          l1_size >= 10_000 -> score
          l1_size >= 5_000 -> score - 10
          l1_size > 0 -> score - 20
          true -> score - 30
        end

      max(score, 0.0)
    end
  end

  defp calculate_security_score(config) do
    score = 100.0
    url = Map.get(config, :url, "")
    ssl_verify = Map.get(config, :ssl_verify, true)
    tls_version = Map.get(config, :tls_min_version, "1.2")
    audit_enabled = Map.get(config, :audit_enabled, false)

    # Protocol scoring
    score = if String.starts_with?(url, "http://"), do: score - 40, else: score

    # SSL verification scoring
    score = if not ssl_verify, do: score - 30, else: score

    # TLS version scoring
    score =
      case tls_version do
        "1.3" -> score + 5
        "1.2" -> score
        _ -> score - 20
      end

    # Audit logging scoring
    score = if not audit_enabled and production_environment?(config), do: score - 15, else: score

    max(score, 0.0)
  end

  defp calculate_reliability_score(config) do
    retry_attempts = config.retry_attempts
    retry_delay = config.retry_delay
    timeout = config.timeout

    score = 100.0

    # Retry attempts scoring
    score =
      if retry_attempts in @optimal_retry_attempts_range do
        score
      else
        score - 15
      end

    # Retry delay scoring
    score =
      if retry_delay && retry_delay >= 500 do
        score
      else
        score - 10
      end

    # Timeout configuration scoring
    score =
      if retry_attempts && retry_delay && timeout do
        total_retry_time = retry_attempts * retry_delay
        if total_retry_time > timeout, do: score - 20, else: score
      else
        score
      end

    max(score, 0.0)
  end

  defp generate_score_recommendations(overall_score, category_scores) do
    recommendations = []

    recommendations =
      if overall_score < 70 do
        ["Configuration needs significant optimization" | recommendations]
      else
        recommendations
      end

    recommendations =
      if category_scores.connection < 70 do
        ["Optimize connection pool and timeout settings" | recommendations]
      else
        recommendations
      end

    recommendations =
      if category_scores.caching < 70 do
        ["Enable or optimize caching configuration" | recommendations]
      else
        recommendations
      end

    recommendations =
      if category_scores.security < 70 do
        ["Strengthen security configuration" | recommendations]
      else
        recommendations
      end

    recommendations =
      if category_scores.reliability < 70 do
        ["Improve retry and timeout configuration" | recommendations]
      else
        recommendations
      end

    if Enum.empty?(recommendations) do
      ["Configuration is well optimized"]
    else
      recommendations
    end
  end

  # Utility functions

  defp sort_suggestions_by_priority(suggestions) do
    priority_order = %{critical: 4, high: 3, medium: 2, low: 1}

    Enum.sort_by(
      suggestions,
      fn suggestion ->
        Map.get(priority_order, suggestion.priority, 0)
      end,
      :desc
    )
  end

  defp priority_to_weight(priority) do
    case priority do
      :critical -> 100
      :high -> 75
      :medium -> 50
      :low -> 25
    end
  end

  defp effort_to_weight(effort) do
    case effort do
      :low -> 10
      :medium -> 25
      :high -> 50
    end
  end
end
