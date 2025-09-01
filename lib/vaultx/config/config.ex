defmodule Vaultx.Config do
  @moduledoc """
  Modern configuration management system for VaultX.

  This module provides the main interface to the configuration system,
  delegating to specialized modules for specific functionality.

  ## Architecture

  - Config: Main configuration interface (this module)
  - Builder: Configuration building and environment merging
  - Validator: Configuration validation and error checking
  - Optimizer: Performance and security optimization suggestions
  - Diagnostics: Health monitoring and diagnostics

  ## Usage Examples

      # Get configuration
      config = Vaultx.Config.get()

      # Get specific values
      url = Vaultx.Config.get_value(:url)

      # Validate configuration
      :ok = Vaultx.Config.validate()

      # Get health status
      status = Vaultx.Config.health_status()

  """

  alias Vaultx.Base.Logger
  alias Vaultx.Config.{Builder, Diagnostics, Optimizer, Validator}

  @type config_analysis :: %{
          valid: boolean(),
          issues: [map()],
          suggestions: [map()],
          performance_score: float(),
          security_score: float(),
          connectivity_status: atom(),
          environment_compatibility: map()
        }

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Gets the complete configuration.

  This is the primary configuration access method that provides a clean,
  validated configuration map.
  """
  @spec get() :: map()
  def get do
    try do
      # Delegate to Builder module
      Builder.build()
    rescue
      error ->
        Logger.error("Configuration loading failed", error: Exception.message(error))
        Builder.get_defaults()
    end
  end

  @doc """
  Gets a specific configuration value by key.

  ## Examples

      iex> Vaultx.Config.get_value(:url)
      "https://vault.example.com:8200"

      iex> Vaultx.Config.get_value(:timeout, 60_000)
      30000

  """
  @spec get_value(atom(), any()) :: any()
  def get_value(key, default \\ nil) do
    try do
      config = get()
      Map.get(config, key, default)
    rescue
      error ->
        Logger.warn("Failed to get configuration value for #{key}",
          error: Exception.message(error)
        )

        default
    end
  end

  @doc """
  Gets multiple configuration values efficiently.

  ## Examples

      iex> Vaultx.Config.get_values([:url, :timeout, :ssl_verify])
      %{url: "https://vault.example.com:8200", timeout: 30000, ssl_verify: true}

  """
  @spec get_values([atom()]) :: %{atom() => any()}
  def get_values(keys) when is_list(keys) do
    try do
      config = get()
      Map.take(config, keys)
    rescue
      error ->
        Logger.warn("Failed to get multiple configuration values",
          error: Exception.message(error)
        )

        Map.new(keys, fn key -> {key, nil} end)
    end
  end

  @doc """
  Validates the current configuration.

  ## Examples

      iex> Vaultx.Config.validate()
      :ok

      iex> Vaultx.Config.validate()
      {:error, ["URL is required", "Invalid timeout value"]}

  """
  @spec validate() :: :ok | {:error, [String.t()]}
  def validate do
    try do
      config = get()
      # Delegate to Validator module
      Validator.validate_basic(config)
    rescue
      error ->
        {:error, ["Configuration validation failed: #{Exception.message(error)}"]}
    end
  end

  @doc """
  Performs comprehensive configuration analysis.

  ## Examples

      iex> {:ok, analysis} = Vaultx.Config.analyze()
      iex> analysis.valid
      true

  """
  @spec analyze() :: {:ok, config_analysis()}
  def analyze do
    try do
      config = get()

      # Use real validation from Validator module
      validation_issues = Validator.validate_comprehensive(config)

      # Use real performance scoring from Optimizer module
      performance_score_data = Optimizer.calculate_performance_score(config)

      # Use real optimization suggestions from Optimizer module
      suggestions = Optimizer.generate_suggestions(config)

      # Determine if configuration is valid (no critical errors)
      critical_errors = Enum.filter(validation_issues, &(&1.severity == :critical))
      valid = Enum.empty?(critical_errors)

      {:ok,
       %{
         valid: valid,
         issues: validation_issues,
         suggestions: suggestions,
         performance_score: performance_score_data.overall,
         security_score: performance_score_data.categories.security,
         connectivity_status: :skipped,
         environment_compatibility: %{
           mix_env: Mix.env(),
           elixir_version: System.version(),
           otp_version: System.otp_release()
         }
       }}
    rescue
      error ->
        Logger.error("Configuration analysis failed", error: Exception.message(error))

        {:ok,
         %{
           valid: false,
           issues: [
             %{
               type: :error,
               severity: :critical,
               message: "Analysis failed: #{Exception.message(error)}"
             }
           ],
           suggestions: [],
           performance_score: 50.0,
           security_score: 50.0,
           connectivity_status: :error,
           environment_compatibility: %{}
         }}
    end
  end

  @doc """
  Gets the configuration health status.

  This provides a quick health assessment without complex analysis.

  ## Examples

      iex> Vaultx.Config.get_health_status()
      :healthy

  """
  @spec get_health_status() :: :healthy | :degraded | :unhealthy | :critical
  def get_health_status do
    health_status()
  end

  @doc """
  Validates and provides optimization recommendations.

  ## Examples

      iex> {:ok, result} = Vaultx.Config.validate_and_optimize()
      iex> result.optimization_potential
      :low

  """
  @spec validate_and_optimize() :: {:ok, map()}
  def validate_and_optimize do
    # analyze() always returns {:ok, analysis}, so we can pattern match directly
    {:ok, analysis} = analyze()

    # Use real optimization potential calculation from Optimizer module
    optimization_potential = Optimizer.calculate_optimization_potential(analysis)

    {:ok,
     %{
       valid: analysis.valid,
       issues: analysis.issues,
       suggestions: analysis.suggestions,
       performance_score: analysis.performance_score,
       security_score: analysis.security_score,
       connectivity_status: analysis.connectivity_status,
       environment_compatibility: analysis.environment_compatibility,
       optimization_potential: optimization_potential.score,
       performance_impact: determine_performance_impact(optimization_potential),
       estimated_improvement: optimization_potential.recommendation
     }}
  end

  @doc """
  Provides backward-compatible diagnose function for legacy code.

  This function converts the modern analysis format to the legacy format
  expected by existing code.

  ## Examples

      iex> Vaultx.Config.diagnose()
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
    # analyze() always returns {:ok, analysis}, so we can pattern match directly
    {:ok, analysis} = analyze()

    %{
      valid: analysis.valid,
      warnings: extract_warnings_from_issues(analysis.issues),
      errors: extract_errors_from_issues(analysis.issues),
      recommendations: extract_recommendations_from_suggestions(analysis.suggestions)
    }
  end

  @doc """
  Modern feature management with intelligent analysis.

  This provides enhanced feature detection and recommendations.
  """
  @spec feature_enabled?(atom()) :: boolean()
  def feature_enabled?(feature) when is_atom(feature) do
    # Map feature names to configuration keys
    config_key =
      case feature do
        :telemetry -> :telemetry_enabled
        :audit -> :audit_enabled
        :metrics -> :metrics_enabled
        :cache -> :cache_enabled
        :rate_limit -> :rate_limit_enabled
        :token_renewal -> :token_renewal_enabled
        :security_headers -> :security_headers_enabled
        _ -> feature
      end

    get_value(config_key, false)
  end

  @doc """
  Gets comprehensive feature status with recommendations.
  """
  @spec features_status() :: %{
          enabled: [atom()],
          disabled: [atom()],
          recommendations: [String.t()]
        }
  def features_status do
    all_features = [:telemetry, :logger, :retry, :ssl_verify, :cache, :rate_limit]

    enabled = Enum.filter(all_features, &feature_enabled?/1)
    disabled = all_features -- enabled

    # Generate recommendations based on environment and configuration
    recommendations = generate_feature_recommendations(enabled, disabled)

    %{
      enabled: enabled,
      disabled: disabled,
      recommendations: recommendations
    }
  end

  # ============================================================================
  # Private Helper Functions
  # ============================================================================

  defp determine_performance_impact(optimization_potential) do
    cond do
      optimization_potential.score >= 75 -> :high
      optimization_potential.score >= 50 -> :medium
      optimization_potential.score >= 25 -> :low
      true -> :minimal
    end
  end

  defp extract_warnings_from_issues(issues) do
    issues
    |> Enum.filter(&(&1.type == :warn))
    |> Enum.map(& &1.message)
  end

  defp extract_errors_from_issues(issues) do
    issues
    |> Enum.filter(&(&1.type == :error))
    |> Enum.map(& &1.message)
  end

  defp extract_recommendations_from_suggestions(suggestions) do
    suggestions
    |> Enum.map(&(&1.description || &1.title))
    |> Enum.reject(&is_nil/1)
  end

  defp generate_feature_recommendations(enabled, _disabled) do
    recommendations = []

    # Recommend telemetry for production
    recommendations =
      if :telemetry not in enabled and Mix.env() == :prod do
        ["Enable telemetry for production monitoring" | recommendations]
      else
        recommendations
      end

    # Recommend SSL verification
    recommendations =
      if :ssl_verify not in enabled do
        ["Enable SSL verification for security" | recommendations]
      else
        recommendations
      end

    # Recommend caching for performance
    recommendations =
      if :cache not in enabled do
        ["Enable caching for better performance" | recommendations]
      else
        recommendations
      end

    recommendations
  end

  # ============================================================================
  # Private Functions - Analysis Helpers
  # ============================================================================

  # ============================================================================
  # Private Functions - Feature and Health Status
  # ============================================================================

  @doc """
  Checks if a configuration key exists and has a non-nil value.
  """
  @spec has_value?(atom()) :: boolean()
  def has_value?(key) do
    case get_value(key) do
      nil -> false
      _ -> true
    end
  end

  @doc """
  Provides a comprehensive health check of the configuration system.
  """
  @spec health_status() :: :healthy | :degraded | :unhealthy | :critical
  def health_status do
    # Use real health check from Diagnostics module
    health_result = Diagnostics.check_system_health()
    health_result.status
  end
end
