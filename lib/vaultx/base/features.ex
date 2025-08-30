defmodule Vaultx.Base.Features do
  @moduledoc """
  Feature flag management for Vaultx HashiCorp Vault client.

  This module provides centralized control over optional features in Vaultx,
  enabling fine-grained performance tuning and functionality control. Features
  can be toggled via application configuration or environment variables.

  ## Design Goals

  - Performance: Optional features can be disabled for maximum performance
  - Flexibility: Runtime feature toggling without code changes
  - Observability: Clear visibility into enabled/disabled features
  - Safety: Secure defaults with opt-in for advanced features

  ## Available Features

  - `:telemetry` - Telemetry events and metrics collection
  - `:logger` - Structured logging with security sanitization
  - `:retry` - Automatic retry logic with exponential backoff
  - `:ssl_verify` - SSL certificate verification (security critical)
  - `:audit` - Security audit logging for compliance

  ## Performance Optimization

  When features are disabled, they provide zero overhead:
  - Disabled telemetry: No event processing or handler calls
  - Disabled logging: No log formatting or output
  - Disabled retry: No retry logic or delays

  ## Configuration

      # Application configuration
      config :vaultx,
        telemetry_enabled: true,
        logger_level: :info,        # :none disables logging
        retry_attempts: 3,          # 0 disables retry
        ssl_verify: true,
        audit_enabled: true

      # Environment variables
      export VAULTX_TELEMETRY_ENABLED=true
      export VAULTX_LOGGER_LEVEL=info
      export VAULTX_RETRY_ATTEMPTS=3

  ## Examples

      # Check if a feature is enabled
      if Vaultx.Base.Features.enabled?(:telemetry) do
        emit_telemetry_event()
      end

      # Get all feature statuses
      status = Vaultx.Base.Features.status()

      # Check if running in performance mode (all features disabled)
      if Vaultx.Base.Features.performance_mode?() do
        # Maximum performance configuration
      end
  """

  alias Vaultx.Base.Config

  @type feature ::
          :telemetry
          | :logger
          | :retry
          | :ssl_verify
          | :audit

  @type feature_config :: %{
          telemetry: boolean(),
          logger: boolean(),
          retry: boolean(),
          ssl_verify: boolean(),
          audit: boolean()
        }

  @doc """
  Returns the status of all features.

  ## Examples

      iex> Vaultx.Base.Features.status()
      %{
        telemetry: true,
        logger: true,
        retry: true,
        ssl_verify: true,
        audit: true
      }

  """
  @spec status() :: feature_config()
  def status do
    %{
      telemetry: enabled?(:telemetry),
      logger: enabled?(:logger),
      retry: enabled?(:retry),
      ssl_verify: enabled?(:ssl_verify),
      audit: enabled?(:audit)
    }
  end

  @doc """
  Checks if a specific feature is enabled.

  ## Examples

      iex> Vaultx.Base.Features.enabled?(:telemetry)
      true

      iex> Vaultx.Base.Features.enabled?(:logger)
      false

  """
  @spec enabled?(feature()) :: boolean()
  def enabled?(feature) when is_atom(feature) do
    case feature do
      :telemetry -> Config.get_telemetry_enabled()
      :logger -> Config.get_logger_level() != :none
      :retry -> Config.get_retry_attempts() > 0
      :ssl_verify -> Config.get_ssl_verify()
      :audit -> get_audit_enabled()
      _ -> false
    end
  end

  def enabled?(_feature) do
    false
  end

  @doc """
  Enables one or more features.

  ## Examples

      Vaultx.Base.Features.enable(:telemetry)
      Vaultx.Base.Features.enable([:telemetry, :logger])

  """
  @spec enable(feature() | [feature()]) :: :ok
  def enable(feature) when is_atom(feature) do
    enable([feature])
  end

  def enable(features) when is_list(features) do
    current_features = Application.get_env(:vaultx, :features, [])

    new_features =
      Enum.reduce(features, current_features, fn feature, acc ->
        Keyword.put(acc, feature, true)
      end)

    Application.put_env(:vaultx, :features, new_features)
    :ok
  end

  @doc """
  Disables one or more features.

  ## Examples

      Vaultx.Base.Features.disable(:telemetry)
      Vaultx.Base.Features.disable([:telemetry, :logger])

  """
  @spec disable(feature() | [feature()]) :: :ok
  def disable(feature) when is_atom(feature) do
    disable([feature])
  end

  def disable(features) when is_list(features) do
    current_features = Application.get_env(:vaultx, :features, [])

    new_features =
      Enum.reduce(features, current_features, fn feature, acc ->
        Keyword.put(acc, feature, false)
      end)

    Application.put_env(:vaultx, :features, new_features)
    :ok
  end

  @doc """
  Toggles one or more features.

  ## Examples

      Vaultx.Base.Features.toggle(:telemetry)
      Vaultx.Base.Features.toggle([:telemetry, :logger])

  """
  @spec toggle(feature() | [feature()]) :: :ok
  def toggle(feature) when is_atom(feature) do
    toggle([feature])
  end

  def toggle(features) when is_list(features) do
    current_features = Application.get_env(:vaultx, :features, [])

    new_features =
      Enum.reduce(features, current_features, fn feature, acc ->
        current_value = enabled?(feature)
        Keyword.put(acc, feature, not current_value)
      end)

    Application.put_env(:vaultx, :features, new_features)
    :ok
  end

  @doc """
  Lists all configured features.

  ## Examples

      Vaultx.Base.Features.list()
      #=> [telemetry: true, logger: false, retry: true]

  """
  @spec list() :: keyword()
  def list do
    Application.get_env(:vaultx, :features, [])
  end

  @doc """
  Returns only enabled features.

  ## Examples

      Vaultx.Base.Features.enabled_features()
      #=> [:telemetry, :retry]

  """
  @spec enabled_features() :: [feature()]
  def enabled_features do
    [:telemetry, :logger, :retry, :ssl_verify, :audit]
    |> Enum.filter(&enabled?/1)
  end

  @doc """
  Returns only disabled features.

  ## Examples

      Vaultx.Base.Features.disabled_features()
      #=> [:logger, :audit]

  """
  @spec disabled_features() :: [feature()]
  def disabled_features do
    [:telemetry, :logger, :retry, :ssl_verify, :audit]
    |> Enum.reject(&enabled?/1)
  end

  @doc """
  Checks if running in performance mode (all optional features disabled).

  ## Examples

      iex> Vaultx.Base.Features.performance_mode?()
      false

  """
  @spec performance_mode?() :: boolean()
  def performance_mode? do
    not enabled?(:telemetry) and
      not enabled?(:logger) and
      not enabled?(:retry) and
      not enabled?(:audit)
  end

  @doc """
  Enables performance mode by disabling all optional features.

  ## Examples

      Vaultx.Base.Features.enable_performance_mode()

  """
  @spec enable_performance_mode() :: :ok
  def enable_performance_mode do
    disable([:telemetry, :logger, :retry, :audit])
  end

  @doc """
  Disables performance mode by enabling all features with their defaults.

  ## Examples

      Vaultx.Base.Features.disable_performance_mode()

  """
  @spec disable_performance_mode() :: :ok
  def disable_performance_mode do
    enable([:telemetry, :logger, :retry, :audit])
  end

  @doc """
  Resets all features to their default values.

  ## Examples

      Vaultx.Base.Features.reset_to_defaults()

  """
  @spec reset_to_defaults() :: :ok
  def reset_to_defaults do
    Application.delete_env(:vaultx, :features)
    :ok
  end

  # Private functions

  defp get_audit_enabled do
    case System.get_env("VAULTX_AUDIT_ENABLED") do
      nil -> Application.get_env(:vaultx, :audit_enabled, true)
      value -> String.downcase(value) in ["true", "1", "yes", "on"]
    end
  end
end
