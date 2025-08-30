defmodule Vaultx.Base.FeaturesTest do
  use ExUnit.Case, async: false

  alias Vaultx.Base.Features

  setup do
    # Store original application config
    original_config = Application.get_all_env(:vaultx)

    # Clean up after each test
    on_exit(fn ->
      # Restore original config
      Application.delete_env(:vaultx, :features)

      for {key, value} <- original_config do
        Application.put_env(:vaultx, key, value)
      end
    end)

    :ok
  end

  describe "status/0" do
    test "returns status of all features" do
      status = Features.status()

      assert Map.has_key?(status, :telemetry)
      assert Map.has_key?(status, :logger)
      assert Map.has_key?(status, :retry)
      assert Map.has_key?(status, :ssl_verify)
      assert Map.has_key?(status, :audit)

      assert is_boolean(status.telemetry)
      assert is_boolean(status.logger)
      assert is_boolean(status.retry)
      assert is_boolean(status.ssl_verify)
      assert is_boolean(status.audit)
    end
  end

  describe "enabled?/1" do
    test "returns true for telemetry when enabled" do
      Application.put_env(:vaultx, :telemetry_enabled, true)
      assert Features.enabled?(:telemetry) == true
    end

    test "returns false for telemetry when disabled" do
      Application.put_env(:vaultx, :telemetry_enabled, false)
      assert Features.enabled?(:telemetry) == false
    end

    test "returns true for logger when level is not :none" do
      Application.put_env(:vaultx, :logger_level, :info)
      assert Features.enabled?(:logger) == true
    end

    test "returns false for logger when level is :none" do
      Application.put_env(:vaultx, :logger_level, :none)
      assert Features.enabled?(:logger) == false
    end

    test "returns true for retry when attempts > 0" do
      Application.put_env(:vaultx, :retry_attempts, 3)
      assert Features.enabled?(:retry) == true
    end

    test "returns false for retry when attempts = 0" do
      Application.put_env(:vaultx, :retry_attempts, 0)
      assert Features.enabled?(:retry) == false
    end

    test "returns true for ssl_verify when enabled" do
      Application.put_env(:vaultx, :ssl_verify, true)
      assert Features.enabled?(:ssl_verify) == true
    end

    test "returns false for ssl_verify when disabled" do
      Application.put_env(:vaultx, :ssl_verify, false)
      assert Features.enabled?(:ssl_verify) == false
    end

    test "returns true for audit when enabled" do
      assert Features.enabled?(:audit) == true
    end

    test "returns false for audit when disabled via environment variable" do
      System.put_env("VAULTX_AUDIT_ENABLED", "false")
      assert Features.enabled?(:audit) == false
      System.delete_env("VAULTX_AUDIT_ENABLED")
    end

    test "returns false for unknown feature" do
      assert Features.enabled?(:unknown_feature) == false
      assert Features.enabled?("string_feature") == false
      assert Features.enabled?(123) == false
    end
  end

  describe "enable/1" do
    test "enables a single feature" do
      Features.enable(:telemetry)

      features = Application.get_env(:vaultx, :features, [])
      assert Keyword.get(features, :telemetry) == true
    end

    test "enables multiple features" do
      Features.enable([:telemetry, :logger])

      features = Application.get_env(:vaultx, :features, [])
      assert Keyword.get(features, :telemetry) == true
      assert Keyword.get(features, :logger) == true
    end
  end

  describe "disable/1" do
    test "disables a single feature" do
      Features.disable(:telemetry)

      features = Application.get_env(:vaultx, :features, [])
      assert Keyword.get(features, :telemetry) == false
    end

    test "disables multiple features" do
      Features.disable([:telemetry, :logger])

      features = Application.get_env(:vaultx, :features, [])
      assert Keyword.get(features, :telemetry) == false
      assert Keyword.get(features, :logger) == false
    end
  end

  describe "toggle/1" do
    test "toggles a single feature based on current enabled state" do
      # Set telemetry to disabled in main config
      Application.put_env(:vaultx, :telemetry_enabled, false)

      # Toggle should set it to true (opposite of current false state)
      Features.toggle(:telemetry)
      features = Application.get_env(:vaultx, :features, [])
      assert Keyword.get(features, :telemetry) == true
    end

    test "toggles multiple features based on current enabled state" do
      # Set initial states
      Application.put_env(:vaultx, :telemetry_enabled, true)
      Application.put_env(:vaultx, :logger_level, :info)

      # Toggle should set them to false (opposite of current true state)
      Features.toggle([:telemetry, :logger])
      features = Application.get_env(:vaultx, :features, [])
      assert Keyword.get(features, :telemetry) == false
      assert Keyword.get(features, :logger) == false
    end
  end

  describe "list/0" do
    test "returns configured features" do
      Features.enable([:telemetry, :logger])
      Features.disable(:audit)

      features = Features.list()

      assert is_list(features)
      assert Keyword.get(features, :telemetry) == true
      assert Keyword.get(features, :logger) == true
      assert Keyword.get(features, :audit) == false
    end

    test "returns empty list when no features configured" do
      features = Features.list()
      assert features == []
    end
  end

  describe "enabled_features/0" do
    test "returns only enabled features" do
      # Set up test environment to have known state
      Application.put_env(:vaultx, :telemetry_enabled, true)
      Application.put_env(:vaultx, :logger_level, :info)
      Application.put_env(:vaultx, :retry_attempts, 3)
      Application.put_env(:vaultx, :ssl_verify, false)

      enabled = Features.enabled_features()

      assert :telemetry in enabled
      assert :logger in enabled
      assert :retry in enabled
      assert :audit in enabled
      refute :ssl_verify in enabled
    end
  end

  describe "disabled_features/0" do
    test "returns only disabled features" do
      # Set up test environment to have known state
      Application.put_env(:vaultx, :telemetry_enabled, false)
      Application.put_env(:vaultx, :logger_level, :none)
      Application.put_env(:vaultx, :retry_attempts, 0)
      Application.put_env(:vaultx, :ssl_verify, true)

      disabled = Features.disabled_features()

      assert :telemetry in disabled
      assert :logger in disabled
      assert :retry in disabled
      refute :ssl_verify in disabled
      refute :audit in disabled
    end
  end

  describe "performance_mode?/0" do
    test "returns true when all optional features are disabled" do
      Application.put_env(:vaultx, :telemetry_enabled, false)
      Application.put_env(:vaultx, :logger_level, :none)
      Application.put_env(:vaultx, :retry_attempts, 0)
      System.put_env("VAULTX_AUDIT_ENABLED", "false")

      assert Features.performance_mode?() == true

      System.delete_env("VAULTX_AUDIT_ENABLED")
    end

    test "returns false when any optional feature is enabled" do
      Application.put_env(:vaultx, :telemetry_enabled, true)
      Application.put_env(:vaultx, :logger_level, :none)
      Application.put_env(:vaultx, :retry_attempts, 0)
      System.put_env("VAULTX_AUDIT_ENABLED", "false")

      assert Features.performance_mode?() == false

      System.delete_env("VAULTX_AUDIT_ENABLED")
    end
  end

  describe "enable_performance_mode/0" do
    test "disables all optional features" do
      Features.enable_performance_mode()

      features = Application.get_env(:vaultx, :features, [])
      assert Keyword.get(features, :telemetry) == false
      assert Keyword.get(features, :logger) == false
      assert Keyword.get(features, :retry) == false
      assert Keyword.get(features, :audit) == false
    end
  end

  describe "disable_performance_mode/0" do
    test "enables all features with their defaults" do
      Features.disable_performance_mode()

      features = Application.get_env(:vaultx, :features, [])
      assert Keyword.get(features, :telemetry) == true
      assert Keyword.get(features, :logger) == true
      assert Keyword.get(features, :retry) == true
      assert Keyword.get(features, :audit) == true
    end
  end

  describe "reset_to_defaults/0" do
    test "resets all features to their default values" do
      # First set some features
      Features.enable([:telemetry, :logger])
      Features.disable(:audit)

      # Verify they are set
      features = Application.get_env(:vaultx, :features, [])
      assert features != []

      # Reset to defaults
      Features.reset_to_defaults()

      # Verify they are cleared
      features = Application.get_env(:vaultx, :features, [])
      assert features == []
    end
  end
end
