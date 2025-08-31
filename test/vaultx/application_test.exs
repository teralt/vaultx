defmodule Vaultx.ApplicationTest do
  use ExUnit.Case, async: false

  alias Vaultx.Application

  describe "public API" do
    test "version returns application version" do
      version = Application.version()
      assert is_binary(version)
      assert String.length(version) > 0
    end

    test "config_summary returns complete configuration" do
      summary = Application.config_summary()

      # Verify structure
      assert is_map(summary)

      required_keys = [
        :url,
        :timeout,
        :retry_attempts,
        :ssl_verify,
        :logger_level,
        :telemetry_enabled,
        :features
      ]

      for key <- required_keys do
        assert Map.has_key?(summary, key), "Missing key: #{key}"
      end

      # Verify types
      assert is_binary(summary.url)
      assert is_integer(summary.timeout)
      assert is_integer(summary.retry_attempts)
      assert is_boolean(summary.ssl_verify)
      assert is_atom(summary.logger_level)
      assert is_boolean(summary.telemetry_enabled)
      assert is_map(summary.features)
    end

    test "config_summary integrates with Config module" do
      summary = Application.config_summary()
      config = Vaultx.Base.Config.get()
      features = Vaultx.Base.Config.features_status()

      # Should match values from Config module
      assert summary.url == config.url
      assert summary.timeout == config.timeout
      assert summary.retry_attempts == config.retry_attempts
      assert summary.ssl_verify == config.ssl_verify
      assert summary.logger_level == config.logger_level
      assert summary.telemetry_enabled == config.telemetry_enabled
      assert summary.features == features
    end
  end

  describe "telemetry handling" do
    test "handles various telemetry events" do
      events = [
        [:vaultx, :http, :request, :start],
        [:vaultx, :http, :request, :stop],
        [:vaultx, :http, :request, :exception],
        [:vaultx, :auth, :start],
        [:vaultx, :auth, :success],
        [:vaultx, :auth, :failure]
      ]

      for event <- events do
        measurements = %{duration: 100, system_time: System.system_time()}
        metadata = %{test: true}
        config = %{}

        assert :ok = Application.handle_telemetry_event(event, measurements, metadata, config)
      end
    end

    test "sanitizes sensitive metadata" do
      event = [:vaultx, :auth, :success]
      measurements = %{duration: 150}

      metadata = %{
        method: "app_role",
        token: "hvs.secret_token",
        secret_id: "secret_123",
        password: "my_password",
        normal_field: "normal_value",
        nested: %{
          token: "nested_secret",
          safe_field: "safe_value"
        }
      }

      config = %{}

      # Should sanitize sensitive data and not crash
      assert :ok = Application.handle_telemetry_event(event, measurements, metadata, config)
    end

    test "handles malformed metadata gracefully" do
      event = [:vaultx, :test]
      measurements = %{}

      malformed_metadata = [nil, "not a map", 123, [], %{circular: :reference}]

      for metadata <- malformed_metadata do
        # Should not crash even with malformed metadata
        assert :ok = Application.handle_telemetry_event(event, measurements, metadata, %{})
      end
    end
  end

  describe "application lifecycle" do
    test "application is loaded and running" do
      # Check if the application is loaded
      loaded_apps = :application.loaded_applications()
      app_names = Enum.map(loaded_apps, fn {name, _, _} -> name end)
      assert :vaultx in app_names

      # Finch should be started as part of the application
      assert Process.whereis(Vaultx.Finch) != nil
    end

    test "stop callback handles telemetry cleanup" do
      # Test stop callback - should not crash
      assert :ok = Application.stop(:normal)
    end
  end
end
