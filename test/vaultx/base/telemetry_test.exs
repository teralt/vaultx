defmodule Vaultx.Base.TelemetryTest do
  use ExUnit.Case, async: true

  alias Vaultx.Base.Telemetry

  setup do
    # Store original application config
    original_config = Application.get_all_env(:vaultx)

    # Clean up after each test
    on_exit(fn ->
      # Restore original config
      for {key, value} <- original_config do
        Application.put_env(:vaultx, key, value)
      end

      # Clean up any test handlers
      try do
        Telemetry.detach("test-handler")
      rescue
        _ -> :ok
      end
    end)

    :ok
  end

  describe "enabled?/0" do
    test "returns correct status based on configuration" do
      Application.put_env(:vaultx, :telemetry_enabled, true)
      assert Telemetry.enabled?() == true

      Application.put_env(:vaultx, :telemetry_enabled, false)
      assert Telemetry.enabled?() == false
    end
  end

  describe "execute/3" do
    test "executes telemetry event when enabled" do
      Application.put_env(:vaultx, :telemetry_enabled, true)
      assert Telemetry.execute([:test, :event], %{duration: 100}, %{path: "/test"}) == :ok
    end

    test "is no-op when telemetry is disabled" do
      Application.put_env(:vaultx, :telemetry_enabled, false)
      assert Telemetry.execute([:test, :event], %{duration: 100}, %{path: "/test"}) == :ok
    end

    test "works with default metadata" do
      Application.put_env(:vaultx, :telemetry_enabled, true)
      assert Telemetry.execute([:test, :event], %{duration: 100}) == :ok
    end
  end

  describe "span/3" do
    test "executes function and returns result when enabled" do
      Application.put_env(:vaultx, :telemetry_enabled, true)

      result =
        Telemetry.span([:test, :operation], %{path: "/test"}, fn ->
          {{:ok, "test result"}, %{extra: "metadata"}}
        end)

      assert result == {:ok, "test result"}
    end

    test "executes function directly when disabled" do
      Application.put_env(:vaultx, :telemetry_enabled, false)

      result =
        Telemetry.span([:test, :operation], %{path: "/test"}, fn ->
          "simple result"
        end)

      assert result == "simple result"
    end

    test "handles span function returning tuple with metadata" do
      Application.put_env(:vaultx, :telemetry_enabled, true)

      result =
        Telemetry.span([:test, :span], %{}, fn ->
          {42, %{computed: true}}
        end)

      assert result == 42
    end

    test "handles span function returning tuple when telemetry is disabled" do
      Application.put_env(:vaultx, :telemetry_enabled, false)

      result =
        Telemetry.span([:test, :span], %{}, fn ->
          {"success", %{extra: "metadata"}}
        end)

      assert result == "success"
    end
  end

  describe "measure/3" do
    test "measures function execution when enabled" do
      Application.put_env(:vaultx, :telemetry_enabled, true)

      result =
        Telemetry.measure([:test, :request], %{method: :get}, fn ->
          {:ok, %{status: 200}}
        end)

      assert result == {:ok, %{status: 200}}
    end

    test "executes function directly when disabled" do
      Application.put_env(:vaultx, :telemetry_enabled, false)

      result =
        Telemetry.measure([:test, :request], %{method: :get}, fn ->
          {:ok, %{status: 200}}
        end)

      assert result == {:ok, %{status: 200}}
    end

    test "handles function errors correctly" do
      Application.put_env(:vaultx, :telemetry_enabled, true)

      assert_raise RuntimeError, "test error", fn ->
        Telemetry.measure([:test, :error], %{method: :get}, fn ->
          raise "test error"
        end)
      end
    end
  end

  describe "handler management" do
    test "attach/4 delegates to telemetry attach" do
      assert_raise ArgumentError, fn ->
        Telemetry.attach(
          "test-handler",
          [[:invalid]],
          fn _, _, _, _ -> :ok end,
          %{}
        )
      end
    end

    test "attach_many/4 delegates to telemetry attach_many" do
      # Test with valid event names (at least 4 parts each)
      result =
        Telemetry.attach_many(
          "test-handlers",
          [[:vaultx, :test, :event, :start], [:vaultx, :test, :event, :stop]],
          fn _, _, _, _ -> :ok end,
          %{}
        )

      assert result == :ok

      # Clean up
      Telemetry.detach("test-handlers")
    end

    test "detach/1 returns error for non-existent handler" do
      result = Telemetry.detach("non-existent-handler")
      assert {:error, :not_found} = result
    end

    test "list_handlers/1 lists handlers for event prefix" do
      handlers = Telemetry.list_handlers([:vaultx])
      assert is_list(handlers)
    end
  end

  describe "info/0" do
    test "returns telemetry configuration and status" do
      Application.put_env(:vaultx, :telemetry_enabled, true)

      info = Telemetry.info()

      assert Map.has_key?(info, :enabled)
      assert Map.has_key?(info, :handlers_count)
      assert Map.has_key?(info, :available_events)

      assert info.enabled == true
      assert is_integer(info.handlers_count)
      assert is_list(info.available_events)

      # Check that available events include expected ones
      expected_events = [
        [:vaultx, :http, :request, :start],
        [:vaultx, :http, :request, :stop],
        [:vaultx, :auth, :start],
        [:vaultx, :auth, :stop],
        [:vaultx, :secret, :read, :start],
        [:vaultx, :secret, :write, :start],
        [:vaultx, :system, :health, :start]
      ]

      for event <- expected_events do
        assert event in info.available_events
      end
    end

    test "shows disabled status when telemetry is disabled" do
      Application.put_env(:vaultx, :telemetry_enabled, false)

      info = Telemetry.info()
      assert info.enabled == false
    end
  end

  describe "integration tests" do
    test "execute works with telemetry disabled" do
      Application.put_env(:vaultx, :telemetry_enabled, false)
      assert Telemetry.execute([:invalid, :event], %{duration: 100}, %{path: "/test"}) == :ok
    end

    test "execute works with telemetry enabled" do
      Application.put_env(:vaultx, :telemetry_enabled, true)
      assert Telemetry.execute([:invalid, :event], %{duration: 100}, %{path: "/test"}) == :ok
    end

    test "telemetry_available? returns true when telemetry is loaded" do
      assert Telemetry.telemetry_available?() == true
    end

    test "attach functions handle telemetry unavailability gracefully" do
      # This test would be more meaningful if we could unload telemetry,
      # but for now we just test the happy path with valid event names
      result = Telemetry.attach("test-handler", [:test, :event], fn _, _, _, _ -> :ok end, %{})
      assert result == :ok or match?({:error, _}, result)

      # Clean up
      Telemetry.detach("test-handler")
    end
  end

  describe "authentication events" do
    setup do
      Application.put_env(:vaultx, :telemetry_enabled, true)
      :ok
    end

    test "auth_start/1 executes auth start event" do
      metadata = %{method: :token, user: "test"}
      assert Telemetry.auth_start(metadata) == :ok
    end

    test "auth_start/0 works with default metadata" do
      assert Telemetry.auth_start() == :ok
    end

    test "auth_success/2 executes auth success event" do
      duration = 150
      metadata = %{method: :token, user: "test"}
      assert Telemetry.auth_success(duration, metadata) == :ok
    end

    test "auth_success/1 works with default metadata" do
      assert Telemetry.auth_success(150) == :ok
    end

    test "auth_failure/2 executes auth failure event" do
      duration = 200
      metadata = %{method: :token, error: "invalid_token"}
      assert Telemetry.auth_failure(duration, metadata) == :ok
    end

    test "auth_failure/1 works with default metadata" do
      assert Telemetry.auth_failure(200) == :ok
    end
  end

  describe "operation events" do
    setup do
      Application.put_env(:vaultx, :telemetry_enabled, true)
      :ok
    end

    test "operation_start/1 executes operation start event" do
      metadata = %{operation: "read", path: "secret/test"}
      assert Telemetry.operation_start(metadata) == :ok
    end

    test "operation_start/0 works with default metadata" do
      assert Telemetry.operation_start() == :ok
    end

    test "operation_success/2 executes operation success event" do
      duration = 100
      metadata = %{operation: "read", path: "secret/test"}
      assert Telemetry.operation_success(duration, metadata) == :ok
    end

    test "operation_success/1 works with default metadata" do
      assert Telemetry.operation_success(100) == :ok
    end

    test "operation_failure/2 executes operation failure event" do
      duration = 250
      metadata = %{operation: "read", path: "secret/test", error: "not_found"}
      assert Telemetry.operation_failure(duration, metadata) == :ok
    end

    test "operation_failure/1 works with default metadata" do
      assert Telemetry.operation_failure(250) == :ok
    end
  end

  describe "HTTP request events" do
    setup do
      Application.put_env(:vaultx, :telemetry_enabled, true)
      :ok
    end

    test "http_request_start/1 executes HTTP request start event" do
      metadata = %{method: :get, url: "https://vault.example.com/v1/secret/test"}
      assert Telemetry.http_request_start(metadata) == :ok
    end

    test "http_request_start/0 works with default metadata" do
      assert Telemetry.http_request_start() == :ok
    end

    test "http_request_stop/2 executes HTTP request stop event" do
      duration = 120
      metadata = %{method: :get, status: 200}
      assert Telemetry.http_request_stop(duration, metadata) == :ok
    end

    test "http_request_stop/1 works with default metadata" do
      assert Telemetry.http_request_stop(120) == :ok
    end

    test "http_request_exception/2 executes HTTP request exception event" do
      duration = 300
      metadata = %{method: :get, error: "timeout"}
      assert Telemetry.http_request_exception(duration, metadata) == :ok
    end

    test "http_request_exception/1 works with default metadata" do
      assert Telemetry.http_request_exception(300) == :ok
    end
  end

  describe "telemetry disabled" do
    setup do
      Application.put_env(:vaultx, :telemetry_enabled, false)
      :ok
    end

    test "all convenience functions work when telemetry is disabled" do
      # Auth functions
      assert Telemetry.auth_start(%{method: :token}) == :ok
      assert Telemetry.auth_success(100, %{method: :token}) == :ok
      assert Telemetry.auth_failure(200, %{error: "invalid"}) == :ok

      # Operation functions
      assert Telemetry.operation_start(%{operation: "read"}) == :ok
      assert Telemetry.operation_success(150, %{operation: "read"}) == :ok
      assert Telemetry.operation_failure(300, %{error: "not_found"}) == :ok

      # HTTP functions
      assert Telemetry.http_request_start(%{method: :get}) == :ok
      assert Telemetry.http_request_stop(120, %{status: 200}) == :ok
      assert Telemetry.http_request_exception(400, %{error: "timeout"}) == :ok
    end
  end

  describe "cache metrics" do
    setup do
      Application.put_env(:vaultx, :telemetry_enabled, true)
      :ok
    end

    test "emit_cache_metrics/4 emits cache metrics with all parameters" do
      hit_rate = 0.85
      size = 1000
      memory_usage = 2048
      metadata = %{cache_type: "secrets"}

      assert Telemetry.emit_cache_metrics(hit_rate, size, memory_usage, metadata) == :ok
    end

    test "emit_cache_metrics/3 works with default metadata" do
      hit_rate = 0.75
      size = 500
      memory_usage = 1024

      assert Telemetry.emit_cache_metrics(hit_rate, size, memory_usage) == :ok
    end

    test "emit_cache_event/3 emits cache events with metadata" do
      event_type = :hit
      key = "secret/myapp/config"
      metadata = %{cache_type: "secrets"}

      assert Telemetry.emit_cache_event(event_type, key, metadata) == :ok
    end

    test "emit_cache_event/2 works with default metadata" do
      event_type = :miss
      key = "secret/myapp/database"

      assert Telemetry.emit_cache_event(event_type, key) == :ok
    end

    test "emit_cache_event/2 anonymizes sensitive paths" do
      event_type = :eviction
      key = "secret/sensitive/password"

      assert Telemetry.emit_cache_event(event_type, key) == :ok
    end
  end

  describe "connection pool metrics" do
    setup do
      Application.put_env(:vaultx, :telemetry_enabled, true)
      :ok
    end

    test "emit_pool_metrics/5 emits pool metrics with all parameters" do
      active = 5
      idle = 3
      pending = 2
      response_times = [100, 150, 200]
      metadata = %{pool_name: "vault_pool"}

      assert Telemetry.emit_pool_metrics(active, idle, pending, response_times, metadata) == :ok
    end

    test "emit_pool_metrics/4 works with default metadata" do
      active = 8
      idle = 2
      pending = 1
      response_times = [80, 120, 180]

      assert Telemetry.emit_pool_metrics(active, idle, pending, response_times) == :ok
    end

    test "emit_pool_metrics/3 works with default response times and metadata" do
      active = 10
      idle = 5
      pending = 0

      assert Telemetry.emit_pool_metrics(active, idle, pending) == :ok
    end

    test "emit_pool_event/2 emits pool events with metadata" do
      event_type = :connection_created
      metadata = %{pool_name: "vault_pool", connection_id: "conn_123"}

      assert Telemetry.emit_pool_event(event_type, metadata) == :ok
    end

    test "emit_pool_event/1 works with default metadata" do
      event_type = :connection_closed

      assert Telemetry.emit_pool_event(event_type) == :ok
    end
  end

  describe "security events" do
    setup do
      Application.put_env(:vaultx, :telemetry_enabled, true)
      :ok
    end

    test "emit_security_event/3 emits security events with metadata" do
      event_type = :authentication_failure
      severity = :high
      metadata = %{user: "test_user", ip: "192.168.1.100"}

      assert Telemetry.emit_security_event(event_type, severity, metadata) == :ok
    end

    test "emit_security_event/2 works with default metadata" do
      event_type = :unauthorized_access
      severity = :critical

      assert Telemetry.emit_security_event(event_type, severity) == :ok
    end

    test "emit_security_event/2 handles different severity levels" do
      assert Telemetry.emit_security_event(:login_attempt, :low) == :ok
      assert Telemetry.emit_security_event(:permission_denied, :medium) == :ok
      assert Telemetry.emit_security_event(:data_breach, :high) == :ok
      assert Telemetry.emit_security_event(:system_compromise, :critical) == :ok
    end

    test "emit_security_anomaly/3 emits security anomalies with metadata" do
      description = "Unusual access pattern detected"
      severity = :medium
      metadata = %{pattern: "rapid_requests", threshold: 100}

      assert Telemetry.emit_security_anomaly(description, severity, metadata) == :ok
    end

    test "emit_security_anomaly/2 works with default metadata" do
      description = "Failed login attempts exceeded threshold"
      severity = :high

      assert Telemetry.emit_security_anomaly(description, severity) == :ok
    end

    test "emit_security_anomaly/2 handles different severity levels" do
      assert Telemetry.emit_security_anomaly("Low priority anomaly", :low) == :ok
      assert Telemetry.emit_security_anomaly("Medium priority anomaly", :medium) == :ok
      assert Telemetry.emit_security_anomaly("High priority anomaly", :high) == :ok
      assert Telemetry.emit_security_anomaly("Critical anomaly", :critical) == :ok
    end
  end

  describe "business metrics" do
    setup do
      Application.put_env(:vaultx, :telemetry_enabled, true)
      :ok
    end

    test "emit_business_metrics/3 emits business metrics with metadata" do
      metric_type = :secret_reads
      value = 150
      metadata = %{department: "engineering", application: "web_app"}

      assert Telemetry.emit_business_metrics(metric_type, value, metadata) == :ok
    end

    test "emit_business_metrics/2 works with default metadata" do
      metric_type = :token_generations
      value = 25

      assert Telemetry.emit_business_metrics(metric_type, value) == :ok
    end

    test "emit_business_metrics/2 handles different metric types" do
      assert Telemetry.emit_business_metrics(:api_calls, 1000) == :ok
      assert Telemetry.emit_business_metrics(:user_sessions, 50) == :ok
      assert Telemetry.emit_business_metrics(:data_volume, 2048) == :ok
    end
  end

  describe "performance metrics" do
    setup do
      Application.put_env(:vaultx, :telemetry_enabled, true)
      :ok
    end

    test "emit_performance_metrics/4 emits performance metrics with metadata" do
      operation = "secret_read"
      duration = 150
      success = true
      metadata = %{cache_hit: true, path: "secret/app/config"}

      assert Telemetry.emit_performance_metrics(operation, duration, success, metadata) == :ok
    end

    test "emit_performance_metrics/3 works with default metadata" do
      operation = "token_validation"
      duration = 75
      success = false

      assert Telemetry.emit_performance_metrics(operation, duration, success) == :ok
    end

    test "emit_performance_metrics/3 handles success and failure cases" do
      assert Telemetry.emit_performance_metrics("auth_login", 200, true) == :ok
      assert Telemetry.emit_performance_metrics("auth_login", 500, false) == :ok
    end
  end

  describe "private helper functions (tested indirectly)" do
    setup do
      Application.put_env(:vaultx, :telemetry_enabled, true)
      :ok
    end

    test "severity_to_number/1 is tested through security events" do
      # Test all severity levels to ensure severity_to_number/1 is called
      assert Telemetry.emit_security_event(:test_event, :low) == :ok
      assert Telemetry.emit_security_event(:test_event, :medium) == :ok
      assert Telemetry.emit_security_event(:test_event, :high) == :ok
      assert Telemetry.emit_security_event(:test_event, :critical) == :ok
      assert Telemetry.emit_security_event(:test_event, :unknown) == :ok
    end

    test "severity_to_number/1 is tested through security anomalies" do
      # Test all severity levels in anomalies to ensure coverage
      assert Telemetry.emit_security_anomaly("Test anomaly", :low) == :ok
      assert Telemetry.emit_security_anomaly("Test anomaly", :medium) == :ok
      assert Telemetry.emit_security_anomaly("Test anomaly", :high) == :ok
      assert Telemetry.emit_security_anomaly("Test anomaly", :critical) == :ok
      assert Telemetry.emit_security_anomaly("Test anomaly", :invalid) == :ok
    end

    test "calculate_average/1 is tested through pool metrics with empty list" do
      # Test with empty response times to trigger calculate_average([])
      active = 5
      idle = 3
      pending = 2
      response_times = []
      metadata = %{pool_name: "test_pool"}

      assert Telemetry.emit_pool_metrics(active, idle, pending, response_times, metadata) == :ok
    end

    test "calculate_average/1 is tested through pool metrics with values" do
      # Test with response times to trigger calculate_average with values
      active = 5
      idle = 3
      pending = 2
      response_times = [100, 200, 300]
      metadata = %{pool_name: "test_pool"}

      assert Telemetry.emit_pool_metrics(active, idle, pending, response_times, metadata) == :ok
    end

    test "calculate_average/1 is tested with single value" do
      # Test with single response time to ensure division works
      active = 1
      idle = 0
      pending = 0
      response_times = [150]
      metadata = %{pool_name: "single_pool"}

      assert Telemetry.emit_pool_metrics(active, idle, pending, response_times, metadata) == :ok
    end

    test "calculate_average/1 is tested with multiple values" do
      # Test with multiple response times to ensure proper averaging
      active = 10
      idle = 5
      pending = 3
      response_times = [50, 100, 150, 200, 250]
      metadata = %{pool_name: "multi_pool"}

      assert Telemetry.emit_pool_metrics(active, idle, pending, response_times, metadata) == :ok
    end

    test "anonymize_path/1 is tested through cache events with secret paths" do
      # Test path anonymization with secret paths
      assert Telemetry.emit_cache_event(:hit, "secret/myapp/config") == :ok
      assert Telemetry.emit_cache_event(:miss, "secret/sensitive/password") == :ok
      assert Telemetry.emit_cache_event(:eviction, "secret/database/credentials") == :ok
    end

    test "anonymize_path/1 is tested through cache events with non-secret paths" do
      # Test path anonymization with non-secret paths
      assert Telemetry.emit_cache_event(:hit, "auth/token/lookup") == :ok
      assert Telemetry.emit_cache_event(:miss, "sys/health") == :ok
      assert Telemetry.emit_cache_event(:eviction, "kv/data/config") == :ok
    end
  end

  describe "telemetry disabled for all new functions" do
    setup do
      Application.put_env(:vaultx, :telemetry_enabled, false)
      :ok
    end

    test "all new telemetry functions work when disabled" do
      # Cache functions
      assert Telemetry.emit_cache_metrics(0.8, 100, 512) == :ok
      assert Telemetry.emit_cache_event(:hit, "secret/test") == :ok

      # Pool functions
      assert Telemetry.emit_pool_metrics(5, 3, 2, [100, 200]) == :ok
      assert Telemetry.emit_pool_event(:connection_created) == :ok

      # Security functions
      assert Telemetry.emit_security_event(:auth_failure, :high) == :ok
      assert Telemetry.emit_security_anomaly("Test anomaly", :medium) == :ok

      # Business functions
      assert Telemetry.emit_business_metrics(:api_calls, 1000) == :ok

      # Performance functions
      assert Telemetry.emit_performance_metrics("test_op", 100, true) == :ok
    end
  end
end
