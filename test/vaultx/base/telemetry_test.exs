defmodule Vaultx.Base.TelemetryTest do
  use ExUnit.Case, async: false

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
end
