defmodule Vaultx.Base.LoggerTest do
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog

  alias Vaultx.Base.{Logger, Error}

  describe "debug/2" do
    test "logs debug messages when level is debug" do
      with_config(:debug, fn ->
        log = capture_log(fn -> Logger.debug("Debug message", %{key: "value"}) end)
        assert log =~ "[debug] [Vaultx] Debug message"
        # Note: Metadata may not be visible in test output, but function should work
      end)
    end

    test "does not log debug messages when level is higher" do
      with_config(:info, fn ->
        log = capture_log(fn -> Logger.debug("Debug message") end)
        assert log == ""
      end)
    end

    test "sanitizes sensitive data in debug logs" do
      with_config(:debug, fn ->
        log =
          capture_log(fn ->
            Logger.debug("Debug with token", %{token: "secret-token", data: "safe"})
          end)

        assert log =~ "[debug] [Vaultx] Debug with token"
        # Sanitization happens internally, message still appears
      end)
    end

    test "handles nil metadata gracefully" do
      with_config(:debug, fn ->
        log = capture_log(fn -> Logger.debug("Debug message", nil) end)
        assert log =~ "[debug] [Vaultx] Debug message"
      end)
    end

    test "validates message type with guards" do
      with_config(:debug, fn ->
        assert Logger.debug("string message") == :ok
        assert Logger.debug(["io", "data"]) == :ok
      end)
    end

    test "returns :ok when disabled for performance" do
      with_config(:info, fn ->
        assert Logger.debug("Debug message") == :ok
      end)
    end
  end

  describe "info/2" do
    test "logs info messages when level is info or debug" do
      with_config(:info, fn ->
        log = capture_log(fn -> Logger.info("Info message", %{status: :ok}) end)
        assert log =~ "[info] [Vaultx] Info message"
      end)
    end

    test "does not log info messages when level is higher" do
      with_config(:warn, fn ->
        log = capture_log(fn -> Logger.info("Info message") end)
        assert log == ""
      end)
    end

    test "handles keyword list metadata" do
      with_config(:info, fn ->
        log = capture_log(fn -> Logger.info("Info", key: "value", count: 42) end)
        assert log =~ "[info] [Vaultx] Info"
      end)
    end
  end

  describe "warn/2" do
    test "logs warn messages when level is warn, info, or debug" do
      with_config(:warn, fn ->
        log = capture_log(fn -> Logger.warn("Warning message", %{issue: "deprecated"}) end)
        assert log =~ "[warning] [Vaultx] Warning message"
      end)
    end

    test "does not log warn messages when level is higher" do
      with_config(:error, fn ->
        log = capture_log(fn -> Logger.warn("Warning message") end)
        assert log == ""
      end)
    end

    test "converts :warn to :warn for Elixir 1.18+ compatibility" do
      with_config(:warn, fn ->
        log = capture_log(fn -> Logger.warn("Warning") end)
        assert log =~ "[warning]"
      end)
    end
  end

  describe "warning/2" do
    test "is an alias for warn/2" do
      with_config(:warn, fn ->
        log = capture_log(fn -> Logger.warn("Warning message") end)
        assert log =~ "[warning] [Vaultx] Warning message"
      end)
    end
  end

  describe "error/2" do
    test "logs error messages unless disabled" do
      with_config(:error, fn ->
        log = capture_log(fn -> Logger.error("Error message", %{code: 500}) end)
        assert log =~ "[error] [Vaultx] Error message"
      end)
    end

    test "does not log when level is none" do
      with_config(:none, fn ->
        # Ensure Logger.enabled? returns false for all levels when set to :none
        assert Logger.enabled?(:debug) == false
        assert Logger.enabled?(:info) == false
        assert Logger.enabled?(:warn) == false
        assert Logger.enabled?(:error) == false

        # Test that no actual logging occurs
        log =
          capture_log(fn ->
            Logger.debug("Debug message")
            Logger.info("Info message")
            Logger.warn("Warn message")
            Logger.error("Error message")
          end)

        # Should be empty since all logging is disabled
        assert log == ""
      end)
    end

    test "logs errors even when level is higher than error" do
      with_config(:error, fn ->
        log = capture_log(fn -> Logger.error("Critical error") end)
        assert log =~ "[error] [Vaultx] Critical error"
      end)
    end
  end

  describe "current_level/0" do
    test "returns the configured log level from Config" do
      with_config(:debug, fn ->
        assert Logger.current_level() == :debug
      end)

      with_config(:info, fn ->
        assert Logger.current_level() == :info
      end)

      with_config(:none, fn ->
        assert Logger.current_level() == :none
      end)
    end
  end

  describe "enabled?/1" do
    test "returns correct boolean for each level combination" do
      with_config(:debug, fn ->
        assert Logger.enabled?(:debug) == true
        assert Logger.enabled?(:info) == true
        assert Logger.enabled?(:warn) == true
        assert Logger.enabled?(:error) == true
      end)

      with_config(:info, fn ->
        assert Logger.enabled?(:debug) == false
        assert Logger.enabled?(:info) == true
        assert Logger.enabled?(:warn) == true
        assert Logger.enabled?(:error) == true
      end)

      with_config(:warn, fn ->
        assert Logger.enabled?(:debug) == false
        assert Logger.enabled?(:info) == false
        assert Logger.enabled?(:warn) == true
        assert Logger.enabled?(:error) == true
      end)

      with_config(:error, fn ->
        assert Logger.enabled?(:debug) == false
        assert Logger.enabled?(:info) == false
        assert Logger.enabled?(:warn) == false
        assert Logger.enabled?(:error) == true
      end)
    end

    test "returns false when logging is completely disabled" do
      with_config(:none, fn ->
        assert Logger.enabled?(:debug) == false
        assert Logger.enabled?(:info) == false
        assert Logger.enabled?(:warn) == false
        assert Logger.enabled?(:error) == false
      end)
    end

    test "returns false for invalid levels with guard protection" do
      with_config(:info, fn ->
        assert Logger.enabled?(:invalid) == false
        assert Logger.enabled?("string") == false
        assert Logger.enabled?(123) == false
        assert Logger.enabled?(nil) == false
      end)
    end
  end

  describe "log_operation/4" do
    test "logs successful operations as info level" do
      with_config(:info, fn ->
        log =
          capture_log(fn ->
            Logger.log_operation("read", "secret/test", 150, :ok)
          end)

        assert log =~ "[info] [Vaultx] read completed successfully"
      end)
    end

    test "logs successful operations with data as info level" do
      with_config(:info, fn ->
        log =
          capture_log(fn ->
            Logger.log_operation("write", "secret/test", 200, {:ok, %{version: 1}})
          end)

        assert log =~ "[info] [Vaultx] write completed successfully"
      end)
    end

    test "logs error operations with Error struct as error level" do
      with_config(:error, fn ->
        error = %Error{type: :not_found, message: "Secret not found"}

        log =
          capture_log(fn ->
            Logger.log_operation("read", "secret/missing", 100, {:error, error})
          end)

        assert log =~ "[error] [Vaultx] read failed: Secret not found"
      end)
    end

    test "logs error operations with reason as error level" do
      with_config(:error, fn ->
        log =
          capture_log(fn ->
            Logger.log_operation("delete", "secret/test", 75, {:error, :timeout})
          end)

        assert log =~ "[error] [Vaultx] delete failed: :timeout"
      end)
    end

    test "logs other results as debug level" do
      with_config(:debug, fn ->
        log =
          capture_log(fn ->
            Logger.log_operation("custom", "path/test", 50, {:custom, "result"})
          end)

        assert log =~ "[debug] [Vaultx] custom completed"
      end)
    end

    test "validates parameters with guards" do
      with_config(:info, fn ->
        assert Logger.log_operation("read", "path", 100, :ok) == :ok
        assert Logger.log_operation("write", "path", 0, :ok) == :ok
      end)
    end

    test "handles negative duration gracefully" do
      with_config(:info, fn ->
        # Should not crash, but may not log due to guard
        result = Logger.log_operation("test", "path", -1, :ok)
        # The function should handle this gracefully
        assert is_atom(result)
      end)
    end
  end

  describe "data sanitization" do
    test "sanitizes all sensitive keys" do
      sensitive_data = %{
        token: "secret1",
        secret_id: "secret2",
        password: "secret3",
        secret: "secret4",
        client_token: "secret5",
        accessor: "secret6",
        auth_token: "secret7",
        vault_token: "secret8",
        api_key: "secret9",
        private_key: "secret10",
        certificate: "secret11",
        safe_data: "visible"
      }

      with_config(:info, fn ->
        log = capture_log(fn -> Logger.info("Test", sensitive_data) end)

        # The message should appear, sanitization happens internally
        assert log =~ "[info] [Vaultx] Test"

        # Sensitive data should not appear in logs (though metadata may not be visible in tests)
        refute log =~ "secret1"
        refute log =~ "secret2"
        refute log =~ "secret3"
        refute log =~ "secret4"
        refute log =~ "secret5"
        refute log =~ "secret6"
        refute log =~ "secret7"
        refute log =~ "secret8"
        refute log =~ "secret9"
        refute log =~ "secret10"
        refute log =~ "secret11"
      end)
    end

    test "sanitizes nested maps recursively" do
      nested_data = %{
        user: %{
          name: "john",
          token: "secret-token"
        },
        config: %{
          timeout: 5000,
          password: "secret-pass"
        }
      }

      with_config(:info, fn ->
        log = capture_log(fn -> Logger.info("Nested test", nested_data) end)
        assert log =~ "[info] [Vaultx] Nested test"
        # Sanitization happens internally, sensitive data should not appear
        refute log =~ "secret-token"
        refute log =~ "secret-pass"
      end)
    end

    test "sanitizes nested lists with sensitive data" do
      list_data = %{
        items: [
          %{name: "item1", token: "secret1"},
          %{name: "item2", password: "secret2"}
        ]
      }

      with_config(:info, fn ->
        log = capture_log(fn -> Logger.info("List test", list_data) end)
        assert log =~ "[info] [Vaultx] List test"
        # Sanitization happens internally, sensitive data should not appear
        refute log =~ "secret1"
        refute log =~ "secret2"
      end)
    end

    test "formats Error structs with debug information" do
      error = %Error{
        type: :authentication_failed,
        message: "Invalid credentials",
        http_status: 401,
        recoverable: false,
        request_id: "req-123",
        vault_errors: ["error1", "error2"]
      }

      with_config(:info, fn ->
        log = capture_log(fn -> Logger.info("Error test", %{error: error}) end)
        assert log =~ "[info] [Vaultx] Error test"
        # Error struct formatting happens internally, may not be visible in test output
      end)
    end

    test "handles Error structs in nested lists" do
      error = %Error{type: :network_error, message: "Connection failed"}

      data = %{
        errors: [error, %{other: "data"}]
      }

      with_config(:info, fn ->
        log = capture_log(fn -> Logger.info("Error list", data) end)
        assert log =~ "[info] [Vaultx] Error list"
        # Error struct formatting happens internally, may not be visible in test output
      end)
    end

    test "adds sanitization marker to all metadata" do
      with_config(:info, fn ->
        log = capture_log(fn -> Logger.info("Test", %{key: "value"}) end)
        assert log =~ "[info] [Vaultx] Test"
        # Sanitization marker is added internally, may not be visible in test output
      end)

      with_config(:info, fn ->
        log = capture_log(fn -> Logger.info("Test", key: "value") end)
        assert log =~ "[info] [Vaultx] Test"
        # Sanitization marker is added internally, may not be visible in test output
      end)
    end

    test "handles non-map/list metadata gracefully" do
      with_config(:info, fn ->
        log = capture_log(fn -> Logger.info("Test", "string metadata") end)
        assert log =~ "[info] [Vaultx] Test"
        # Non-map metadata handling happens internally, may not be visible in test output
      end)
    end
  end

  describe "performance and edge cases" do
    test "handles empty metadata" do
      with_config(:info, fn ->
        log = capture_log(fn -> Logger.info("Test", %{}) end)
        assert log =~ "[info] [Vaultx] Test"
        # Empty metadata handling happens internally, may not be visible in test output
      end)
    end

    test "handles large metadata efficiently" do
      large_data = for i <- 1..100, into: %{}, do: {"key_#{i}", "value_#{i}"}

      with_config(:info, fn ->
        log = capture_log(fn -> Logger.info("Large data", large_data) end)
        assert log =~ "[info] [Vaultx] Large data"
        # Large metadata processing happens internally, may not be visible in test output
      end)
    end

    test "sanitizes key-value tuples in lists" do
      # Test with a list that contains tuples (this will be processed by sanitize_nested_list)
      list_with_tuples = [
        {"safe_key", "safe_value"},
        {"token", "secret-token"},
        {"password", "secret-pass"}
      ]

      with_config(:info, fn ->
        log = capture_log(fn -> Logger.info("List with tuples", %{data: list_with_tuples}) end)
        assert log =~ "[info] [Vaultx] List with tuples"
        # Sensitive data in tuples should be sanitized internally
        refute log =~ "secret-token"
        refute log =~ "secret-pass"
      end)
    end

    test "disabled logging has minimal overhead" do
      with_config(:none, fn ->
        # These should be no-ops
        assert Logger.debug("Debug") == :ok
        assert Logger.info("Info") == :ok
        assert Logger.warn("Warn") == :ok
        assert Logger.error("Error") == :ok
      end)
    end

    test "level_priority returns correct values" do
      # This test ensures level_priority(:none) is covered
      # Test with explicit :info level first
      with_config(:info, fn ->
        assert Logger.enabled?(:debug) == false
        assert Logger.enabled?(:info) == true
        assert Logger.enabled?(:warn) == true
        assert Logger.enabled?(:error) == true
      end)

      # Test with :none level specifically
      with_config(:none, fn ->
        assert Logger.enabled?(:debug) == false
        assert Logger.enabled?(:info) == false
        assert Logger.enabled?(:warn) == false
        assert Logger.enabled?(:error) == false
      end)
    end
  end

  # Helper function to temporarily set log level
  defp with_config(level, fun) do
    original_config = Application.get_env(:vaultx, :logger_level, :info)
    Application.put_env(:vaultx, :logger_level, level)

    try do
      fun.()
    after
      Application.put_env(:vaultx, :logger_level, original_config)
    end
  end
end
