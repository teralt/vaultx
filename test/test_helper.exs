# Configure ExUnit for comprehensive testing
ExUnit.start(
  capture_log: true,
  max_failures: 30,
  timeout: 30_000,
  exclude: [:integration, :performance, :slow]
)

# Configure Mox for testing
# Mocks are defined in test/support/mocks.ex

# Set test configuration to use mocks
Application.put_env(:vaultx, :url, "http://localhost:8200")
Application.put_env(:vaultx, :token, "test-token")
Application.put_env(:vaultx, :timeout, 30000)
# Disable retries in tests to maximize speed
Application.put_env(:vaultx, :retry_attempts, 0)
Application.put_env(:vaultx, :retry_delay, 1)
Application.put_env(:vaultx, :logger_level, :none)
Application.put_env(:vaultx, :telemetry_enabled, false)

# Override HTTP client to use mock
Application.put_env(:vaultx, :http_client, Vaultx.HTTPClientMock)

# Test support modules are automatically loaded from test/support/
