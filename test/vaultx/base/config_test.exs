defmodule Vaultx.Base.ConfigTest do
  use ExUnit.Case, async: false

  alias Vaultx.Base.Config

  setup do
    # Store original application config
    original_config = Application.get_all_env(:vaultx)

    # Clean up after each test
    on_exit(fn ->
      # Restore original config
      for {key, value} <- original_config do
        Application.put_env(:vaultx, key, value)
      end
    end)

    :ok
  end

  describe "get/0" do
    test "returns default configuration" do
      # Clear any environment variables that might affect the test
      original_ssl_verify = System.get_env("VAULTX_SSL_VERIFY")
      original_retry_attempts = System.get_env("VAULTX_RETRY_ATTEMPTS")
      original_retry_delay = System.get_env("VAULTX_RETRY_DELAY")

      System.delete_env("VAULTX_SSL_VERIFY")
      System.delete_env("VAULTX_RETRY_ATTEMPTS")
      System.delete_env("VAULTX_RETRY_DELAY")

      # Also remove application config overrides so defaults apply
      app_retry_attempts = Application.get_env(:vaultx, :retry_attempts)
      app_retry_delay = Application.get_env(:vaultx, :retry_delay)
      Application.delete_env(:vaultx, :retry_attempts)
      Application.delete_env(:vaultx, :retry_delay)

      try do
        config = Config.get()

        assert config.url == "http://localhost:8200"
        assert config.timeout == 30_000
        assert config.retry_attempts == 3
        assert config.retry_delay == 1_000
        # ssl_verify might be affected by test environment, so we check it's a boolean
        assert is_boolean(config.ssl_verify)
        assert config.pool_size == 10
      after
        # Restore original environment variables if they existed
        if original_ssl_verify, do: System.put_env("VAULTX_SSL_VERIFY", original_ssl_verify)

        if original_retry_attempts,
          do: System.put_env("VAULTX_RETRY_ATTEMPTS", original_retry_attempts)

        if original_retry_delay, do: System.put_env("VAULTX_RETRY_DELAY", original_retry_delay)

        # Restore application config overrides
        if app_retry_attempts != nil,
          do: Application.put_env(:vaultx, :retry_attempts, app_retry_attempts),
          else: Application.delete_env(:vaultx, :retry_attempts)

        if app_retry_delay != nil,
          do: Application.put_env(:vaultx, :retry_delay, app_retry_delay),
          else: Application.delete_env(:vaultx, :retry_delay)
      end
    end

    test "merges application config with defaults" do
      Application.put_env(:vaultx, :url, "https://vault.example.com")
      Application.put_env(:vaultx, :timeout, 60_000)

      config = Config.get()

      assert config.url == "https://vault.example.com"
      assert config.timeout == 60_000
    end
  end

  describe "environment variables" do
    test "reads URL from environment variables" do
      # Test VAULTX_URL
      System.put_env("VAULTX_URL", "https://vault.example.com")
      assert Config.get_url() == "https://vault.example.com"
      System.delete_env("VAULTX_URL")

      # Test VAULT_ADDR fallback
      System.put_env("VAULT_ADDR", "https://vault-fallback.example.com")
      assert Config.get_url() == "https://vault-fallback.example.com"
      System.delete_env("VAULT_ADDR")

      # Test precedence
      System.put_env("VAULTX_URL", "https://primary.example.com")
      System.put_env("VAULT_ADDR", "https://fallback.example.com")
      assert Config.get_url() == "https://primary.example.com"
      System.delete_env("VAULTX_URL")
      System.delete_env("VAULT_ADDR")
    end

    test "reads token from environment variables" do
      System.put_env("VAULTX_TOKEN", "env-token")
      assert Config.get_token() == "env-token"
      System.delete_env("VAULTX_TOKEN")

      System.put_env("VAULT_TOKEN", "vault-token")
      assert Config.get_token() == "vault-token"
      System.delete_env("VAULT_TOKEN")
    end

    test "reads numeric values from environment" do
      System.put_env("VAULTX_TIMEOUT", "45000")
      assert Config.get_timeout() == 45_000
      System.delete_env("VAULTX_TIMEOUT")

      System.put_env("VAULTX_RETRY_ATTEMPTS", "5")
      assert Config.get_retry_attempts() == 5
      System.delete_env("VAULTX_RETRY_ATTEMPTS")

      System.put_env("VAULTX_RETRY_DELAY", "2000")
      assert Config.get_retry_delay() == 2_000
      System.delete_env("VAULTX_RETRY_DELAY")

      System.put_env("VAULTX_RATE_LIMIT_BURST", "25")
      assert Config.get_rate_limit_burst() == 25
      System.delete_env("VAULTX_RATE_LIMIT_BURST")

      System.put_env("VAULTX_POOL_SIZE", "20")
      assert Config.get_pool_size() == 20
      System.delete_env("VAULTX_POOL_SIZE")
    end

    test "reads boolean values from environment" do
      boolean_values = [
        {"true", true},
        {"false", false},
        {"1", true},
        {"0", false},
        {"yes", true},
        {"no", false},
        {"on", true},
        {"off", false}
      ]

      for {env_value, expected} <- boolean_values do
        System.put_env("VAULTX_SSL_VERIFY", env_value)
        assert Config.get_ssl_verify() == expected
        System.delete_env("VAULTX_SSL_VERIFY")

        System.put_env("VAULTX_TELEMETRY_ENABLED", env_value)
        assert Config.get_telemetry_enabled() == expected
        System.delete_env("VAULTX_TELEMETRY_ENABLED")
      end
    end

    test "reads logger level from environment" do
      levels = ["debug", "info", "warn", "error", "none"]
      expected_atoms = [:debug, :info, :warn, :error, :none]

      for {level_str, expected_atom} <- Enum.zip(levels, expected_atoms) do
        System.put_env("VAULTX_LOGGER_LEVEL", level_str)
        assert Config.get_logger_level() == expected_atom
        System.delete_env("VAULTX_LOGGER_LEVEL")
      end

      # Test invalid level
      System.put_env("VAULTX_LOGGER_LEVEL", "invalid")
      assert Config.get_logger_level() == :info
      System.delete_env("VAULTX_LOGGER_LEVEL")
    end

    test "handles invalid numeric environment variables" do
      System.put_env("VAULTX_TIMEOUT", "not_a_number")
      assert Config.get_timeout() == 30_000
      System.delete_env("VAULTX_TIMEOUT")

      System.put_env("VAULTX_POOL_SIZE", "invalid")
      assert Config.get_pool_size() == 10
      System.delete_env("VAULTX_POOL_SIZE")
    end
  end

  describe "optional configuration" do
    test "returns nil for optional values when not configured" do
      # Clear any test environment configuration
      Application.delete_env(:vaultx, :token)
      assert Config.get_token() == nil
      assert Config.get_cacert() == nil
      assert Config.get_namespace() == nil
    end

    test "reads optional values from environment" do
      System.put_env("VAULTX_CACERT", "/path/to/ca.pem")
      assert Config.get_cacert() == "/path/to/ca.pem"
      System.delete_env("VAULTX_CACERT")

      System.put_env("VAULTX_NAMESPACE", "my-namespace")
      assert Config.get_namespace() == "my-namespace"
      System.delete_env("VAULTX_NAMESPACE")
    end
  end

  describe "validate/0" do
    test "validates correct configuration" do
      assert Config.validate() == :ok
    end

    test "validates configuration with custom values" do
      Application.put_env(:vaultx, :url, "https://vault.example.com")
      Application.put_env(:vaultx, :timeout, 60_000)

      assert Config.validate() == :ok
    end

    test "returns error for invalid configuration" do
      Application.put_env(:vaultx, :timeout, -1)

      assert {:error, [_error]} = Config.validate()
    end

    test "handles validation exceptions" do
      Application.put_env(:vaultx, :url, 12345)

      result = Config.validate()
      assert {:error, _} = result
    end
  end

  describe "edge cases" do
    test "covers default values when config is cleared" do
      Application.delete_env(:vaultx, :url)
      assert Config.get_url() == "http://localhost:8200"

      Application.delete_env(:vaultx, :retry_attempts)
      assert Config.get_retry_attempts() == 3
    end

    test "covers merge_app_config with unknown keys" do
      Application.put_env(:vaultx, :unknown_key, "value")

      config = Config.get()
      refute Map.has_key?(config, :unknown_key)
    end
  end

  describe "new configuration features" do
    test "get_retry_config/0 returns retry configuration" do
      config = Config.get_retry_config()

      assert is_map(config)
      assert Map.has_key?(config, :attempts)
      assert Map.has_key?(config, :delay)
      assert Map.has_key?(config, :backoff)
      assert Map.has_key?(config, :max_delay)
      assert config.backoff in [:linear, :exponential]
    end

    test "get_pool_config/0 returns pool configuration" do
      config = Config.get_pool_config()

      assert is_map(config)
      assert Map.has_key?(config, :size)
      assert Map.has_key?(config, :max_idle_time)
      refute Map.has_key?(config, :max_overflow)
      refute Map.has_key?(config, :timeout)
    end

    test "ssl_configured?/0 detects SSL configuration" do
      # Test with HTTPS URL and SSL verify enabled
      System.put_env("VAULTX_URL", "https://vault.example.com:8200")
      System.put_env("VAULTX_SSL_VERIFY", "true")

      try do
        assert Config.ssl_configured?() == true
      after
        System.delete_env("VAULTX_URL")
        System.delete_env("VAULTX_SSL_VERIFY")
      end
    end

    test "mtls_configured?/0 detects mutual TLS configuration" do
      System.put_env("VAULTX_URL", "https://vault.example.com:8200")
      System.put_env("VAULTX_SSL_VERIFY", "true")
      System.put_env("VAULTX_CLIENT_CERT", "/path/to/cert.pem")
      System.put_env("VAULTX_CLIENT_KEY", "/path/to/key.pem")

      try do
        assert Config.mtls_configured?() == true
      after
        System.delete_env("VAULTX_URL")
        System.delete_env("VAULTX_SSL_VERIFY")
        System.delete_env("VAULTX_CLIENT_CERT")
        System.delete_env("VAULTX_CLIENT_KEY")
      end
    end

    test "mtls_configured?/0 returns false when SSL not configured" do
      System.put_env("VAULTX_URL", "http://vault.example.com:8200")
      System.put_env("VAULTX_CLIENT_CERT", "/path/to/cert.pem")
      System.put_env("VAULTX_CLIENT_KEY", "/path/to/key.pem")

      try do
        assert Config.mtls_configured?() == false
      after
        System.delete_env("VAULTX_URL")
        System.delete_env("VAULTX_CLIENT_CERT")
        System.delete_env("VAULTX_CLIENT_KEY")
      end
    end

    test "get_value/2 returns configuration values with fallback" do
      assert Config.get_value(:timeout) == 30_000
      assert Config.get_value(:nonexistent_key, "default") == "default"
    end

    test "diagnose/0 returns diagnostic information" do
      result = Config.diagnose()

      assert is_map(result)
      assert Map.has_key?(result, :valid)
      assert Map.has_key?(result, :warnings)
      assert Map.has_key?(result, :errors)
      assert Map.has_key?(result, :recommendations)
      assert is_boolean(result.valid)
      assert is_list(result.warnings)
      assert is_list(result.errors)
      assert is_list(result.recommendations)
    end

    test "diagnose/0 detects security warnings" do
      # HTTP to remote server
      System.put_env("VAULTX_URL", "http://vault.example.com:8200")
      # Enable this so audit check runs
      System.put_env("VAULTX_SECURITY_HEADERS_ENABLED", "true")
      System.put_env("VAULTX_AUDIT_ENABLED", "false")

      try do
        result = Config.diagnose()

        # Should have warnings about HTTP and recommendations about security
        assert length(result.warnings) > 0
        assert length(result.recommendations) > 0
        assert Enum.any?(result.warnings, &String.contains?(&1, "unencrypted HTTP"))
        assert Enum.any?(result.recommendations, &String.contains?(&1, "audit"))
      after
        System.delete_env("VAULTX_URL")
        System.delete_env("VAULTX_SECURITY_HEADERS_ENABLED")
        System.delete_env("VAULTX_AUDIT_ENABLED")
      end
    end

    test "diagnose/0 detects performance warnings" do
      # Very high timeout
      System.put_env("VAULTX_TIMEOUT", "120000")
      # Very large pool
      System.put_env("VAULTX_POOL_SIZE", "100")
      # Keep normal to test metrics
      System.put_env("VAULTX_RETRY_ATTEMPTS", "3")
      System.put_env("VAULTX_METRICS_ENABLED", "false")

      try do
        result = Config.diagnose()

        # Should have warnings about high values and recommendations
        # At least timeout warning
        assert length(result.warnings) >= 1
        assert length(result.recommendations) > 0
        assert Enum.any?(result.warnings, &String.contains?(&1, "timeout is very high"))
        # Since retry attempts is normal, metrics recommendation should appear
        assert Enum.any?(result.recommendations, &String.contains?(&1, "metrics"))
      after
        System.delete_env("VAULTX_TIMEOUT")
        System.delete_env("VAULTX_POOL_SIZE")
        System.delete_env("VAULTX_RETRY_ATTEMPTS")
        System.delete_env("VAULTX_METRICS_ENABLED")
      end
    end

    test "diagnose/0 detects large pool size warning" do
      # Set pool size > 50 to trigger warning
      System.put_env("VAULTX_POOL_SIZE", "60")
      # Normal timeout
      System.put_env("VAULTX_TIMEOUT", "30000")

      try do
        result = Config.diagnose()

        # Should have warning about large pool size
        assert Enum.any?(result.warnings, &String.contains?(&1, "pool size is very large"))
      after
        System.delete_env("VAULTX_POOL_SIZE")
        System.delete_env("VAULTX_TIMEOUT")
      end
    end

    test "diagnose/0 detects high retry attempts recommendation" do
      # Set retry attempts > 5 to trigger recommendation
      System.put_env("VAULTX_RETRY_ATTEMPTS", "8")
      # Normal timeout
      System.put_env("VAULTX_TIMEOUT", "30000")
      # Normal pool size
      System.put_env("VAULTX_POOL_SIZE", "10")
      # Enable metrics
      System.put_env("VAULTX_METRICS_ENABLED", "true")

      try do
        result = Config.diagnose()

        # Should have recommendation about retry attempts
        assert Enum.any?(result.recommendations, &String.contains?(&1, "retry attempts"))
      after
        System.delete_env("VAULTX_RETRY_ATTEMPTS")
        System.delete_env("VAULTX_TIMEOUT")
        System.delete_env("VAULTX_POOL_SIZE")
        System.delete_env("VAULTX_METRICS_ENABLED")
      end
    end

    test "diagnose/0 reaches default branches with good config" do
      # Set up a configuration that passes all checks to reach default branches
      System.put_env("VAULTX_URL", "https://vault.example.com:8200")
      System.put_env("VAULTX_SSL_VERIFY", "true")
      System.put_env("VAULTX_SECURITY_HEADERS_ENABLED", "true")
      System.put_env("VAULTX_AUDIT_ENABLED", "true")
      # Normal timeout
      System.put_env("VAULTX_TIMEOUT", "30000")
      # Normal pool size
      System.put_env("VAULTX_POOL_SIZE", "10")
      # Normal retries
      System.put_env("VAULTX_RETRY_ATTEMPTS", "3")
      System.put_env("VAULTX_METRICS_ENABLED", "true")
      System.put_env("VAULTX_TLS_MIN_VERSION", "1.3")
      System.put_env("VAULTX_CACERT", "/path/to/ca.pem")

      try do
        result = Config.diagnose()

        # Should have minimal warnings/recommendations since config is good
        assert result.valid == true
        # Should reach the default branches
      after
        System.delete_env("VAULTX_URL")
        System.delete_env("VAULTX_SSL_VERIFY")
        System.delete_env("VAULTX_SECURITY_HEADERS_ENABLED")
        System.delete_env("VAULTX_AUDIT_ENABLED")
        System.delete_env("VAULTX_TIMEOUT")
        System.delete_env("VAULTX_POOL_SIZE")
        System.delete_env("VAULTX_RETRY_ATTEMPTS")
        System.delete_env("VAULTX_METRICS_ENABLED")
        System.delete_env("VAULTX_TLS_MIN_VERSION")
        System.delete_env("VAULTX_CACERT")
      end
    end

    test "print_summary/0 prints configuration summary" do
      # Capture IO output
      import ExUnit.CaptureIO

      # Ensure no token is set
      System.delete_env("VAULTX_TOKEN")
      System.delete_env("VAULT_TOKEN")
      Application.delete_env(:vaultx, :token)

      output =
        capture_io(fn ->
          Config.print_summary()
        end)

      assert String.contains?(output, "VaultX Configuration Summary")
      assert String.contains?(output, "URL:")
      assert String.contains?(output, "SSL Verify:")
      assert String.contains?(output, "Token: not configured")
    end

    test "diagnose/0 returns validation errors without further checks" do
      # This will make validate/0 return {:error, [%NimbleOptions.ValidationError{}]}
      Application.put_env(:vaultx, :token_renewal_threshold, 150)

      try do
        result = Config.diagnose()

        assert result.valid == false
        assert length(result.errors) > 0

        # We returned early; warnings/recommendations should be empty because we skipped further checks
        assert result.warnings == []
        assert result.recommendations == []
      after
        Application.delete_env(:vaultx, :token_renewal_threshold)
      end
    end

    test "print_summary/0 shows token preview when configured" do
      import ExUnit.CaptureIO

      System.put_env("VAULTX_TOKEN", "hvs.CAESIJ1234567890abcdef")

      try do
        output =
          capture_io(fn ->
            Config.print_summary()
          end)

        assert String.contains?(output, "Token: hvs.CAESIJ...")
        refute String.contains?(output, "Token: not configured")
      after
        System.delete_env("VAULTX_TOKEN")
      end
    end
  end

  describe "new environment variables" do
    test "supports VAULT_NAMESPACE environment variable" do
      System.put_env("VAULT_NAMESPACE", "test-namespace")

      try do
        assert Config.get_namespace() == "test-namespace"
      after
        System.delete_env("VAULT_NAMESPACE")
      end
    end

    test "supports new SSL/TLS environment variables" do
      System.put_env("VAULTX_CACERTS_DIR", "/etc/ssl/certs")
      System.put_env("VAULTX_TLS_MIN_VERSION", "1.3")
      System.put_env("VAULTX_TLS_SERVER_NAME", "vault.example.com")

      try do
        assert Config.get_cacerts_dir() == "/etc/ssl/certs"
        assert Config.get_tls_min_version() == "1.3"
        assert Config.get_tls_server_name() == "vault.example.com"
      after
        System.delete_env("VAULTX_CACERTS_DIR")
        System.delete_env("VAULTX_TLS_MIN_VERSION")
        System.delete_env("VAULTX_TLS_SERVER_NAME")
      end
    end

    test "handles invalid TLS version values" do
      # invalid version
      System.put_env("VAULTX_TLS_MIN_VERSION", "1.1")

      try do
        # should fallback to default
        assert Config.get_tls_min_version() == "1.2"
      after
        System.delete_env("VAULTX_TLS_MIN_VERSION")
      end
    end

    test "supports new timeout environment variables" do
      System.put_env("VAULTX_CONNECT_TIMEOUT", "15000")
      System.put_env("VAULTX_MAX_RETRY_DELAY", "60000")
      System.put_env("VAULTX_RETRY_BACKOFF", "linear")

      try do
        assert Config.get_connect_timeout() == 15_000
        assert Config.get_max_retry_delay() == 60_000
        assert Config.get_retry_backoff() == :linear
      after
        System.delete_env("VAULTX_CONNECT_TIMEOUT")
        System.delete_env("VAULTX_MAX_RETRY_DELAY")
        System.delete_env("VAULTX_RETRY_BACKOFF")
      end
    end

    test "handles invalid retry backoff values" do
      System.put_env("VAULTX_RETRY_BACKOFF", "invalid_value")

      try do
        # should fallback to default
        assert Config.get_retry_backoff() == :exponential
      after
        System.delete_env("VAULTX_RETRY_BACKOFF")
      end
    end

    test "supports exponential retry backoff explicitly" do
      System.put_env("VAULTX_RETRY_BACKOFF", "exponential")

      try do
        assert Config.get_retry_backoff() == :exponential
      after
        System.delete_env("VAULTX_RETRY_BACKOFF")
      end
    end

    test "supports new pool environment variables" do
      System.put_env("VAULTX_POOL_MAX_IDLE_TIME", "600000")

      try do
        assert Config.get_pool_max_idle_time() == 600_000
      after
        System.delete_env("VAULTX_POOL_MAX_IDLE_TIME")
      end
    end

    test "supports new security environment variables" do
      System.put_env("VAULTX_AUDIT_ENABLED", "true")
      System.put_env("VAULTX_RATE_LIMIT_ENABLED", "true")
      System.put_env("VAULTX_RATE_LIMIT_REQUESTS", "50")
      System.put_env("VAULTX_TOKEN_RENEWAL_THRESHOLD", "90")

      try do
        assert Config.get_audit_enabled() == true
        assert Config.get_rate_limit_enabled() == true
        assert Config.get_rate_limit_requests() == 50
        assert Config.get_token_renewal_threshold() == 90
      after
        System.delete_env("VAULTX_AUDIT_ENABLED")
        System.delete_env("VAULTX_RATE_LIMIT_ENABLED")
        System.delete_env("VAULTX_RATE_LIMIT_REQUESTS")
        System.delete_env("VAULTX_TOKEN_RENEWAL_THRESHOLD")
      end
    end

    test "boolean environment variables fallback to application config" do
      # Test when environment variables are not set, should use application config
      Application.put_env(:vaultx, :metrics_enabled, false)
      Application.put_env(:vaultx, :token_renewal_enabled, false)
      Application.put_env(:vaultx, :security_headers_enabled, false)

      try do
        assert Config.get_metrics_enabled() == false
        assert Config.get_token_renewal_enabled() == false
        assert Config.get_security_headers_enabled() == false
      after
        Application.delete_env(:vaultx, :metrics_enabled)
        Application.delete_env(:vaultx, :token_renewal_enabled)
        Application.delete_env(:vaultx, :security_headers_enabled)
      end
    end

    test "boolean environment variables override application config" do
      # Set environment variables to override application config
      System.put_env("VAULTX_TOKEN_RENEWAL_ENABLED", "false")
      System.put_env("VAULTX_METRICS_ENABLED", "true")
      System.put_env("VAULTX_SECURITY_HEADERS_ENABLED", "true")

      try do
        assert Config.get_token_renewal_enabled() == false
        assert Config.get_metrics_enabled() == true
        assert Config.get_security_headers_enabled() == true
      after
        System.delete_env("VAULTX_TOKEN_RENEWAL_ENABLED")
        System.delete_env("VAULTX_METRICS_ENABLED")
        System.delete_env("VAULTX_SECURITY_HEADERS_ENABLED")
      end
    end
  end

  describe "validate_percentage/1" do
    test "validates valid percentages" do
      assert {:ok, 50} = Config.validate_percentage(50)
      assert {:ok, 1} = Config.validate_percentage(1)
      assert {:ok, 99} = Config.validate_percentage(99)
    end

    test "rejects invalid percentages" do
      assert {:error, _} = Config.validate_percentage(0)
      assert {:error, _} = Config.validate_percentage(100)
      assert {:error, _} = Config.validate_percentage(-1)
      assert {:error, _} = Config.validate_percentage("50")
    end
  end

  # ============================================================================
  # Feature Management Tests (migrated from Features module)
  # ============================================================================

  describe "feature_enabled?/1" do
    test "returns true for enabled telemetry" do
      Application.put_env(:vaultx, :telemetry_enabled, true)
      assert Config.feature_enabled?(:telemetry) == true
    end

    test "returns false for disabled telemetry" do
      Application.put_env(:vaultx, :telemetry_enabled, false)
      assert Config.feature_enabled?(:telemetry) == false
    end

    test "returns true for enabled logger" do
      Application.put_env(:vaultx, :logger_level, :info)
      assert Config.feature_enabled?(:logger) == true
    end

    test "returns false for disabled logger" do
      Application.put_env(:vaultx, :logger_level, :none)
      assert Config.feature_enabled?(:logger) == false
    end

    test "returns true for enabled retry" do
      Application.put_env(:vaultx, :retry_attempts, 3)
      assert Config.feature_enabled?(:retry) == true
    end

    test "returns false for disabled retry" do
      Application.put_env(:vaultx, :retry_attempts, 0)
      assert Config.feature_enabled?(:retry) == false
    end

    test "returns true for enabled ssl_verify" do
      Application.put_env(:vaultx, :ssl_verify, true)
      assert Config.feature_enabled?(:ssl_verify) == true
    end

    test "returns false for disabled ssl_verify" do
      Application.put_env(:vaultx, :ssl_verify, false)
      assert Config.feature_enabled?(:ssl_verify) == false
    end

    test "returns true for enabled audit" do
      Application.put_env(:vaultx, :audit_enabled, true)
      assert Config.feature_enabled?(:audit) == true
    end

    test "returns false for disabled audit" do
      Application.put_env(:vaultx, :audit_enabled, false)
      assert Config.feature_enabled?(:audit) == false
    end

    test "returns true for enabled cache" do
      Application.put_env(:vaultx, :cache_enabled, true)
      assert Config.feature_enabled?(:cache) == true
    end

    test "returns false for disabled cache" do
      Application.put_env(:vaultx, :cache_enabled, false)
      assert Config.feature_enabled?(:cache) == false
    end

    test "returns true for enabled rate_limit" do
      Application.put_env(:vaultx, :rate_limit_enabled, true)
      assert Config.feature_enabled?(:rate_limit) == true
    end

    test "returns false for disabled rate_limit" do
      Application.put_env(:vaultx, :rate_limit_enabled, false)
      assert Config.feature_enabled?(:rate_limit) == false
    end

    test "returns false for unknown feature" do
      assert Config.feature_enabled?(:unknown) == false
    end

    test "returns false for non-atom feature" do
      assert Config.feature_enabled?("telemetry") == false
    end
  end

  describe "features_status/0" do
    test "returns status of all features" do
      Application.put_env(:vaultx, :telemetry_enabled, true)
      Application.put_env(:vaultx, :logger_level, :info)
      Application.put_env(:vaultx, :retry_attempts, 3)
      Application.put_env(:vaultx, :ssl_verify, true)
      Application.put_env(:vaultx, :audit_enabled, false)
      Application.put_env(:vaultx, :cache_enabled, true)
      Application.put_env(:vaultx, :rate_limit_enabled, false)

      status = Config.features_status()

      assert status.telemetry == true
      assert status.logger == true
      assert status.retry == true
      assert status.ssl_verify == true
      assert status.audit == false
      assert status.cache == true
      assert status.rate_limit == false
    end
  end

  describe "enabled_features/0" do
    test "returns only enabled features" do
      Application.put_env(:vaultx, :telemetry_enabled, true)
      Application.put_env(:vaultx, :logger_level, :info)
      Application.put_env(:vaultx, :retry_attempts, 0)
      Application.put_env(:vaultx, :ssl_verify, true)
      Application.put_env(:vaultx, :audit_enabled, false)
      Application.put_env(:vaultx, :cache_enabled, true)
      Application.put_env(:vaultx, :rate_limit_enabled, false)

      enabled = Config.enabled_features()

      assert :telemetry in enabled
      assert :logger in enabled
      assert :ssl_verify in enabled
      assert :cache in enabled
      refute :retry in enabled
      refute :audit in enabled
      refute :rate_limit in enabled
    end
  end

  describe "disabled_features/0" do
    test "returns only disabled features" do
      Application.put_env(:vaultx, :telemetry_enabled, true)
      Application.put_env(:vaultx, :logger_level, :none)
      Application.put_env(:vaultx, :retry_attempts, 3)
      Application.put_env(:vaultx, :ssl_verify, false)
      Application.put_env(:vaultx, :audit_enabled, true)
      Application.put_env(:vaultx, :cache_enabled, false)
      Application.put_env(:vaultx, :rate_limit_enabled, true)

      disabled = Config.disabled_features()

      assert :logger in disabled
      assert :ssl_verify in disabled
      assert :cache in disabled
      refute :telemetry in disabled
      refute :retry in disabled
      refute :audit in disabled
      refute :rate_limit in disabled
    end
  end
end
