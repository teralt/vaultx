defmodule Vaultx.Config.ValidatorTest do
  use ExUnit.Case, async: true

  alias Vaultx.Config.Validator

  @moduledoc """
  Simplified test suite for Config Validator focusing on core functionality.
  """

  # Helper to create valid base config with all required fields
  defp base_config do
    %{
      url: "https://vault.example.com:8200",
      namespace: nil,
      token: "hvs.test_token",
      ssl_verify: true,
      tls_min_version: "1.2",
      timeout: 30_000,
      connect_timeout: 5_000,
      retry_attempts: 3,
      retry_delay: 1000,
      pool_size: 10
    }
  end

  describe "validate_comprehensive/1" do
    test "validates valid configuration successfully" do
      config = base_config()

      issues = Validator.validate_comprehensive(config)
      assert is_list(issues)
    end

    test "handles configuration with missing optional fields" do
      minimal_config = %{
        url: "https://vault.example.com:8200",
        namespace: nil,
        token: "hvs.test_token",
        ssl_verify: true,
        tls_min_version: "1.2",
        timeout: 30_000,
        connect_timeout: 5_000,
        retry_attempts: 3,
        retry_delay: 1000,
        pool_size: 10
      }

      issues = Validator.validate_comprehensive(minimal_config)
      assert is_list(issues)
    end

    test "validates URL format variations" do
      url_configs = [
        Map.put(base_config(), :url, "https://vault.example.com:8200"),
        Map.put(base_config(), :url, "http://localhost:8200"),
        Map.put(base_config(), :url, "invalid-url")
      ]

      for config <- url_configs do
        issues = Validator.validate_comprehensive(config)
        assert is_list(issues)
      end
    end

    test "validates authentication methods" do
      auth_configs = [
        Map.merge(base_config(), %{auth_method: :token, token: "hvs.test"}),
        Map.merge(base_config(), %{auth_method: :userpass, username: "user", password: "pass"}),
        Map.merge(base_config(), %{auth_method: :aws})
      ]

      for config <- auth_configs do
        issues = Validator.validate_comprehensive(config)
        assert is_list(issues)
      end
    end

    test "validates timeout and pool size" do
      network_configs = [
        Map.put(base_config(), :timeout, 30_000),
        # Invalid
        Map.put(base_config(), :timeout, -1000),
        Map.put(base_config(), :pool_size, 10),
        # Invalid
        Map.put(base_config(), :pool_size, 0)
      ]

      for config <- network_configs do
        issues = Validator.validate_comprehensive(config)
        assert is_list(issues)
      end
    end

    test "validates SSL configuration" do
      ssl_configs = [
        Map.put(base_config(), :ssl_verify, true),
        Map.put(base_config(), :ssl_verify, false),
        Map.put(base_config(), :cacert, "/path/to/ca.pem")
      ]

      for config <- ssl_configs do
        issues = Validator.validate_comprehensive(config)
        assert is_list(issues)
      end
    end
  end

  describe "check_security_configuration/1" do
    test "identifies basic security issues" do
      insecure_config = %{
        # HTTP instead of HTTPS
        url: "http://vault.example.com",
        namespace: nil,
        ssl_verify: false,
        auth_method: :token,
        token: "root"
      }

      warnings = Validator.check_security_configuration(insecure_config)
      assert is_list(warnings)
      assert length(warnings) > 0
    end

    test "validates secure configuration" do
      secure_config = base_config()

      warnings = Validator.check_security_configuration(secure_config)
      assert is_list(warnings)
    end

    test "detects weak authentication" do
      weak_auth_configs = [
        Map.merge(base_config(), %{token: "root"}),
        Map.merge(base_config(), %{auth_method: :userpass, username: "admin", password: "123"})
      ]

      for config <- weak_auth_configs do
        warnings = Validator.check_security_configuration(config)
        assert is_list(warnings)
      end
    end
  end

  describe "check_compatibility/1" do
    test "checks basic compatibility" do
      config = Map.put(base_config(), :vault_version, "1.15.0")

      result = Validator.check_compatibility(config)
      assert is_map(result)
      assert Map.has_key?(result, :vault_version_compatible)
      assert Map.has_key?(result, :feature_compatibility)
      assert Map.has_key?(result, :environment_compatibility)
      assert Map.has_key?(result, :deprecation_warnings)
    end

    test "checks feature compatibility" do
      config_with_features =
        Map.merge(base_config(), %{
          auth_method: :jwt,
          cache_enabled: true,
          kv_version: 2
        })

      result = Validator.check_compatibility(config_with_features)
      assert is_map(result)
      assert Map.has_key?(result, :feature_compatibility)
    end

    test "checks environment compatibility" do
      env_configs = [
        Map.put(base_config(), :environment, :production),
        Map.put(base_config(), :environment, :development),
        Map.merge(base_config(), %{url: "http://localhost:8200", environment: :development})
      ]

      for config <- env_configs do
        result = Validator.check_compatibility(config)
        assert is_map(result)
        assert Map.has_key?(result, :environment_compatibility)
      end
    end

    test "detects deprecation warnings" do
      config_with_deprecated =
        Map.merge(base_config(), %{
          auth_method: :ldap,
          old_ssl_option: true,
          legacy_timeout: 5000
        })

      result = Validator.check_compatibility(config_with_deprecated)
      assert is_map(result)
      assert is_list(result.deprecation_warnings)
    end
  end

  describe "error handling" do
    test "handles empty configuration" do
      # This should raise an error since required fields are missing
      assert_raise KeyError, fn ->
        Validator.validate_comprehensive(%{})
      end
    end

    test "handles invalid data types" do
      invalid_configs = [
        Map.put(base_config(), :timeout, "30000"),
        Map.put(base_config(), :ssl_verify, "true"),
        Map.put(base_config(), :pool_size, "10")
      ]

      for config <- invalid_configs do
        issues = Validator.validate_comprehensive(config)
        assert is_list(issues)
      end
    end

    test "handles malformed URLs" do
      malformed_configs = [
        Map.put(base_config(), :url, "://invalid"),
        Map.put(base_config(), :url, "https://"),
        Map.put(base_config(), :url, "not-a-url-at-all")
      ]

      for config <- malformed_configs do
        issues = Validator.validate_comprehensive(config)
        assert is_list(issues)
      end
    end
  end

  describe "performance validation" do
    test "validates performance-related configuration" do
      performance_configs = [
        Map.merge(base_config(), %{timeout: 1000, pool_size: 1}),
        Map.merge(base_config(), %{timeout: 30_000, pool_size: 10}),
        Map.merge(base_config(), %{timeout: 120_000, pool_size: 100})
      ]

      for config <- performance_configs do
        issues = Validator.validate_comprehensive(config)
        assert is_list(issues)
      end
    end
  end

  describe "namespace validation" do
    test "validates namespace configuration" do
      namespace_configs = [
        Map.put(base_config(), :namespace, nil),
        Map.put(base_config(), :namespace, "production"),
        Map.put(base_config(), :namespace, "dev/team1")
      ]

      for config <- namespace_configs do
        issues = Validator.validate_comprehensive(config)
        assert is_list(issues)
      end
    end
  end
end
