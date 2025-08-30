#!/usr/bin/env elixir

# VaultX Configuration Examples
# This script demonstrates the enhanced configuration capabilities of VaultX

# Add the current directory to the code path so we can load VaultX
Code.prepend_path("lib")
Code.prepend_path("_build/dev/lib/vaultx/ebin")

# Load the compiled modules
Code.ensure_loaded(Vaultx.Base.Config)

# Start the application
Application.ensure_all_started(:vaultx)

alias Vaultx.Base.Config

IO.puts("=== VaultX Enhanced Configuration Examples ===\n")

# Example 1: Basic Configuration
IO.puts("1. Basic Configuration:")
config = Config.get()
IO.puts("   URL: #{config.url}")
IO.puts("   Timeout: #{config.timeout}ms")
IO.puts("   SSL Verify: #{config.ssl_verify}")
IO.puts("   Pool Size: #{config.pool_size}")

# Example 2: Environment Variable Configuration
IO.puts("\n2. Environment Variable Configuration:")
IO.puts("   Set environment variables to override defaults:")
IO.puts("   export VAULTX_URL=https://vault.example.com:8200")
IO.puts("   export VAULTX_TIMEOUT=60000")
IO.puts("   export VAULTX_SSL_VERIFY=true")
IO.puts("   export VAULTX_RETRY_BACKOFF=exponential")

# Example 3: SSL/TLS Configuration
IO.puts("\n3. SSL/TLS Configuration:")
IO.puts("   SSL Configured: #{Config.ssl_configured?()}")
IO.puts("   mTLS Configured: #{Config.mtls_configured?()}")
IO.puts("   TLS Min Version: #{Config.get_tls_min_version()}")

# Example 4: Retry Configuration
IO.puts("\n4. Retry Configuration:")
retry_config = Config.get_retry_config()
IO.puts("   Attempts: #{retry_config.attempts}")
IO.puts("   Delay: #{retry_config.delay}ms")
IO.puts("   Backoff: #{retry_config.backoff}")
IO.puts("   Max Delay: #{retry_config.max_delay}ms")

# Example 5: Pool Configuration
IO.puts("\n5. Connection Pool Configuration:")
pool_config = Config.get_pool_config()
IO.puts("   Size: #{pool_config.size}")
IO.puts("   Max Idle Time: #{pool_config.max_idle_time}ms")

# Example 6: Security Features
IO.puts("\n6. Security Features:")
IO.puts("   Audit Enabled: #{Config.get_audit_enabled()}")
IO.puts("   Rate Limiting: #{Config.get_rate_limit_enabled()}")
IO.puts("   Token Renewal: #{Config.get_token_renewal_enabled()}")
IO.puts("   Security Headers: #{Config.get_security_headers_enabled()}")

# Example 7: Configuration Validation
IO.puts("\n7. Configuration Validation:")
case Config.validate() do
  :ok -> IO.puts("   ✓ Configuration is valid")
  {:error, errors} -> IO.puts("   ✗ Configuration errors: #{inspect(errors)}")
end

# Example 8: Configuration Diagnostics
IO.puts("\n8. Configuration Diagnostics:")
diagnostics = Config.diagnose()
IO.puts("   Valid: #{diagnostics.valid}")
IO.puts("   Warnings: #{length(diagnostics.warnings)}")
IO.puts("   Errors: #{length(diagnostics.errors)}")
IO.puts("   Recommendations: #{length(diagnostics.recommendations)}")

if not Enum.empty?(diagnostics.warnings) do
  IO.puts("\n   Warnings:")
  Enum.each(diagnostics.warnings, fn warning ->
    IO.puts("   - #{warning}")
  end)
end

if not Enum.empty?(diagnostics.recommendations) do
  IO.puts("\n   Recommendations:")
  Enum.each(diagnostics.recommendations, fn rec ->
    IO.puts("   - #{rec}")
  end)
end

# Example 9: Configuration Summary
IO.puts("\n9. Configuration Summary:")
Config.print_summary()

# Example 10: Advanced Environment Variables
IO.puts("10. Advanced Environment Variables:")
IO.puts("    Core Configuration:")
IO.puts("    - VAULTX_URL or VAULT_ADDR")
IO.puts("    - VAULTX_TOKEN or VAULT_TOKEN")
IO.puts("    - VAULTX_NAMESPACE or VAULT_NAMESPACE")
IO.puts("")
IO.puts("    SSL/TLS Configuration:")
IO.puts("    - VAULTX_SSL_VERIFY")
IO.puts("    - VAULTX_CACERT or VAULT_CACERT")
IO.puts("    - VAULTX_CACERTS_DIR")
IO.puts("    - VAULTX_CLIENT_CERT or VAULT_CLIENT_CERT")
IO.puts("    - VAULTX_CLIENT_KEY or VAULT_CLIENT_KEY")
IO.puts("    - VAULTX_TLS_SERVER_NAME")
IO.puts("    - VAULTX_TLS_MIN_VERSION")
IO.puts("")
IO.puts("    Network & Timeouts:")
IO.puts("    - VAULTX_TIMEOUT")
IO.puts("    - VAULTX_CONNECT_TIMEOUT")
IO.puts("    - VAULTX_RETRY_ATTEMPTS")
IO.puts("    - VAULTX_RETRY_DELAY")
IO.puts("    - VAULTX_RETRY_BACKOFF")
IO.puts("    - VAULTX_MAX_RETRY_DELAY")
IO.puts("")
IO.puts("    Connection Pool:")
IO.puts("    - VAULTX_POOL_SIZE")
IO.puts("    - VAULTX_POOL_MAX_IDLE_TIME")
IO.puts("")
IO.puts("    Security & Compliance:")
IO.puts("    - VAULTX_AUDIT_ENABLED")
IO.puts("    - VAULTX_RATE_LIMIT_ENABLED")
IO.puts("    - VAULTX_RATE_LIMIT_REQUESTS")
IO.puts("    - VAULTX_TOKEN_RENEWAL_ENABLED")
IO.puts("    - VAULTX_TOKEN_RENEWAL_THRESHOLD")
IO.puts("    - VAULTX_SECURITY_HEADERS_ENABLED")

IO.puts("\n=== End of Configuration Examples ===")
