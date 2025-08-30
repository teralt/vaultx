# VaultX Configuration

VaultX provides comprehensive configuration management with support for environment variables, application configuration, and runtime validation. This guide covers all available configuration options and best practices.

## Configuration Philosophy

VaultX follows modern Elixir library conventions:

- **Stateless**: No GenServer or caching, pure function-based configuration
- **Dynamic**: Configuration changes take effect immediately
- **Hierarchical**: Environment variables override application configuration
- **Validated**: Comprehensive validation using NimbleOptions
- **Secure**: Built-in security validation and best practices

## Configuration Sources

Configuration is resolved in the following priority order:

1. **Environment variables** (highest priority)
2. **Application configuration**
3. **Default values** (lowest priority)

## Core Configuration

### Basic Settings

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `url` | `VAULTX_URL` or `VAULT_ADDR` | `http://localhost:8200` | Vault server URL |
| `token` | `VAULTX_TOKEN` or `VAULT_TOKEN` | `nil` | Authentication token |
| `namespace` | `VAULTX_NAMESPACE` or `VAULT_NAMESPACE` | `nil` | Vault namespace (Enterprise) |

### Network & Timeouts

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `timeout` | `VAULTX_TIMEOUT` | `30000` | Request timeout (ms) |
| `connect_timeout` | `VAULTX_CONNECT_TIMEOUT` | `10000` | Connection timeout (ms) |
| `retry_attempts` | `VAULTX_RETRY_ATTEMPTS` | `3` | Number of retry attempts |
| `retry_delay` | `VAULTX_RETRY_DELAY` | `1000` | Initial retry delay (ms) |
| `retry_backoff` | `VAULTX_RETRY_BACKOFF` | `exponential` | Backoff strategy (linear/exponential) |
| `max_retry_delay` | `VAULTX_MAX_RETRY_DELAY` | `30000` | Maximum retry delay (ms) |

### SSL/TLS Configuration

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `ssl_verify` | `VAULTX_SSL_VERIFY` | `true` | Enable SSL verification |
| `cacert` | `VAULTX_CACERT` or `VAULT_CACERT` | `nil` | CA certificate file path |
| `cacerts_dir` | `VAULTX_CACERTS_DIR` | `nil` | Directory of CA certificates (loaded into :cacerts) |
| `client_cert` | `VAULTX_CLIENT_CERT` or `VAULT_CLIENT_CERT` | `nil` | Client certificate (mTLS) |
| `client_key` | `VAULTX_CLIENT_KEY` or `VAULT_CLIENT_KEY` | `nil` | Client private key (mTLS) |
| `tls_server_name` | `VAULTX_TLS_SERVER_NAME` | `nil` | TLS SNI server name |
| `tls_min_version` | `VAULTX_TLS_MIN_VERSION` | `1.2` | Minimum TLS version |

### Connection Pool

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `pool_size` | `VAULTX_POOL_SIZE` | `10` | Connection pool size |
| `pool_max_idle_time` | `VAULTX_POOL_MAX_IDLE_TIME` | `300000` | Max idle time (ms) |

### Logging & Telemetry

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `logger_level` | `VAULTX_LOGGER_LEVEL` | `info` | Logger level |
| `telemetry_enabled` | `VAULTX_TELEMETRY_ENABLED` | `true` | Enable telemetry |
| `audit_enabled` | `VAULTX_AUDIT_ENABLED` | `false` | Enable audit logging |
| `metrics_enabled` | `VAULTX_METRICS_ENABLED` | `true` | Enable metrics |

### Security & Compliance

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `rate_limit_enabled` | `VAULTX_RATE_LIMIT_ENABLED` | `false` | Enable rate limiting |
| `rate_limit_requests` | `VAULTX_RATE_LIMIT_REQUESTS` | `100` | Requests per second (per-bucket: host\|namespace) |
| `rate_limit_burst` | `VAULTX_RATE_LIMIT_BURST` | `0` | Additional burst tokens allowed |
| `token_renewal_enabled` | `VAULTX_TOKEN_RENEWAL_ENABLED` | `true` | Auto token renewal |
| `token_renewal_threshold` | `VAULTX_TOKEN_RENEWAL_THRESHOLD` | `80` | Renewal threshold (%) |
| `security_headers_enabled` | `VAULTX_SECURITY_HEADERS_ENABLED` | `false` | Validate security headers (non-fatal warnings) |

## Usage Examples

### Basic Configuration

```elixir
# Get complete configuration
config = Vaultx.Base.Config.get()

# Get specific values
url = Vaultx.Base.Config.get_url()
timeout = Vaultx.Base.Config.get_timeout()
```

### Environment Variables

```bash
# Core settings
export VAULTX_URL="https://vault.example.com:8200"
export VAULTX_TOKEN="hvs.CAESIJ..."
export VAULTX_NAMESPACE="my-namespace"

# SSL/TLS settings
export VAULTX_SSL_VERIFY="true"
export VAULTX_CACERT="/etc/ssl/certs/vault-ca.pem"
export VAULTX_CLIENT_CERT="/etc/ssl/certs/client.pem"
export VAULTX_CLIENT_KEY="/etc/ssl/private/client-key.pem"
export VAULTX_CACERTS_DIR="/etc/ssl/certs"

# Performance tuning
export VAULTX_TIMEOUT="60000"
export VAULTX_RETRY_ATTEMPTS="5"
export VAULTX_POOL_SIZE="20"
```

### Application Configuration

```elixir
# config/config.exs
config :vaultx,
  url: "https://vault.example.com:8200",
  timeout: 30_000,
  retry_attempts: 3,
  ssl_verify: true,
  pool_size: 10
```

### Configuration Validation

```elixir
# Validate configuration
case Vaultx.Base.Config.validate() do
  :ok -> :ok
  {:error, errors} -> handle_errors(errors)
end

# Get detailed diagnostics
diagnostics = Vaultx.Base.Config.diagnose()
IO.inspect(diagnostics)
```

### Convenience Functions

```elixir
# Check SSL configuration
Vaultx.Base.Config.ssl_configured?()
Vaultx.Base.Config.mtls_configured?()

# Get grouped configurations
retry_config = Vaultx.Base.Config.get_retry_config()
pool_config = Vaultx.Base.Config.get_pool_config()
# => %{size: 10, max_idle_time: 300_000}

# Print configuration summary
Vaultx.Base.Config.print_summary()
```

## Best Practices

### Security

1. **Always use HTTPS** in production environments
2. **Enable SSL verification** (`ssl_verify: true`)
3. **Use strong TLS versions** (prefer TLS 1.3)
4. **Implement mutual TLS** for high-security environments
5. **Enable audit logging** for compliance requirements

### Performance

1. **Tune connection pools** based on your workload
2. **Configure appropriate timeouts** for your network
3. **Use exponential backoff** for retry strategies
4. **Enable metrics** for monitoring
5. **Consider rate limiting** to protect Vault

### Reliability

1. **Configure retry attempts** appropriately
2. **Set reasonable timeouts** to avoid hanging requests
3. **Enable token renewal** for long-running applications
4. **Monitor configuration diagnostics** regularly

### Development vs Production

```elixir
# Development
config :vaultx,
  url: "http://localhost:8200",
  ssl_verify: false,
  logger_level: :debug

# Production
config :vaultx,
  url: {:system, "VAULTX_URL"},
  ssl_verify: true,
  logger_level: :info,
  audit_enabled: true
```

## Troubleshooting

### Common Issues

1. **SSL Certificate Errors**: Check `cacert` and `ssl_verify` settings
2. **Connection Timeouts**: Adjust `timeout` and `connect_timeout`
3. **Pool Exhaustion**: Increase `pool_size`
4. **Authentication Failures**: Verify `token` and `namespace` settings

### Diagnostic Tools

```elixir
# Run comprehensive diagnostics
diagnostics = Vaultx.Base.Config.diagnose()

# Check for warnings and recommendations
if not Enum.empty?(diagnostics.warnings) do
  IO.puts("Warnings: #{inspect(diagnostics.warnings)}")
end

# Print configuration summary
Vaultx.Base.Config.print_summary()
```

## Migration Guide

### From Previous Versions

The Vaultx library was only officially released to the public starting from version v0.6.0, so there is currently no relevant content for this entry.
