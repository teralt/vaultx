# VaultX Configuration Guide

VaultX v0.7.0 provides a modern, enterprise-grade configuration system with hot reload, comprehensive validation, and intelligent optimization capabilities.

## Configuration Philosophy

- **Hot Reload**: Configuration changes take effect without restarts
- **Hierarchical**: Environment variables → Application config → Defaults
- **Validated**: Comprehensive validation with detailed error reporting
- **Optimized**: Intelligent performance optimization and recommendations
- **Secure**: Built-in security best practices and compliance checks
- **Observable**: Real-time configuration analysis and health monitoring
- **Template-Based**: Environment-specific configuration templates

## Configuration Sources

Configuration is resolved in priority order:

1. **Environment Variables** (highest priority)
2. **Application Configuration** (mix config)
3. **Default Values** (lowest priority)

## Important Notes

> [!IMPORTANT]
> **v0.7.0 Breaking Changes**: This version includes breaking changes in KV behaviour (struct → map) and configuration validation. See [CHANGELOG.md](../CHANGELOG.md) for migration guide.

> [!NOTE]
> **Production Ready**: All caching, configuration, and telemetry features are now production-ready with comprehensive testing and stability guarantees.

> [!TIP]
> **Performance**: Enable caching for up to 90% performance improvement in secret access operations.

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
| `retry_backoff` | `VAULTX_RETRY_BACKOFF` | `exponential` | Backoff strategy |
| `max_retry_delay` | `VAULTX_MAX_RETRY_DELAY` | `30000` | Maximum retry delay (ms) |

### SSL/TLS Configuration

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `ssl_verify` | `VAULTX_SSL_VERIFY` | `true` | Enable SSL verification |
| `cacert` | `VAULTX_CACERT` or `VAULT_CACERT` | `nil` | CA certificate file path |
| `cacerts_dir` | `VAULTX_CACERTS_DIR` | `nil` | Directory of CA certificates |
| `client_cert` | `VAULTX_CLIENT_CERT` or `VAULT_CLIENT_CERT` | `nil` | Client certificate (mTLS) |
| `client_key` | `VAULTX_CLIENT_KEY` or `VAULT_CLIENT_KEY` | `nil` | Client private key (mTLS) |
| `tls_server_name` | `VAULTX_TLS_SERVER_NAME` | `nil` | TLS SNI server name |
| `tls_min_version` | `VAULTX_TLS_MIN_VERSION` | `1.2` | Minimum TLS version |

### Connection Pool

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `pool_size` | `VAULTX_POOL_SIZE` | `10` | Connection pool size |
| `pool_max_idle_time` | `VAULTX_POOL_MAX_IDLE_TIME` | `300000` | Max idle time (ms) |

### Features & Observability

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `logger_level` | `VAULTX_LOGGER_LEVEL` | `info` | Logger level |
| `telemetry_enabled` | `VAULTX_TELEMETRY_ENABLED` | `true` | Enable telemetry |
| `audit_enabled` | `VAULTX_AUDIT_ENABLED` | `false` | Enable audit logging |
| `metrics_enabled` | `VAULTX_METRICS_ENABLED` | `true` | Enable metrics |
| `cache_enabled` | `VAULTX_CACHE_ENABLED` | `true` | Enable multi-layer caching system |

### Multi-Layer Caching System

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `cache_l1_enabled` | `VAULTX_CACHE_L1_ENABLED` | `true` | Enable L1 in-memory cache |
| `cache_l1_ttl` | `VAULTX_CACHE_L1_TTL` | `300` | L1 cache TTL (seconds) |
| `cache_l1_max_size` | `VAULTX_CACHE_L1_MAX_SIZE` | `1000` | L1 cache max entries |
| `cache_l2_enabled` | `VAULTX_CACHE_L2_ENABLED` | `false` | Enable L2 distributed cache |
| `cache_l2_ttl` | `VAULTX_CACHE_L2_TTL` | `3600` | L2 cache TTL (seconds) |
| `cache_l3_enabled` | `VAULTX_CACHE_L3_ENABLED` | `false` | Enable L3 persistent cache |
| `cache_l3_ttl` | `VAULTX_CACHE_L3_TTL` | `86400` | L3 cache TTL (seconds) |
| `cache_encryption_enabled` | `VAULTX_CACHE_ENCRYPTION_ENABLED` | `true` | Encrypt cached data |

### Database Secrets Engine

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `database_default_ttl` | `VAULTX_DATABASE_DEFAULT_TTL` | `3600` | Default credential TTL (seconds) |
| `database_max_ttl` | `VAULTX_DATABASE_MAX_TTL` | `86400` | Maximum credential TTL (seconds) |
| `database_connection_timeout` | `VAULTX_DATABASE_CONNECTION_TIMEOUT` | `30000` | Database connection timeout (ms) |
| `database_pool_size` | `VAULTX_DATABASE_POOL_SIZE` | `10` | Database connection pool size |

### Security & Compliance

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `rate_limit_enabled` | `VAULTX_RATE_LIMIT_ENABLED` | `false` | Enable rate limiting |
| `rate_limit_requests` | `VAULTX_RATE_LIMIT_REQUESTS` | `100` | Requests per second |
| `rate_limit_burst` | `VAULTX_RATE_LIMIT_BURST` | `0` | Additional burst tokens |
| `token_renewal_enabled` | `VAULTX_TOKEN_RENEWAL_ENABLED` | `true` | Auto token renewal |
| `token_renewal_threshold` | `VAULTX_TOKEN_RENEWAL_THRESHOLD` | `80` | Renewal threshold (%) |
| `security_headers_enabled` | `VAULTX_SECURITY_HEADERS_ENABLED` | `true` | Validate security headers |

## Configuration Examples

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

# Performance tuning
export VAULTX_TIMEOUT="60000"
export VAULTX_RETRY_ATTEMPTS="5"
export VAULTX_POOL_SIZE="20"

# Caching system
export VAULTX_CACHE_ENABLED="true"
export VAULTX_CACHE_L1_ENABLED="true"
export VAULTX_CACHE_L2_ENABLED="false"
export VAULTX_CACHE_L3_ENABLED="false"

# Features
export VAULTX_TELEMETRY_ENABLED="true"
export VAULTX_AUDIT_ENABLED="true"
```

### Application Configuration

```elixir
# config/config.exs
config :vaultx,
  # Core settings
  url: "https://vault.example.com:8200",
  timeout: 30_000,
  retry_attempts: 3,
  ssl_verify: true,
  pool_size: 10,

  # Multi-layer caching system
  cache_enabled: true,
  cache_l1_enabled: true,
  cache_l1_ttl: 300,
  cache_l1_max_size: 1000,
  cache_l2_enabled: false,
  cache_l3_enabled: false,
  cache_encryption_enabled: true,

  # Features
  telemetry_enabled: true,
  audit_enabled: false,

  # Security
  token_renewal_enabled: true,
  token_renewal_threshold: 80,
  rate_limit_enabled: false
```

### Environment-Specific Configuration

```elixir
# config/dev.exs
config :vaultx,
  url: "http://localhost:8200",
  ssl_verify: false,
  logger_level: :debug,
  audit_enabled: false

# config/prod.exs
config :vaultx,
  url: {:system, "VAULTX_URL"},
  ssl_verify: true,
  logger_level: :info,
  audit_enabled: true,
  rate_limit_enabled: true
```

## Configuration Management

### Basic Usage

```elixir
# Get complete configuration
config = Vaultx.Config.get()

# Get specific values
url = Vaultx.Config.get_value(:url)
timeout = Vaultx.Config.get_value(:timeout, 60_000)

# Get multiple values efficiently
%{url: url, timeout: timeout} = Vaultx.Config.get_values([:url, :timeout])
```

### Configuration Validation

```elixir
# Basic validation
case Vaultx.Config.validate() do
  :ok -> :ok
  {:error, errors} -> handle_errors(errors)
end

# Comprehensive analysis
{:ok, analysis} = Vaultx.Config.analyze()
IO.inspect(analysis.performance_score)  # 85.5
IO.inspect(analysis.security_score)     # 92.0
IO.inspect(analysis.suggestions)        # Optimization recommendations
```

### Health Monitoring

```elixir
# Check configuration health
health_status = Vaultx.Config.health_status()
# Returns: :healthy | :degraded | :unhealthy | :critical

# Get optimization suggestions
{:ok, optimization} = Vaultx.Config.validate_and_optimize()
IO.inspect(optimization.optimization_potential)  # :low | :medium | :high
IO.inspect(optimization.suggestions)             # List of improvements
```

## Best Practices

### Security

1. **Always use HTTPS** in production environments
2. **Enable SSL verification** (`ssl_verify: true`)
3. **Use strong TLS versions** (prefer TLS 1.3)
4. **Implement mutual TLS** for high-security environments
5. **Enable audit logging** for compliance requirements
6. **Use short-lived tokens** with automatic renewal

### Performance

1. **Tune connection pools** based on your workload
2. **Configure appropriate timeouts** for your network
3. **Use exponential backoff** for retry strategies
4. **Enable intelligent caching** for read-heavy workloads
5. **Monitor performance metrics** regularly

### Reliability

1. **Configure retry attempts** appropriately
2. **Set reasonable timeouts** to avoid hanging requests
3. **Enable token renewal** for long-running applications
4. **Monitor configuration health** regularly
5. **Use rate limiting** to protect Vault from overload

## Troubleshooting

### Common Issues

1. **SSL Certificate Errors**: Check `cacert` and `ssl_verify` settings
2. **Connection Timeouts**: Adjust `timeout` and `connect_timeout`
3. **Pool Exhaustion**: Increase `pool_size`
4. **Authentication Failures**: Verify `token` and `namespace` settings
5. **Rate Limiting**: Check Vault server rate limits and adjust client settings

### Diagnostic Tools

```elixir
# Run comprehensive analysis
{:ok, analysis} = Vaultx.Config.analyze()
IO.inspect(analysis, label: "Configuration Analysis")

# Check health status
health = Vaultx.Config.health_status()
IO.puts("Configuration health: #{health}")

# Get optimization suggestions
{:ok, optimization} = Vaultx.Config.validate_and_optimize()
Enum.each(optimization.suggestions, fn suggestion ->
  IO.puts("#{suggestion.priority}: #{suggestion.title}")
  IO.puts("  #{suggestion.description}")
end)
```

### Configuration Templates

VaultX provides configuration templates for different environments:

```elixir
# Generate development template
dev_template = Vaultx.Config.Templates.generate(:development)

# Generate production template with specific features
prod_template = Vaultx.Config.Templates.generate(:production,
  features: [:cache, :telemetry, :audit],
  security_level: :enterprise
)

# Generate migration template
migration = Vaultx.Config.Templates.generate_migration(:development, :production)
```

## v0.7.0 New Features

### Hot Configuration Reload

VaultX now supports runtime configuration updates without application restarts:

```elixir
# Update configuration at runtime
new_config = %{cache_l1_ttl: 600, pool_size: 20}
:ok = Vaultx.Config.HotReload.update(new_config)

# Monitor configuration changes
Vaultx.Config.HotReload.subscribe(self())
receive do
  {:config_updated, changes} ->
    IO.inspect(changes, label: "Configuration updated")
end
```

### Enhanced Caching System

Multi-layer caching provides significant performance improvements:

```elixir
# Configure caching for optimal performance
config :vaultx,
  cache_enabled: true,
  cache_l1_enabled: true,      # In-memory cache (fastest)
  cache_l1_ttl: 300,           # 5 minutes
  cache_l2_enabled: true,      # Distributed cache (multi-node)
  cache_l2_ttl: 3600,          # 1 hour
  cache_l3_enabled: true,      # Persistent cache (survives restarts)
  cache_l3_ttl: 86400,         # 24 hours
  cache_encryption_enabled: true
```

### Database Secrets Engine Configuration

Configure the new Database secrets engine for dynamic credentials:

```elixir
config :vaultx,
  # Database secrets engine defaults
  database_default_ttl: 3600,        # 1 hour default TTL
  database_max_ttl: 86400,           # 24 hours maximum TTL
  database_connection_timeout: 30000, # 30 seconds
  database_pool_size: 10              # Connection pool size
```

### Migration from v0.6.x

Key changes when upgrading from v0.6.x:

1. **KV Behaviour**: Update pattern matching from structs to maps
2. **Configuration Validation**: Review configurations as validation is stricter
3. **Caching**: Enable caching for performance improvements
4. **Telemetry**: New telemetry events available for monitoring

See [CHANGELOG.md](../CHANGELOG.md) for complete migration guide.
