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

### Cache Configuration

VaultX provides a sophisticated multi-layer caching system for improved performance. The cache system consists of three layers: L1 (Memory), L2 (Distributed), and L3 (Persistent).

#### Core Cache Settings

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `cache_enabled` | `VAULTX_CACHE_ENABLED` | `true` | Enable/disable entire cache system |
| `cache_eviction_policy` | `VAULTX_CACHE_EVICTION_POLICY` | `lru` | Eviction policy (lru, lfu, ttl) |
| `cache_max_memory_usage` | `VAULTX_CACHE_MAX_MEMORY_USAGE` | `104857600` | Max memory usage in bytes (100MB) |
| `cache_warming_enabled` | `VAULTX_CACHE_WARMING_ENABLED` | `true` | Enable cache warming |
| `cache_metrics_enabled` | `VAULTX_CACHE_METRICS_ENABLED` | `true` | Enable metrics collection |
| `cache_manager_cleanup_interval` | `VAULTX_CACHE_MANAGER_CLEANUP_INTERVAL` | `300000` | Manager cleanup interval (ms) |

#### L1 Memory Cache

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `cache_l1_enabled` | `VAULTX_CACHE_L1_ENABLED` | `true` | Enable L1 memory cache |
| `cache_l1_max_size` | `VAULTX_CACHE_L1_MAX_SIZE` | `10000` | Maximum number of entries |
| `cache_l1_ttl_default` | `VAULTX_CACHE_L1_TTL_DEFAULT` | `900000` | Default TTL in ms (15 min) |
| `cache_l1_cleanup_interval` | `VAULTX_CACHE_L1_CLEANUP_INTERVAL` | `300000` | Cleanup interval in ms (5 min) |

#### L2 Distributed Cache

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `cache_l2_enabled` | `VAULTX_CACHE_L2_ENABLED` | `true` | Enable L2 distributed cache |
| `cache_l2_adapter` | `VAULTX_CACHE_L2_ADAPTER` | `Vaultx.Cache.Adapters.Memory` | Cache adapter module |
| `cache_l2_max_size` | `VAULTX_CACHE_L2_MAX_SIZE` | `50000` | Maximum number of entries |
| `cache_l2_ttl_default` | `VAULTX_CACHE_L2_TTL_DEFAULT` | `3600000` | Default TTL in ms (1 hour) |
| `cache_l2_cleanup_interval` | `VAULTX_CACHE_L2_CLEANUP_INTERVAL` | `600000` | Cleanup interval in ms (10 min) |

#### L3 Persistent Cache

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `cache_l3_enabled` | `VAULTX_CACHE_L3_ENABLED` | `false` | Enable L3 persistent cache |
| `cache_l3_storage_path` | `VAULTX_CACHE_L3_STORAGE_PATH` | `/tmp/vaultx_cache` | Storage directory path |
| `cache_l3_ttl_default` | `VAULTX_CACHE_L3_TTL_DEFAULT` | `86400000` | Default TTL in ms (24 hours) |
| `cache_l3_cleanup_interval` | `VAULTX_CACHE_L3_CLEANUP_INTERVAL` | `3600000` | Cleanup interval in ms (1 hour) |
| `cache_l3_encryption` | `VAULTX_CACHE_L3_ENCRYPTION` | `false` | Enable AES-256-GCM encryption |

#### L3 Encryption Configuration

When L3 encryption is enabled, the encryption key is sourced in priority order:

1. **Environment Variable**: `VAULTX_L3_ENCRYPTION_KEY` (Base64-encoded 256-bit key)
2. **Key File**: `.encryption_key` in the storage directory (auto-generated)
3. **Fallback**: In-memory generation (not recommended for production)

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

# Cache configuration
export VAULTX_CACHE_ENABLED="true"
export VAULTX_CACHE_L1_ENABLED="true"
export VAULTX_CACHE_L1_MAX_SIZE="20000"
export VAULTX_CACHE_L2_ENABLED="true"
export VAULTX_CACHE_L3_ENABLED="true"
export VAULTX_CACHE_L3_STORAGE_PATH="/var/cache/vaultx"
export VAULTX_CACHE_L3_ENCRYPTION="true"
export VAULTX_L3_ENCRYPTION_KEY="$(openssl rand -base64 32)"
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

  # Cache configuration
  cache_enabled: true,
  cache_l1_enabled: true,
  cache_l1_max_size: 20_000,
  cache_l1_ttl_default: 900_000,  # 15 minutes

  cache_l2_enabled: true,
  cache_l2_adapter: Vaultx.Cache.Adapters.Memory,
  cache_l2_max_size: 50_000,
  cache_l2_ttl_default: 3_600_000,  # 1 hour

  cache_l3_enabled: true,
  cache_l3_storage_path: "/var/cache/vaultx",
  cache_l3_ttl_default: 86_400_000,  # 24 hours
  cache_l3_encryption: true
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

#### Core Configuration Issues

1. **SSL Certificate Errors**: Check `cacert` and `ssl_verify` settings
2. **Connection Timeouts**: Adjust `timeout` and `connect_timeout`
3. **Pool Exhaustion**: Increase `pool_size`
4. **Authentication Failures**: Verify `token` and `namespace` settings

#### Cache Configuration Issues

1. **Cache Permission Errors**: Ensure cache directory has proper permissions (0700)
2. **L3 Encryption Key Issues**: Verify `VAULTX_L3_ENCRYPTION_KEY` is properly set
3. **High Memory Usage**: Adjust `cache_l1_max_size` and `cache_l2_max_size`
4. **Slow Cache Performance**: Check disk I/O for L3 cache, consider SSD storage
5. **Cache Directory Full**: Monitor disk space and adjust cleanup intervals
6. **Encryption Key Mismatch**: Ensure key consistency across application restarts

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

# Cache-specific diagnostics
{:ok, cache_stats} = Vaultx.Cache.stats()
IO.inspect(cache_stats, label: "Cache Statistics")

# Check cache health
case Process.whereis(Vaultx.Cache.Manager) do
  nil -> IO.puts("Cache system is not running")
  pid -> IO.puts("Cache system is running (PID: #{inspect(pid)})")
end

# Validate cache configuration
config = Vaultx.Base.Config.get()
if config.cache_l3_enabled and config.cache_l3_encryption do
  case System.get_env("VAULTX_L3_ENCRYPTION_KEY") do
    nil -> IO.puts("Warning: L3 encryption enabled but no key provided")
    _key -> IO.puts("L3 encryption key configured")
  end
end
```

## Migration Guide

### From Previous Versions

The Vaultx library was only officially released to the public starting from version v0.6.0, so there is currently no relevant content for this entry.
