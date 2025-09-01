# VaultX

[![Hex.pm](https://img.shields.io/hexpm/v/vaultx.svg)](https://hex.pm/packages/vaultx)
[![Documentation](https://img.shields.io/badge/docs-hexdocs-blue.svg)](https://hexdocs.pm/vaultx)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build Status](https://github.com/teralt/vaultx/workflows/Release/badge.svg)](https://github.com/teralt/vaultx/actions)

A modern, high-performance Elixir client for [HashiCorp Vault](https://developer.hashicorp.com/vault) designed for production use.

## Why VaultX?

- **Fast & Reliable**: Built on modern HTTP stack (Req + Finch) with intelligent connection pooling
- **Security First**: Conservative security defaults, comprehensive validation, audit logging
- **Performance**: Multi-layer caching, adaptive retries, efficient JSON handling
- **Simple API**: Clean, consistent interface for all Vault operations
- **Observable**: Structured logging, telemetry integration, health monitoring
- **BEAM-Native**: Designed for OTP distribution, hot code reloading, supervision trees

## Quick Start

### 1. Installation

Add to your `mix.exs`:

```elixir
def deps do
  [
    {:vaultx, "~> 0.6"}
  ]
end
```

### 2. Configuration

Set environment variables:

```bash
export VAULTX_URL="https://vault.example.com:8200"
export VAULTX_TOKEN="hvs.xxxxx"
```

### 3. Basic Usage

```elixir
# Read secrets
{:ok, data} = Vaultx.Secrets.KV.V2.read("myapp/config")

# Write secrets
{:ok, result} = Vaultx.Secrets.KV.V2.write("myapp/config", %{"key" => "value"})

# System operations
{:ok, health} = Vaultx.Sys.Health.check()
{:ok, seal} = Vaultx.Sys.SealStatus.get()
```

## Core Features

### Secrets Management

- **KV v1/v2**: Full support with automatic version detection
- **Dynamic Secrets**: AWS, PKI, Transit, TOTP, RabbitMQ, Consul
- **Lease Management**: Lookup, renew, revoke, bulk operations

### Authentication Methods

- **Token**: Direct token authentication and validation
- **AppRole**: Machine-to-machine authentication
- **JWT/OIDC**: JSON Web Token authentication
- **AWS, Azure, GitHub, LDAP, UserPass**: Multiple identity providers

### System Operations

- **Health & Status**: Comprehensive health checks and monitoring
- **Audit Devices**: Security compliance and logging
- **Policies**: ACL/RGP/EGP policy management
- **Mounts**: Secrets engine management

### Performance & Reliability

- **Intelligent Caching**: Multi-layer caching with encryption support (experimental)
- **Connection Pooling**: Efficient HTTP connection management
- **Adaptive Retries**: Exponential backoff with jitter
- **Health Monitoring**: Real-time system health assessment

## Architecture

VaultX follows modern Elixir conventions:

- **Stateless Core**: Pure function-based operations
- **Dynamic Configuration**: Runtime configuration changes
- **Hierarchical Settings**: Environment variables → Application config → Defaults
- **Comprehensive Validation**: Built-in security and performance validation
- **OTP Integration**: Native supervision trees and distribution support

## Configuration

### Environment Variables

```bash
# Core Settings
export VAULTX_URL="https://vault.example.com:8200"
export VAULTX_TOKEN="hvs.xxxxx"
export VAULTX_NAMESPACE="my-namespace"  # Enterprise

# Network & Performance
export VAULTX_TIMEOUT="30000"
export VAULTX_RETRY_ATTEMPTS="3"
export VAULTX_POOL_SIZE="10"

# Security
export VAULTX_SSL_VERIFY="true"
export VAULTX_CACERT="/path/to/ca.pem"
export VAULTX_CLIENT_CERT="/path/to/client.pem"  # mTLS
export VAULTX_CLIENT_KEY="/path/to/client-key.pem"

# Features
export VAULTX_CACHE_ENABLED="true"
export VAULTX_TELEMETRY_ENABLED="true"
export VAULTX_AUDIT_ENABLED="true"
```

### Application Configuration

```elixir
# config/config.exs
config :vaultx,
  url: "https://vault.example.com:8200",
  timeout: 30_000,
  retry_attempts: 3,
  ssl_verify: true,
  pool_size: 10,
  cache_enabled: true,
  telemetry_enabled: true
```

For detailed configuration options, see [Configuration Guide](docs/configuration.md).

## Important Notes

### Experimental Features

> [!WARNING]
> The intelligent caching system is currently **experimental** and may undergo breaking changes in future versions. While functional and tested, the caching API and behavior may change as we gather feedback and optimize performance. Use with caution in production environments.

### Limited Docker/Kubernetes Support

> [!CAUTION]
> This project has **not been tested or validated** for use with Docker or Kubernetes environments. While VaultX may work in containerized deployments, we do not provide official support, testing, or documentation for Docker/Kubernetes integration patterns.

VaultX is designed as a library for BEAM-native deployments, not as a container-first solution. We intentionally focus on Elixir application integration rather than container ecosystems.

**Why limited container support:**

- **BEAM-Native Philosophy**: Designed for OTP distribution, hot code reloading, and native supervision trees
- **Avoid Duplication**: HashiCorp and the community provide mature container solutions
- **Simplicity**: Keep the core library focused, fast, and maintainable
- **Best-of-Breed**: Encourage composition with existing container-native Vault tools

**Recommended patterns:**

- **BEAM-Native**: Use [DeployEx](https://github.com/thiagoesteves/deployex) for BEAM application deployment
- **Kubernetes**: Combine with Vault Agent Injector, CSI driver, or Kubernetes auth
- **Docker**: Use standard patterns (environment variables, mounted volumes, init containers)

## Examples

### Secrets Operations

```elixir
# KV v2 operations
{:ok, data} = Vaultx.Secrets.KV.V2.read("myapp/database")
{:ok, _} = Vaultx.Secrets.KV.V2.write("myapp/database", %{
  "host" => "db.example.com",
  "password" => "secret123"
})
{:ok, keys} = Vaultx.Secrets.KV.V2.list("myapp/")
{:ok, _} = Vaultx.Secrets.KV.V2.delete("myapp/old-config")

# Dynamic secrets
{:ok, creds} = Vaultx.Secrets.AWS.generate_credentials("deploy-role")
{:ok, cert} = Vaultx.Secrets.PKI.issue_certificate("web-server", %{
  common_name: "api.example.com"
})
```

### System Management

```elixir
# Health and status
{:ok, health} = Vaultx.Sys.Health.check()
{:ok, seal_status} = Vaultx.Sys.SealStatus.get()

# Lease management
{:ok, lease} = Vaultx.Sys.Leases.lookup("aws/creds/deploy/abcd-1234")
{:ok, renewed} = Vaultx.Sys.Leases.renew("aws/creds/deploy/abcd-1234", 1800)
:ok = Vaultx.Sys.Leases.revoke("aws/creds/deploy/abcd-1234")

# Audit devices
{:ok, devices} = Vaultx.Sys.Audit.list()
{:ok, _} = Vaultx.Sys.Audit.enable("file-audit", "file", %{
  file_path: "/var/log/vault/audit.log"
})
```

### Authentication

```elixir
# Token authentication
{:ok, token_info} = Vaultx.Auth.Token.lookup_self()
{:ok, renewed} = Vaultx.Auth.Token.renew_self(3600)

# AppRole authentication
{:ok, auth} = Vaultx.Auth.AppRole.login("my-role-id", "my-secret-id")

# JWT authentication
{:ok, auth} = Vaultx.Auth.JWT.login("my-role", jwt_token)
```

## Configuration Analysis

VaultX provides comprehensive configuration analysis and optimization:

```elixir
# Analyze current configuration
{:ok, analysis} = Vaultx.Config.analyze()
IO.inspect(analysis.performance_score)  # 85.5
IO.inspect(analysis.security_score)     # 92.0
IO.inspect(analysis.suggestions)        # Optimization recommendations

# Validate configuration
:ok = Vaultx.Config.validate()

# Get health status
:healthy = Vaultx.Config.health_status()
```

> [!NOTE]
> Configuration analysis and optimization features are stable and production-ready. They provide valuable insights into your Vault configuration without affecting runtime behavior.

## Deployment Patterns

### BEAM-Native (Recommended)

VaultX is designed for BEAM-native deployments using tools like [DeployEx](https://github.com/thiagoesteves/deployex):

- **OTP Distribution**: Native clustering and monitoring
- **Hot Code Reloading**: Zero-downtime deployments
- **Supervision Trees**: Built-in fault tolerance
- **No Container Overhead**: Direct BEAM deployment

### Container Environments

While VaultX works in containers, we recommend using existing Vault integrations:

- **Kubernetes**: Use Vault Agent Injector or CSI driver
- **Docker**: Mount tokens via volumes or environment variables
- **Never bake secrets into images**

## Requirements

- **Elixir**: ~> 1.18 (uses built-in JSON when available)
- **OTP**: Standard supported versions
- **Vault**: Compatible with Vault 1.0+

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

Copyright (c) 2025 Fleey

Licensed under the MIT License. See [LICENSE](LICENSE) for details.
