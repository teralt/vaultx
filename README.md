# VaultX

[![Hex.pm](https://img.shields.io/hexpm/v/vaultx.svg)](https://hex.pm/packages/vaultx)
[![Documentation](https://img.shields.io/badge/docs-hexdocs-blue.svg)](https://hexdocs.pm/vaultx)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build Status](https://github.com/teralt/vaultx/workflows/Release/badge.svg)](https://github.com/teralt/vaultx/actions)

## Overview

VaultX is a high-level, production-ready Elixir client for [HashiCorp Vault](https://developer.hashicorp.com/vault) that focuses on:

- **Simplicity**: A small, consistent API for common Vault tasks
- **Correctness**: Typed interfaces, robust error handling, safe defaults
- **Performance**: Pooled connections, adaptive retries, native JSON
- **Observability**: Structured logging and optional telemetry
- **Security**: Conservative security defaults, comprehensive validation
- **BEAM-Native**: Designed for OTP distribution and hot code reloading workflows

## What is VaultX

VaultX is an Elixir library that wraps Vault's HTTP API with an ergonomic, stateless interface. It provides comprehensive support for:

### Core Features

- **Secrets Management**: KV v1/v2 and other engines (read, write, delete, list)
- **System Operations**: Health checks, seal status, initialization
- **Lease Management**: Lookup, renew, revoke, tidy, and bulk operations
- **Audit Devices**: List, enable, and disable audit logging
- **Authentication**: Multiple auth methods with high-level authenticate interface

### Supported Secrets Engines

| Engine | Description |
|--------|-------------|
| **Key-Value (KV)** | Both v1 and v2 with automatic version detection |
| **PKI** | Certificate authority management and certificate lifecycle |
| **Transit** | Encryption as a service and key management |
| **AWS** | Dynamic credential generation for AWS services |
| **TOTP** | Time-based one-time password generation |
| **RabbitMQ** | Dynamic RabbitMQ credentials |
| **Consul** | Dynamic Consul credentials |

### Supported Auth Methods

| Method | Description |
|--------|-------------|
| **Token** | Direct token authentication and validation |
| **AppRole** | Machine-to-machine authentication |
| **JWT/OIDC** | JSON Web Token authentication |
| **AWS** | AWS IAM authentication |
| **Azure** | Azure Active Directory authentication |
| **GitHub** | GitHub organization authentication |
| **LDAP** | Lightweight Directory Access Protocol |
| **UserPass** | Username and password authentication |
| **AliCloud** | Alibaba Cloud authentication |

### Supported System Backend

| Operation | Description |
|-----------|-------------|
| **Audit Devices** | List, enable, and disable audit logging devices |
| **Mounts** | Manage secrets engine mount points and configuration |
| **Policies** | Create, read, update, and delete ACL/RGP/EGP policies |
| **Namespaces** | Enterprise namespace management and isolation |
| **Health & Status** | Health checks, seal status, and leader information |
| **Initialization** | Vault initialization and unseal operations |
| **Leases** | Lease lookup, renewal, revocation, and management |
| **Seal Management** | Seal, unseal, and seal backend status operations |
| **Monitoring** | System monitoring and operational metrics |
| **Tools** | Administrative tools and utilities |

## Why Use VaultX

Modern software works because of **secrets**. Secrets are sensitive, discrete pieces of information like credentials, encryption keys, authentication certificates, and other critical pieces of information your applications need to run consistently and securely.

VaultX helps harden applications by centralizing secret management:

### Manage Static Secrets

Store and rotate arbitrary secrets in Vault with the Key/Value engines. VaultX encrypts data before writing to persistent storage, ensuring raw storage access is insufficient to compromise information.

### Manage Dynamic Secrets

Generate and revoke on-demand credentials for database systems and cloud providers like AWS. Control access to external information like encryption keys and cloud credentials with automatic lifecycle management.

### Manage Certificates

Configure VaultX to work with certificate authorities to manage certificate lifecycles and authenticate clients. Support for PKI operations including root CA management and certificate issuance.

### Manage Identities and Authentication

Control client access to sensitive information with managed entities, identity tokens, and comprehensive authentication workflows supporting multiple identity providers.

### Secure Sensitive Data

Define custom parameters to encrypt or tokenize sensitive data in transit and at rest without storing the data in Vault, using the Transit secrets engine.

### Support Regulatory Compliance

Configure VaultX as part of HSM solutions, FIPS compliant architectures, with comprehensive audit logging for security compliance requirements.

## How VaultX Works

VaultX implements HashiCorp Vault's core workflow with four stages:

1. **Authenticate**: Clients supply information that VaultX uses to determine identity through various auth methods
2. **Validation**: VaultX validates clients against third-party trusted sources like GitHub, LDAP, AppRole, and more
3. **Authorize**: Clients are matched against Vault security policies defining API endpoint access
4. **Access**: VaultX grants access to secrets, keys, and encryption capabilities based on associated policies

### Architecture

VaultX follows modern Elixir library conventions:

- **Stateless**: No GenServer or caching, pure function-based operations
- **Dynamic**: Configuration changes take effect immediately
- **Hierarchical**: Environment variables override application configuration
- **Validated**: Comprehensive validation using NimbleOptions
- **Secure**: Built-in security validation and best practices

## Operations

### Secrets Management

```elixir
# Read from KV v2
{:ok, data} = Vaultx.Secrets.KV.V2.read("myapp/config")

# Write secrets
{:ok, result} = Vaultx.Secrets.KV.V2.write("myapp/config", %{"key" => "value"})

# List secrets
{:ok, result} = Vaultx.Secrets.KV.V2.list("myapp/")

# Delete secrets
{:ok, :ok} = Vaultx.Secrets.KV.V2.delete("myapp/config")
```

### System Operations

```elixir
# Health checks
{:ok, health} = Vaultx.Sys.Health.check()

# Seal status
{:ok, seal} = Vaultx.Sys.SealStatus.get()
```

### Lease Management

```elixir
# Lookup lease
{:ok, lease} = VaultX.Sys.Leases.lookup("aws/creds/deploy/abcd-1234")

# Renew lease
{:ok, renewed} = VaultX.Sys.Leases.renew("aws/creds/deploy/abcd-1234", 1800)

# Revoke lease
:ok = VaultX.Sys.Leases.revoke("aws/creds/deploy/abcd-1234")
```

## Audit Devices

VaultX provides comprehensive audit device management for security compliance:

```elixir
# List audit devices
{:ok, devices} = VaultX.Sys.Audit.list()

# Enable file audit
{:ok, _} = VaultX.Sys.Audit.enable("file-audit", "file", %{
  file_path: "/var/log/vault/audit.log"
})

# Disable audit device
{:ok, _} = VaultX.Sys.Audit.disable("file-audit")
```

Audit devices provide detailed logging of all Vault operations, supporting:

- **File-based auditing**: Write audit logs to local files
- **Syslog integration**: Send audit logs to syslog
- **Socket-based auditing**: Stream audit logs over network sockets
- **Multiple devices**: Enable multiple audit devices for redundancy

## Security

VaultX implements HashiCorp Vault's security model with enterprise-grade features:

### Encryption Barrier

All data is encrypted before storage using Vault's encryption barrier. The storage backend is considered untrusted, ensuring data remains secure even if storage is compromised.

### Authentication & Authorization

- **Identity-based access**: All operations require authenticated identity
- **Policy-based authorization**: Fine-grained access control through policies
- **Token lifecycle management**: Automatic token renewal and revocation
- **Audit logging**: Comprehensive logging of all operations

### TLS & Network Security

- **TLS by default**: All communications encrypted in transit
- **Certificate validation**: Comprehensive SSL/TLS certificate verification
- **mTLS support**: Mutual TLS authentication for high-security environments
- **Security headers**: Validation of security headers for compliance

## Limited Docker/Kubernetes Ecosystem Support

> [!WARNING]
> This project has **not been tested or validated** for use with Docker or Kubernetes environments. While VaultX may work in containerized deployments, we do not provide official support, testing, or documentation for Docker/Kubernetes integration patterns.

VaultX is a library, not a sidecar/agent/operator. We intentionally focus on Elixir application integration instead of container ecosystems. As a result, we do not ship:

- A Vault agent sidecar, injector, or CSI driver
- A Kubernetes operator/CRDs or admission webhooks

### Rationale

The limited Docker/Kubernetes ecosystem support is largely influenced by the philosophy behind [DeployEx](https://github.com/thiagoesteves/deployex), a lightweight deployment tool designed for managing BEAM applications (Elixir, Erlang, Gleam) without relying on additional deployment tools like Docker or Kubernetes.

**Key reasons for this approach:**

- **Keep the core library small, fast, and maintainable**
- **Avoid duplicating mature, battle-tested tooling** from HashiCorp and the community
- **Leverage BEAM/OTP distribution capabilities**: The Erlang/OTP distribution system provides robust clustering and monitoring capabilities that often eliminate the need for container orchestration
- **Embrace BEAM-native deployment patterns**: Tools like DeployEx demonstrate that BEAM applications can be effectively deployed and managed using OTP distribution, hot code reloading, and native BEAM supervision trees
- **Encourage best-of-breed composition**: Use Vault Agent Injector, CSI secrets driver, or init containers for Kubernetes; use standard Docker image patterns for configs/tokens

### Recommended Patterns

#### BEAM-Native Deployment (Recommended)

For BEAM applications, consider using [DeployEx](https://github.com/thiagoesteves/deployex):

- **OTP Distribution**: Leverage native Erlang distribution for clustering and monitoring
- **Hot Code Reloading**: Deploy updates without downtime using OTP hot upgrades
- **Native Supervision**: Use OTP supervision trees instead of container orchestration
- **Simplified Operations**: Eliminate container complexity while maintaining enterprise features

#### Kubernetes

Pair VaultX with existing Kubernetes-native solutions:

- **Vault Agent Injector**: Automatically inject secrets into pods
- **Vault CSI Driver**: Mount secrets as volumes
- **Kubernetes Auth**: Authenticate using Kubernetes service accounts
- **Init Containers**: Fetch secrets during pod initialization

#### Docker

Use standard Docker patterns:

- **Environment variables**: Pass tokens via environment variables
- **Mounted files**: Mount token files from host or volumes
- **Avoid baking secrets into images**: Never include secrets in Docker images
- **Rotate tokens out-of-band**: Let VaultX read them dynamically at runtime

### References

- [DeployEx](https://github.com/thiagoesteves/deployex) - BEAM-native deployment tool
- [Vault Agent Injector](https://developer.hashicorp.com/vault/docs/platform/k8s/injector)
- [Vault CSI Driver](https://developer.hashicorp.com/vault/docs/platform/k8s/csi)
- [Kubernetes Auth](https://developer.hashicorp.com/vault/docs/auth/kubernetes)

## Quickstarts

### 1. Installation

Add to your `mix.exs`:

```elixir
def deps do
  [
    {:vaultx, "~> 0.6"}
  ]
end
```

Optional dependencies:

- `{:jason, "~> 1.4"}` if you're on Elixir < 1.18 or prefer Jason
- `{:telemetry, "~> 1.3"}` for metrics and observability

Run:

```bash
mix deps.get
```

### 2. Configuration

Set minimal environment variables (dynamic config is resolved each call):

```bash
export VAULTX_URL="https://vault.example.com:8200"
export VAULTX_TOKEN="hvs.xxxxx"  # or VAULT_TOKEN
# Optional: select JSON library
# export VAULTX_JSON_LIBRARY="elixir" | "jason"
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

## Recommendations

- **Prefer short-lived tokens** and narrow policies; enable leases and enforce revocation on incidents
- **Use KV v2** for versioned data and CAS writes; include `/data/` in paths
- **Enable at least one audit device** before production traffic; consider a fallback device
- **On Kubernetes**, combine VaultX with Vault Agent Injector or the CSI driver
- **Instrument telemetry and logs**; redact sensitive data in your own logs as well

## Installation and Compatibility

- **Elixir**: ~> 1.18 (uses Elixir's built-in JSON when available; falls back to Jason)
- **OTP**: Standard supported versions for Elixir 1.18
- **HTTP Stack**: Req + Finch for modern, efficient HTTP operations
- **Philosophy**: Stateless, dynamic runtime config, conservative security defaults, excellent DX

## Configuration

VaultX.Base.Config resolves settings from environment variables first, then application config, then defaults. Common variables:

- `VAULTX_URL` / `VAULT_ADDR`: Vault server URL
- `VAULTX_TOKEN` / `VAULT_TOKEN`: Authentication token
- `VAULTX_NAMESPACE` / `VAULT_NAMESPACE`: Vault namespace (Enterprise)
- Timeouts, retries, TLS options can be tuned via app env or options per call

For detailed configuration options, advanced settings, and examples, see [Configuration Guide](docs/configuration.md).

## Telemetry

VaultX emits optional telemetry around operations (read/write/list, health, leases, audit). Hook into your metrics/trace stack by attaching handlers.

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

Copyright (c) 2025 Fleey

Licensed under the MIT License. See [LICENSE](LICENSE) for details.
