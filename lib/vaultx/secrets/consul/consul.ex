defmodule Vaultx.Secrets.Consul do
  @moduledoc """
  Unified Consul secrets engine interface for HashiCorp Vault.

  This module provides a comprehensive, enterprise-grade interface for the
  Consul secrets engine, offering dynamic credential management, configuration
  operations, and role management. It supports all Consul credential types
  with advanced security features and compliance capabilities.

  ## Enterprise Consul Credential Management

  - Dynamic Credential Generation: Consul ACL tokens with policies, roles, and service identities
  - Configuration Management: Root credentials, access settings, and connection parameters
  - Role Management: Dynamic role configuration with policy enforcement
  - Multi-Version Support: Compatible with Consul 1.4+ through latest versions
  - Security Compliance: Audit logging, least privilege, and policy validation

  ## Supported Credential Types

  ### Modern Consul (1.5+)
  - Consul Policies: Named policies for fine-grained access control
  - Consul Roles: Pre-defined role-based access patterns
  - Service Identities: Service-specific access tokens
  - Node Identities: Node-specific access tokens (1.8+)
  - Namespace Support: Multi-tenant Consul deployments (1.7+)
  - Admin Partitions: Enterprise multi-partition support (1.11+)

  ### Legacy Consul (1.4 and below)
  - Base64-encoded ACL policies
  - Management and client token types

  ## Configuration Examples

      # Configure root Consul credentials
      config = %{
        address: "127.0.0.1:8500",
        scheme: "https",
        token: "management-token-here",
        ca_cert: "-----BEGIN CERTIFICATE-----...",
        client_cert: "-----BEGIN CERTIFICATE-----...",
        client_key: "-----BEGIN PRIVATE KEY-----..."
      }
      {:ok, _} = Consul.configure_access(config)

      # Create a modern role with policies
      role_config = %{
        consul_policies: ["web-policy", "db-read-policy"],
        consul_namespace: "production",
        ttl: "1h",
        max_ttl: "24h"
      }
      {:ok, _} = Consul.create_role("web-service", role_config)

      # Generate credentials
      {:ok, creds} = Consul.generate_credentials("web-service")

  ## API Compliance

  Fully implements HashiCorp Vault Consul secrets engine:
  - [Consul Secrets Engine API](https://developer.hashicorp.com/vault/api-docs/secret/consul)
  - [Consul Secrets Engine Guide](https://developer.hashicorp.com/vault/docs/secrets/consul)
  - [Consul ACL System](https://developer.hashicorp.com/consul/docs/security/acl)

  """

  alias Vaultx.Base.{Error, Logger, Telemetry}
  alias Vaultx.Secrets.Consul.Behaviour
  alias Vaultx.Transport.HTTP

  @behaviour Behaviour

  @default_mount_path "consul"

  # Configuration Operations

  @doc """
  Configure access information for Consul.

  Sets up the Consul connection parameters that Vault will use to communicate
  with Consul and generate tokens. Supports both HTTP and HTTPS connections
  with optional TLS client certificate authentication.

  ## Parameters

  - `config` - Access configuration parameters
  - `opts` - Request options including mount path

  ## Examples

      # Basic HTTP configuration
      config = %{
        address: "127.0.0.1:8500",
        scheme: "http",
        token: "management-token"
      }
      {:ok, _} = Consul.configure_access(config)

      # HTTPS with client certificates
      config = %{
        address: "consul.example.com:8501",
        scheme: "https",
        token: "management-token",
        ca_cert: File.read!("ca.pem"),
        client_cert: File.read!("client.pem"),
        client_key: File.read!("client-key.pem")
      }

  """
  @impl Behaviour
  def configure_access(config, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    telemetry_metadata = %{
      operation: :configure_access,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()

    Telemetry.operation_start(telemetry_metadata)

    Logger.info("Configuring Consul access", %{
      mount_path: mount_path,
      address: Map.get(config, :address),
      scheme: Map.get(config, :scheme, "http")
    })

    path = "/#{mount_path}/config/access"

    case HTTP.post(path, config, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        Logger.info("Successfully configured Consul access", %{
          mount_path: mount_path
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_success(duration, telemetry_metadata)
        :ok

      {:ok, response} ->
        error = Error.from_http_response(response.status, response.body)

        Logger.error("Failed to configure Consul access", %{
          mount_path: mount_path,
          error: error
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}

      {:error, reason} ->
        error = Error.new(:http_error, "HTTP request failed", details: %{reason: reason})

        Logger.error("HTTP error configuring Consul access", %{
          mount_path: mount_path,
          error: error
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}
    end
  end

  # Role Operations

  @doc """
  Create or update a Consul role.

  Configures a role that can be used to generate Consul ACL tokens.
  The role defines the type of credentials to generate and the
  associated policies, roles, and constraints.

  ## Parameters

  - `name` - Role name
  - `config` - Role configuration
  - `opts` - Request options

  ## Examples

      # Modern Consul with policies (1.4+)
      config = %{
        consul_policies: ["web-policy", "db-read-policy"],
        consul_namespace: "production",
        ttl: "1h",
        max_ttl: "24h",
        local: false
      }
      {:ok, _} = Consul.create_role("web-service", config)

      # With service identities (1.5+)
      config = %{
        service_identities: [
          "web:dc1,dc2",
          "api:dc1"
        ],
        consul_namespace: "production"
      }
      {:ok, _} = Consul.create_role("service-role", config)

      # With node identities (1.8+)
      config = %{
        node_identities: [
          "web-01:dc1",
          "web-02:dc1"
        ],
        partition: "frontend"
      }
      {:ok, _} = Consul.create_role("node-role", config)

  """
  @impl Behaviour
  def create_role(name, config, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    telemetry_metadata = %{
      operation: :create_role,
      role_name: name,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()

    Telemetry.operation_start(telemetry_metadata)

    Logger.info("Creating Consul role", %{
      role_name: name,
      mount_path: mount_path,
      consul_policies: Map.get(config, :consul_policies),
      consul_roles: Map.get(config, :consul_roles)
    })

    path = "/#{mount_path}/roles/#{name}"

    case HTTP.post(path, config, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        Logger.info("Successfully created Consul role", %{
          role_name: name,
          mount_path: mount_path
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_success(duration, telemetry_metadata)
        :ok

      {:ok, response} ->
        error = Error.from_http_response(response.status, response.body)

        Logger.error("Failed to create Consul role", %{
          role_name: name,
          error: error
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}

      {:error, reason} ->
        error = Error.new(:http_error, "HTTP request failed", details: %{reason: reason})
        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}
    end
  end

  @doc """
  Read a Consul role configuration.

  ## Examples

      {:ok, config} = Consul.read_role("web-service")
      %{
        consul_policies: ["web-policy", "db-read-policy"],
        consul_namespace: "production",
        ttl: "1h0m0s",
        max_ttl: "24h0m0s",
        local: false
      }

  """
  @impl Behaviour
  def read_role(name, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    path = "/#{mount_path}/roles/#{name}"

    case HTTP.get(path, opts) do
      {:ok, %{status: 200, body: %{"data" => data}}} ->
        config = %{
          consul_policies: Map.get(data, "consul_policies", []),
          consul_roles: Map.get(data, "consul_roles", []),
          service_identities: Map.get(data, "service_identities", []),
          node_identities: Map.get(data, "node_identities", []),
          consul_namespace: Map.get(data, "consul_namespace"),
          partition: Map.get(data, "partition"),
          ttl: Map.get(data, "ttl"),
          max_ttl: Map.get(data, "max_ttl"),
          local: Map.get(data, "local", false),
          # Legacy fields for older Consul versions
          token_type: Map.get(data, "token_type"),
          policy: Map.get(data, "policy"),
          policies: Map.get(data, "policies", []),
          lease: Map.get(data, "lease")
        }

        {:ok, config}

      {:ok, response} ->
        {:error, Error.from_http_response(response.status, response.body)}

      {:error, reason} ->
        {:error, Error.new(:http_error, "HTTP request failed", details: %{reason: reason})}
    end
  end

  @doc """
  List all configured Consul roles.

  ## Examples

      {:ok, roles} = Consul.list_roles()
      ["web-service", "api-service", "node-role"]

  """
  @impl Behaviour
  def list_roles(opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    path = "/#{mount_path}/roles"

    case HTTP.request(:list, path, nil, [], opts) do
      {:ok, %{status: 200, body: %{"data" => %{"keys" => keys}}}} ->
        {:ok, keys}

      {:ok, response} ->
        {:error, Error.from_http_response(response.status, response.body)}

      {:error, reason} ->
        {:error, Error.new(:http_error, "HTTP request failed", details: %{reason: reason})}
    end
  end

  @doc """
  Delete a Consul role.

  ## Examples

      :ok = Consul.delete_role("old-role")

  """
  @impl Behaviour
  def delete_role(name, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    telemetry_metadata = %{
      operation: :delete_role,
      role_name: name,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()

    Telemetry.operation_start(telemetry_metadata)

    path = "/#{mount_path}/roles/#{name}"

    case HTTP.delete(path, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        duration = System.monotonic_time() - start_time
        Telemetry.operation_success(duration, telemetry_metadata)
        :ok

      {:ok, response} ->
        error = Error.from_http_response(response.status, response.body)
        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}

      {:error, reason} ->
        error = Error.new(:http_error, "HTTP request failed", details: %{reason: reason})
        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}
    end
  end

  @doc """
  Generate credentials for a Consul role.

  Generates a dynamic Consul ACL token based on the given role definition.
  The token will have the policies, roles, and identities configured in the role.

  ## Parameters

  - `name` - Role name to generate credentials for
  - `opts` - Request options

  ## Returns

  - `{:ok, credentials}` - Successfully generated credentials
  - `{:error, error}` - Failed to generate credentials

  ## Examples

      {:ok, creds} = Consul.generate_credentials("web-service")
      %{
        token: "8f246b77-f3e1-ff88-5b48-8ec93abf3e05"
      }

  """
  @impl Behaviour
  def generate_credentials(name, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    telemetry_metadata = %{
      operation: :generate_credentials,
      role_name: name,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()

    Telemetry.operation_start(telemetry_metadata)

    Logger.info("Generating Consul credentials", %{
      role_name: name,
      mount_path: mount_path
    })

    path = "/#{mount_path}/creds/#{name}"

    case HTTP.get(path, opts) do
      {:ok, %{status: 200, body: %{"data" => data}}} ->
        credentials = %{
          token: Map.get(data, "token")
        }

        Logger.info("Successfully generated Consul credentials", %{
          role_name: name,
          mount_path: mount_path
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_success(duration, telemetry_metadata)
        {:ok, credentials}

      {:ok, response} ->
        error = Error.from_http_response(response.status, response.body)

        Logger.error("Failed to generate Consul credentials", %{
          role_name: name,
          error: error
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}

      {:error, reason} ->
        error = Error.new(:http_error, "HTTP request failed", details: %{reason: reason})
        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}
    end
  end
end
