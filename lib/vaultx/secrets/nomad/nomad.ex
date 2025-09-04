defmodule Vaultx.Secrets.Nomad do
  @moduledoc """
  Unified Nomad secrets engine interface for HashiCorp Vault.

  This module provides a comprehensive, enterprise-grade interface for the
  Nomad secrets engine, offering dynamic credential management, configuration
  operations, and role management. It supports all Nomad token types
  with advanced security features and compliance capabilities.

  ## Enterprise Nomad Credential Management

  - Dynamic Token Generation: Nomad ACL tokens with policies and global scope
  - Configuration Management: Root credentials, access settings, and connection parameters
  - Role Management: Dynamic role configuration with policy enforcement
  - Lease Management: TTL and max TTL configuration for generated tokens
  - Multi-Version Support: Compatible with Nomad 0.8+ through latest versions
  - Security Compliance: Audit logging, least privilege, and policy validation

  ## Supported Token Types

  ### Client Tokens
  - Limited access tokens with specific policies
  - Suitable for application and service authentication
  - Can be scoped to specific policies and regions

  ### Management Tokens
  - Full administrative access tokens
  - Suitable for cluster administration and automation
  - Global scope with all permissions

  ## Configuration Examples

      # Configure root Nomad credentials
      config = %{
        address: "http://127.0.0.1:4646",
        token: "management-token-here",
        max_token_name_length: 256,
        ca_cert: "-----BEGIN CERTIFICATE-----...",
        client_cert: "-----BEGIN CERTIFICATE-----...",
        client_key: "-----BEGIN PRIVATE KEY-----..."
      }
      {:ok, _} = Nomad.configure_access(config)

      # Configure lease settings
      lease_config = %{
        ttl: "1h",
        max_ttl: "24h"
      }
      {:ok, _} = Nomad.configure_lease(lease_config)

      # Create a role with policies
      role_config = %{
        policies: "web-policy,db-read-policy",
        type: "client",
        global: false
      }
      {:ok, _} = Nomad.create_role("web-service", role_config)

      # Generate credentials
      {:ok, creds} = Nomad.generate_credentials("web-service")

  ## API Compliance

  Fully implements HashiCorp Vault Nomad secrets engine:
  - [Nomad Secrets Engine API](https://developer.hashicorp.com/vault/api-docs/secret/nomad)
  - [Nomad Secrets Engine Guide](https://developer.hashicorp.com/vault/docs/secrets/nomad)
  - [Nomad ACL System](https://developer.hashicorp.com/nomad/docs/operations/acl)

  """

  alias Vaultx.Base.{Error, Logger, Telemetry}
  alias Vaultx.Secrets.Nomad.Behaviour
  alias Vaultx.Transport.HTTP

  @behaviour Behaviour

  @default_mount_path "nomad"

  # Configuration Operations

  @doc """
  Configure access information for Nomad.

  Sets up the Nomad connection parameters that Vault will use to communicate
  with Nomad and generate tokens. Supports both HTTP and HTTPS connections
  with optional TLS client certificate authentication.

  ## Parameters

  - `config` - Access configuration parameters
  - `opts` - Request options including mount path

  ## Examples

      # Basic HTTP configuration
      config = %{
        address: "http://127.0.0.1:4646",
        token: "management-token"
      }
      {:ok, _} = Nomad.configure_access(config)

      # HTTPS with client certificates
      config = %{
        address: "https://nomad.example.com:4646",
        token: "management-token",
        ca_cert: File.read!("ca.pem"),
        client_cert: File.read!("client.pem"),
        client_key: File.read!("client-key.pem"),
        max_token_name_length: 256
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

    Logger.info("Configuring Nomad access", %{
      mount_path: mount_path,
      address: Map.get(config, :address),
      max_token_name_length: Map.get(config, :max_token_name_length)
    })

    path = "/#{mount_path}/config/access"

    case HTTP.post(path, config, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        Logger.info("Successfully configured Nomad access", %{
          mount_path: mount_path
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_success(duration, telemetry_metadata)
        :ok

      {:ok, response} ->
        error = Error.from_http_response(response.status, response.body)

        Logger.error("Failed to configure Nomad access", %{
          mount_path: mount_path,
          error: error
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}

      {:error, reason} ->
        error = Error.new(:http_error, "HTTP request failed", details: %{reason: reason})

        Logger.error("HTTP error configuring Nomad access", %{
          mount_path: mount_path,
          error: error
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}
    end
  end

  @doc """
  Read access configuration for Nomad.

  ## Examples

      {:ok, config} = Nomad.read_access_config()
      %{
        address: "http://localhost:4646/"
      }

  """
  @impl Behaviour
  def read_access_config(opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    path = "/#{mount_path}/config/access"

    case HTTP.get(path, opts) do
      {:ok, %{status: 200, body: %{"data" => data}}} ->
        config = %{
          address: Map.get(data, "address")
        }

        {:ok, config}

      {:ok, response} ->
        {:error, Error.from_http_response(response.status, response.body)}

      {:error, reason} ->
        {:error, Error.new(:http_error, "HTTP request failed", details: %{reason: reason})}
    end
  end

  @doc """
  Configure lease settings for generated tokens.

  ## Parameters

  - `config` - Lease configuration parameters
  - `opts` - Request options

  ## Examples

      config = %{
        ttl: "1h",
        max_ttl: "24h"
      }
      {:ok, _} = Nomad.configure_lease(config)

  """
  @impl Behaviour
  def configure_lease(config, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    telemetry_metadata = %{
      operation: :configure_lease,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()

    Telemetry.operation_start(telemetry_metadata)

    Logger.info("Configuring Nomad lease", %{
      mount_path: mount_path,
      ttl: Map.get(config, :ttl),
      max_ttl: Map.get(config, :max_ttl)
    })

    path = "/#{mount_path}/config/lease"

    case HTTP.post(path, config, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        Logger.info("Successfully configured Nomad lease", %{
          mount_path: mount_path
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_success(duration, telemetry_metadata)
        :ok

      {:ok, response} ->
        error = Error.from_http_response(response.status, response.body)

        Logger.error("Failed to configure Nomad lease", %{
          mount_path: mount_path,
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
  Read lease configuration.

  ## Examples

      {:ok, config} = Nomad.read_lease_config()
      %{
        max_ttl: 86400,
        ttl: 86400
      }

  """
  @impl Behaviour
  def read_lease_config(opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    path = "/#{mount_path}/config/lease"

    case HTTP.get(path, opts) do
      {:ok, %{status: 200, body: %{"data" => data}}} ->
        config = %{
          ttl: Map.get(data, "ttl"),
          max_ttl: Map.get(data, "max_ttl")
        }

        {:ok, config}

      {:ok, response} ->
        {:error, Error.from_http_response(response.status, response.body)}

      {:error, reason} ->
        {:error, Error.new(:http_error, "HTTP request failed", details: %{reason: reason})}
    end
  end

  @doc """
  Delete lease configuration.

  ## Examples

      :ok = Nomad.delete_lease_config()

  """
  @impl Behaviour
  def delete_lease_config(opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    telemetry_metadata = %{
      operation: :delete_lease_config,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()

    Telemetry.operation_start(telemetry_metadata)

    path = "/#{mount_path}/config/lease"

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

  # Role Operations

  @doc """
  Create or update a Nomad role.

  Configures a role that can be used to generate Nomad tokens.
  The role defines the type of credentials to generate and the
  associated policies and constraints.

  ## Parameters

  - `name` - Role name
  - `config` - Role configuration
  - `opts` - Request options

  ## Examples

      # Client token with policies
      config = %{
        policies: "web-policy,db-read-policy",
        type: "client",
        global: false
      }
      {:ok, _} = Nomad.create_role("web-service", config)

      # Management token
      config = %{
        type: "management",
        global: true
      }
      {:ok, _} = Nomad.create_role("admin-role", config)

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

    Logger.info("Creating Nomad role", %{
      role_name: name,
      mount_path: mount_path,
      policies: Map.get(config, :policies),
      type: Map.get(config, :type, "client")
    })

    path = "/#{mount_path}/role/#{name}"

    case HTTP.post(path, config, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        Logger.info("Successfully created Nomad role", %{
          role_name: name,
          mount_path: mount_path
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_success(duration, telemetry_metadata)
        :ok

      {:ok, response} ->
        error = Error.from_http_response(response.status, response.body)

        Logger.error("Failed to create Nomad role", %{
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
  Read a Nomad role configuration.

  ## Examples

      {:ok, config} = Nomad.read_role("web-service")
      %{
        policies: ["web-policy", "db-read-policy"],
        type: "client",
        global: false
      }

  """
  @impl Behaviour
  def read_role(name, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    path = "/#{mount_path}/role/#{name}"

    case HTTP.get(path, opts) do
      {:ok, %{status: 200, body: %{"data" => data}}} ->
        config = %{
          policies: parse_policies(Map.get(data, "policies", [])),
          type: Map.get(data, "token_type", "client"),
          global: Map.get(data, "global", false),
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
  List all configured Nomad roles.

  ## Examples

      {:ok, roles} = Nomad.list_roles()
      ["web-service", "api-service", "admin-role"]

  """
  @impl Behaviour
  def list_roles(opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    path = "/#{mount_path}/role"

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
  Delete a Nomad role.

  ## Examples

      :ok = Nomad.delete_role("old-role")

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

    path = "/#{mount_path}/role/#{name}"

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
  Generate credentials for a Nomad role.

  Generates a dynamic Nomad token based on the given role definition.
  The token will have the policies and type configured in the role.

  ## Parameters

  - `name` - Role name to generate credentials for
  - `opts` - Request options

  ## Returns

  - `{:ok, credentials}` - Successfully generated credentials
  - `{:error, error}` - Failed to generate credentials

  ## Examples

      {:ok, creds} = Nomad.generate_credentials("web-service")
      %{
        accessor_id: "c834ba40-8d84-b0c1-c084-3a31d3383c03",
        secret_id: "65af6f07-7f57-bb24-cdae-a27f86a894ce"
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

    Logger.info("Generating Nomad credentials", %{
      role_name: name,
      mount_path: mount_path
    })

    path = "/#{mount_path}/creds/#{name}"

    case HTTP.get(path, opts) do
      {:ok, %{status: 200, body: %{"data" => data}}} ->
        credentials = %{
          accessor_id: Map.get(data, "accessor_id"),
          secret_id: Map.get(data, "secret_id")
        }

        Logger.info("Successfully generated Nomad credentials", %{
          role_name: name,
          mount_path: mount_path
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_success(duration, telemetry_metadata)
        {:ok, credentials}

      {:ok, response} ->
        error = Error.from_http_response(response.status, response.body)

        Logger.error("Failed to generate Nomad credentials", %{
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

  # Private helper functions

  defp parse_policies(policies) when is_list(policies), do: policies

  defp parse_policies(policies) when is_binary(policies) do
    policies
    |> String.split(",")
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
  end

  defp parse_policies(_), do: []
end
