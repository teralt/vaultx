defmodule Vaultx.Secrets.RabbitMQ do
  @moduledoc """
  Unified RabbitMQ secrets engine interface for HashiCorp Vault.

  This module provides a comprehensive, enterprise-grade interface for the
  RabbitMQ secrets engine, offering dynamic credential management, connection
  configuration, and role management. It supports all RabbitMQ authentication
  and authorization features with advanced security capabilities.

  ## Enterprise RabbitMQ Credential Management

  - Dynamic Credential Generation: RabbitMQ users with configurable permissions
  - Connection Management: RabbitMQ server connection configuration
  - Role Management: Dynamic role configuration with permission enforcement
  - Lease Management: Configurable TTL and maximum TTL for credentials
  - Security Compliance: Audit logging, least privilege, and policy validation

  ## Supported RabbitMQ Features

  ### User Management
  - Dynamic Users: Temporary users with specific permissions
  - Virtual Host Access: Fine-grained vhost permission control
  - Topic Permissions: Exchange-level topic permission management (RabbitMQ 3.7+)
  - Management Tags: Administrative privilege assignment

  ### Permission Types
  - Configure: Queue and exchange configuration permissions
  - Write: Message publishing permissions
  - Read: Message consumption permissions
  - Topic: Topic-based routing permissions

  ## Configuration Examples

      # Configure RabbitMQ connection
      config = %{
        connection_uri: "http://localhost:15672",
        username: "admin",
        password: "admin123",
        verify_connection: true
      }
      {:ok, _} = RabbitMQ.configure_connection(config)

      # Configure lease settings
      lease_config = %{
        ttl: 1800,
        max_ttl: 3600
      }
      {:ok, _} = RabbitMQ.configure_lease(lease_config)

      # Create a role with vhost permissions
      role_config = %{
        tags: "management",
        vhosts: "{\"/\": {\"configure\":\".*\", \"write\":\".*\", \"read\": \".*\"}}",
        vhost_topics: "{\"/\": {\"amq.topic\": {\"write\":\".*\", \"read\": \".*\"}}}"
      }
      {:ok, _} = RabbitMQ.create_role("web-service", role_config)

      # Generate credentials
      {:ok, creds} = RabbitMQ.generate_credentials("web-service")

  ## API Compliance

  Fully implements HashiCorp Vault RabbitMQ secrets engine:
  - [RabbitMQ Secrets Engine API](https://developer.hashicorp.com/vault/api-docs/secret/rabbitmq)
  - [RabbitMQ Secrets Engine Guide](https://developer.hashicorp.com/vault/docs/secrets/rabbitmq)
  - [RabbitMQ Management API](https://www.rabbitmq.com/management.html)

  """

  alias Vaultx.Base.{Error, Logger, Telemetry}
  alias Vaultx.Secrets.RabbitMQ.Behaviour
  alias Vaultx.Transport.HTTP

  @behaviour Behaviour

  @default_mount_path "rabbitmq"

  # Configuration Operations

  @doc """
  Configure connection information for RabbitMQ.

  Sets up the RabbitMQ connection parameters that Vault will use to communicate
  with RabbitMQ and generate credentials. Supports both HTTP and HTTPS connections
  with optional connection verification.

  ## Parameters

  - `config` - Connection configuration parameters
  - `opts` - Request options including mount path

  ## Examples

      # Basic HTTP configuration
      config = %{
        connection_uri: "http://localhost:15672",
        username: "admin",
        password: "admin123"
      }
      {:ok, _} = RabbitMQ.configure_connection(config)

      # HTTPS with custom password policy
      config = %{
        connection_uri: "https://rabbitmq.example.com:15671",
        username: "vault-admin",
        password: "secure-password",
        verify_connection: true,
        password_policy: "rabbitmq_policy",
        username_template: "vault-{{.DisplayName}}-{{random 8}}"
      }

  """
  @impl Behaviour
  def configure_connection(config, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    telemetry_metadata = %{
      operation: :configure_connection,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()

    Telemetry.operation_start(telemetry_metadata)

    Logger.info("Configuring RabbitMQ connection", %{
      mount_path: mount_path,
      connection_uri: Map.get(config, :connection_uri),
      username: Map.get(config, :username)
    })

    path = "/#{mount_path}/config/connection"

    case HTTP.post(path, config, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        Logger.info("Successfully configured RabbitMQ connection", %{
          mount_path: mount_path
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_success(duration, telemetry_metadata)
        :ok

      {:ok, response} ->
        error = Error.from_http_response(response.status, response.body)

        Logger.error("Failed to configure RabbitMQ connection", %{
          mount_path: mount_path,
          error: error
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}

      {:error, reason} ->
        error = Error.new(:http_error, "HTTP request failed", details: %{reason: reason})

        Logger.error("HTTP error configuring RabbitMQ connection", %{
          mount_path: mount_path,
          error: error
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}
    end
  end

  @doc """
  Configure lease settings for generated credentials.

  Sets the default TTL and maximum TTL for dynamically generated
  RabbitMQ credentials.

  ## Parameters

  - `config` - Lease configuration parameters
  - `opts` - Request options

  ## Examples

      config = %{
        ttl: 1800,
        max_ttl: 3600
      }
      {:ok, _} = RabbitMQ.configure_lease(config)

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

    Logger.info("Configuring RabbitMQ lease settings", %{
      mount_path: mount_path,
      ttl: Map.get(config, :ttl),
      max_ttl: Map.get(config, :max_ttl)
    })

    path = "/#{mount_path}/config/lease"

    case HTTP.post(path, config, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        Logger.info("Successfully configured RabbitMQ lease settings", %{
          mount_path: mount_path
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_success(duration, telemetry_metadata)
        :ok

      {:ok, response} ->
        error = Error.from_http_response(response.status, response.body)

        Logger.error("Failed to configure RabbitMQ lease settings", %{
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

  # Role Operations

  @doc """
  Create or update a RabbitMQ role.

  Configures a role that can be used to generate RabbitMQ credentials.
  The role defines the permissions, virtual hosts, and tags that will be
  assigned to generated users.

  ## Parameters

  - `name` - Role name
  - `config` - Role configuration
  - `opts` - Request options

  ## Examples

      # Basic role with management tags
      config = %{
        tags: "management",
        vhosts: "{\"/\": {\"configure\":\".*\", \"write\":\".*\", \"read\": \".*\"}}"
      }
      {:ok, _} = RabbitMQ.create_role("web-service", config)

      # Role with topic permissions (RabbitMQ 3.7+)
      config = %{
        tags: "monitoring",
        vhosts: "{\"/\": {\"configure\":\"\", \"write\":\"\", \"read\": \".*\"}}",
        vhost_topics: "{\"/\": {\"amq.topic\": {\"write\":\"\", \"read\": \".*\"}}}"
      }
      {:ok, _} = RabbitMQ.create_role("monitoring-role", config)

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

    Logger.info("Creating RabbitMQ role", %{
      role_name: name,
      mount_path: mount_path,
      tags: Map.get(config, :tags)
    })

    path = "/#{mount_path}/roles/#{name}"

    case HTTP.post(path, config, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        Logger.info("Successfully created RabbitMQ role", %{
          role_name: name,
          mount_path: mount_path
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_success(duration, telemetry_metadata)
        :ok

      {:ok, response} ->
        error = Error.from_http_response(response.status, response.body)

        Logger.error("Failed to create RabbitMQ role", %{
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
  Read a RabbitMQ role configuration.

  ## Examples

      {:ok, config} = RabbitMQ.read_role("web-service")
      %{
        tags: "management",
        vhosts: "{\"/\": {\"configure\":\".*\", \"write\":\".*\", \"read\": \".*\"}}",
        vhost_topics: "{\"/\": {\"amq.topic\": {\"write\":\".*\", \"read\": \".*\"}}}"
      }

  """
  @impl Behaviour
  def read_role(name, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    path = "/#{mount_path}/roles/#{name}"

    case HTTP.get(path, opts) do
      {:ok, %{status: 200, body: %{"data" => data}}} ->
        config = %{
          tags: Map.get(data, "tags", ""),
          vhosts: Map.get(data, "vhosts", ""),
          vhost_topics: Map.get(data, "vhost_topics", "")
        }

        {:ok, config}

      {:ok, response} ->
        {:error, Error.from_http_response(response.status, response.body)}

      {:error, reason} ->
        {:error, Error.new(:http_error, "HTTP request failed", details: %{reason: reason})}
    end
  end

  @doc """
  Delete a RabbitMQ role.

  ## Examples

      :ok = RabbitMQ.delete_role("old-role")

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
  Generate credentials for a RabbitMQ role.

  Generates dynamic RabbitMQ credentials based on the given role definition.
  The credentials will have the permissions, virtual hosts, and tags
  configured in the role.

  ## Parameters

  - `name` - Role name to generate credentials for
  - `opts` - Request options

  ## Returns

  - `{:ok, credentials}` - Successfully generated credentials
  - `{:error, error}` - Failed to generate credentials

  ## Examples

      {:ok, creds} = RabbitMQ.generate_credentials("web-service")
      %{
        username: "root-4b95bf47-281d-dcb5-8a60-9594f8056092",
        password: "e1b6c159-ca63-4c6a-3886-6639eae06c30"
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

    Logger.info("Generating RabbitMQ credentials", %{
      role_name: name,
      mount_path: mount_path
    })

    path = "/#{mount_path}/creds/#{name}"

    case HTTP.get(path, opts) do
      {:ok, %{status: 200, body: %{"data" => data}}} ->
        credentials = %{
          username: Map.get(data, "username"),
          password: Map.get(data, "password")
        }

        Logger.info("Successfully generated RabbitMQ credentials", %{
          role_name: name,
          mount_path: mount_path,
          username: credentials.username
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_success(duration, telemetry_metadata)
        {:ok, credentials}

      {:ok, response} ->
        error = Error.from_http_response(response.status, response.body)

        Logger.error("Failed to generate RabbitMQ credentials", %{
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
