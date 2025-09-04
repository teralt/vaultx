defmodule Vaultx.Secrets.Database do
  @moduledoc """
  Unified Database secrets engine interface for HashiCorp Vault.

  This module provides a comprehensive, enterprise-grade interface for the
  Database secrets engine, offering dynamic and static credential management,
  connection configuration, and role management. It supports all major database
  types with advanced security features and compliance capabilities.

  ## Enterprise Database Credential Management

  - Dynamic Credential Generation: Database users with configurable TTL and permissions
  - Static Credential Management: Automatic rotation of existing database users
  - Connection Management: Multiple database connections with plugin support
  - Role Management: Dynamic and static role configuration with policy enforcement
  - Root Credential Rotation: Automatic rotation of root database credentials
  - Multi-Database Support: MySQL, PostgreSQL, MongoDB, Oracle, MSSQL, and more
  - Security Compliance: Audit logging, least privilege, and policy validation

  ## Supported Database Types

  ### Relational Databases
  - MySQL/MariaDB: Full support for user management and permissions
  - PostgreSQL: Advanced role management with schema-level permissions
  - Oracle: Enterprise database support with tablespace management
  - Microsoft SQL Server: Windows and SQL authentication support
  - IBM DB2: Enterprise mainframe database support

  ### NoSQL Databases
  - MongoDB: User and role management with database-level permissions
  - Cassandra: Keyspace and table-level access control
  - Elasticsearch: Index and cluster-level permissions
  - InfluxDB: Database and retention policy management
  - Redis: ACL-based user management (Redis 6+)

  ### Cloud Databases
  - Amazon RDS: Multi-engine support with IAM integration
  - Google Cloud SQL: Service account and user management
  - Azure SQL Database: Azure AD integration support
  - MongoDB Atlas: Cloud-native user management

  ## Configuration Examples

      # Configure MySQL connection
      config = %{
        plugin_name: "mysql-database-plugin",
        connection_url: "{{username}}:{{password}}@tcp(127.0.0.1:3306)/",
        username: "vaultuser",
        password: "secretpassword",
        allowed_roles: ["readonly", "readwrite"]
      }
      {:ok, _} = Database.configure_connection("mysql", config)

      # Create dynamic role
      role_config = %{
        db_name: "mysql",
        creation_statements: [
          "CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}'",
          "GRANT SELECT ON *.* TO '{{name}}'@'%'"
        ],
        default_ttl: 3600,
        max_ttl: 86400
      }
      {:ok, _} = Database.create_role("readonly", role_config)

      # Generate dynamic credentials
      {:ok, creds} = Database.generate_credentials("readonly")

      # Create static role
      static_config = %{
        db_name: "mysql",
        username: "static-database-user",
        rotation_statements: [
          "ALTER USER \"{{name}}\" IDENTIFIED BY '{{password}}';"
        ],
        rotation_period: 3600
      }
      {:ok, _} = Database.create_static_role("static-user", static_config)

  ## API Compliance

  Fully implements HashiCorp Vault Database secrets engine:
  - [Database Secrets Engine API](https://developer.hashicorp.com/vault/api-docs/secret/databases)
  - [Database Secrets Engine Guide](https://developer.hashicorp.com/vault/docs/secrets/databases)

  """

  alias Vaultx.Base.{Error, Logger, Telemetry}
  alias Vaultx.Secrets.Database.{Behaviour, StaticRoles}
  alias Vaultx.Transport.HTTP

  @behaviour Behaviour

  @default_mount_path "database"

  # Connection Management Operations

  @doc """
  Configure a database connection.

  Sets up the database connection parameters that Vault will use to communicate
  with the database and generate credentials. Supports multiple database types
  through plugin system.

  ## Parameters

  - `name` - Connection name
  - `config` - Connection configuration parameters
  - `opts` - Request options including mount path

  ## Examples

      # MySQL connection
      config = %{
        plugin_name: "mysql-database-plugin",
        connection_url: "{{username}}:{{password}}@tcp(127.0.0.1:3306)/",
        username: "vaultuser",
        password: "secretpassword",
        allowed_roles: ["readonly"]
      }
      {:ok, _} = Database.configure_connection("mysql", config)

      # PostgreSQL with TLS and advanced configuration
      config = %{
        plugin_name: "postgresql-database-plugin",
        connection_url: "postgresql://{{username}}:{{password}}@localhost:5432/postgres?sslmode=require",
        username: "vaultuser",
        password: "secretpassword",
        max_open_connections: 10,
        max_idle_connections: 5,
        max_connection_lifetime: "30s",
        username_template: "v-{{.RoleName}}-{{random 8}}-{{unix_time}}",
        password_authentication: "scram-sha-256",  # For PostgreSQL 10+
        disable_escaping: false
      }

      # PostgreSQL with multiple hosts for High Availability
      ha_config = %{
        plugin_name: "postgresql-database-plugin",
        connection_url: "postgresql://{{username}}:{{password}}@primary:5432,secondary:5432/postgres",
        username: "vaultuser",
        password: "secretpassword",
        allowed_roles: ["readonly", "readwrite"]
      }

      # PostgreSQL with Google Cloud SQL IAM authentication
      gcp_config = %{
        plugin_name: "postgresql-database-plugin",
        connection_url: "host=/cloudsql/project:region:instance user={{username}} password={{password}} dbname=postgres",
        auth_type: "gcp_iam",
        service_account_json: "{\"type\":\"service_account\",\"project_id\":\"my-project\"}",
        use_private_ip: true,
        allowed_roles: ["app-readonly"]
      }

  """
  @impl Behaviour
  def configure_connection(name, config, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    telemetry_metadata = %{
      operation: :configure_connection,
      connection_name: name,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()

    Telemetry.operation_start(telemetry_metadata)

    Logger.info("Configuring database connection", %{
      connection_name: name,
      mount_path: mount_path,
      plugin_name: Map.get(config, :plugin_name),
      allowed_roles: Map.get(config, :allowed_roles, [])
    })

    path = "/#{mount_path}/config/#{name}"

    case HTTP.post(path, config, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        Logger.info("Successfully configured database connection", %{
          connection_name: name,
          mount_path: mount_path
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_success(duration, telemetry_metadata)
        :ok

      {:ok, response} ->
        error = Error.from_http_response(response.status, response.body)

        Logger.error("Failed to configure database connection", %{
          connection_name: name,
          error: error
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}

      {:error, reason} ->
        error = Error.new(:http_error, "HTTP request failed", details: %{reason: reason})

        Logger.error("HTTP error configuring database connection", %{
          connection_name: name,
          error: error
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}
    end
  end

  @doc """
  Read database connection configuration.

  ## Examples

      {:ok, config} = Database.read_connection("mysql")
      %{
        allowed_roles: ["readonly"],
        connection_details: %{
          connection_url: "{{username}}:{{password}}@tcp(127.0.0.1:3306)/",
          username: "vaultuser"
        },
        plugin_name: "mysql-database-plugin"
      }

  """
  @impl Behaviour
  def read_connection(name, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    path = "/#{mount_path}/config/#{name}"

    case HTTP.get(path, opts) do
      {:ok, %{status: 200, body: %{"data" => data}}} ->
        config = %{
          allowed_roles: Map.get(data, "allowed_roles", []),
          connection_details: Map.get(data, "connection_details", %{}),
          password_policy: Map.get(data, "password_policy", ""),
          plugin_name: Map.get(data, "plugin_name"),
          plugin_version: Map.get(data, "plugin_version", ""),
          root_credentials_rotate_statements:
            Map.get(data, "root_credentials_rotate_statements", []),
          skip_static_role_import_rotation:
            Map.get(data, "skip_static_role_import_rotation", false)
        }

        {:ok, config}

      {:ok, response} ->
        {:error, Error.from_http_response(response.status, response.body)}

      {:error, reason} ->
        {:error, Error.new(:http_error, "HTTP request failed", details: %{reason: reason})}
    end
  end

  @doc """
  List all configured database connections.

  ## Examples

      {:ok, connections} = Database.list_connections()
      ["mysql", "postgres", "mongodb"]

  """
  @impl Behaviour
  def list_connections(opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    path = "/#{mount_path}/config"

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
  Delete a database connection.

  ## Examples

      :ok = Database.delete_connection("old-connection")

  """
  @impl Behaviour
  def delete_connection(name, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    telemetry_metadata = %{
      operation: :delete_connection,
      connection_name: name,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()

    Telemetry.operation_start(telemetry_metadata)

    path = "/#{mount_path}/config/#{name}"

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
  Reset a database connection.

  Closes the connection and restarts it with stored configuration.

  ## Examples

      :ok = Database.reset_connection("mysql")

  """
  @impl Behaviour
  def reset_connection(name, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    telemetry_metadata = %{
      operation: :reset_connection,
      connection_name: name,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()

    Telemetry.operation_start(telemetry_metadata)

    path = "/#{mount_path}/reset/#{name}"

    case HTTP.post(path, %{}, opts) do
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
  Reload all connections for a specific plugin.

  ## Examples

      {:ok, result} = Database.reload_plugin("postgresql-database-plugin")
      %{connections: ["pg1", "pg2"], count: 2}

  """
  @impl Behaviour
  def reload_plugin(plugin_name, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    telemetry_metadata = %{
      operation: :reload_plugin,
      plugin_name: plugin_name,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()

    Telemetry.operation_start(telemetry_metadata)

    path = "/#{mount_path}/reload/#{plugin_name}"

    case HTTP.post(path, %{}, opts) do
      {:ok, %{status: 200, body: %{"data" => data}}} ->
        result = %{
          connections: Map.get(data, "connections", []),
          count: Map.get(data, "count", 0)
        }

        duration = System.monotonic_time() - start_time
        Telemetry.operation_success(duration, telemetry_metadata)
        {:ok, result}

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
  Rotate root credentials for a database connection.

  ## Examples

      :ok = Database.rotate_root_credentials("mysql")

  """
  @impl Behaviour
  def rotate_root_credentials(name, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    telemetry_metadata = %{
      operation: :rotate_root_credentials,
      connection_name: name,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()

    Telemetry.operation_start(telemetry_metadata)

    Logger.info("Rotating root credentials for database connection", %{
      connection_name: name,
      mount_path: mount_path
    })

    path = "/#{mount_path}/rotate-root/#{name}"

    case HTTP.post(path, %{}, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        Logger.info("Successfully rotated root credentials", %{
          connection_name: name,
          mount_path: mount_path
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_success(duration, telemetry_metadata)
        :ok

      {:ok, response} ->
        error = Error.from_http_response(response.status, response.body)

        Logger.error("Failed to rotate root credentials", %{
          connection_name: name,
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

  # Dynamic Role Management Operations

  @doc """
  Create or update a dynamic database role.

  Configures a role that can be used to generate dynamic database credentials.
  The role defines the database statements and constraints for credential generation.

  ## Parameters

  - `name` - Role name
  - `config` - Role configuration parameters
  - `opts` - Request options

  ## Examples

      # MySQL readonly role
      config = %{
        db_name: "mysql",
        creation_statements: [
          "CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}'",
          "GRANT SELECT ON *.* TO '{{name}}'@'%'"
        ],
        default_ttl: 3600,
        max_ttl: 86400
      }
      :ok = Database.create_role("readonly", config)

      # PostgreSQL role with schema permissions and advanced features
      config = %{
        db_name: "postgres",
        creation_statements: [
          "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
          "GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";",
          "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO \"{{name}}\";"
        ],
        revocation_statements: [
          "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM \"{{name}}\";",
          "REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM \"{{name}}\";",
          "DROP ROLE IF EXISTS \"{{name}}\";"
        ],
        renew_statements: [
          "ALTER ROLE \"{{name}}\" VALID UNTIL '{{expiration}}';"
        ],
        rollback_statements: [
          "DROP ROLE IF EXISTS \"{{name}}\";"
        ]
      }

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

    Logger.info("Creating database role", %{
      role_name: name,
      mount_path: mount_path,
      db_name: Map.get(config, :db_name),
      credential_type: Map.get(config, :credential_type, "password")
    })

    path = "/#{mount_path}/roles/#{name}"

    case HTTP.post(path, config, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        Logger.info("Successfully created database role", %{
          role_name: name,
          mount_path: mount_path
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_success(duration, telemetry_metadata)
        :ok

      {:ok, response} ->
        error = Error.from_http_response(response.status, response.body)

        Logger.error("Failed to create database role", %{
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
  Read a dynamic database role configuration.

  ## Examples

      {:ok, config} = Database.read_role("readonly")
      %{
        creation_statements: [
          "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
          "GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"
        ],
        credential_type: "password",
        db_name: "postgres",
        default_ttl: 3600,
        max_ttl: 86400
      }

  """
  @impl Behaviour
  def read_role(name, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    path = "/#{mount_path}/roles/#{name}"

    case HTTP.get(path, opts) do
      {:ok, %{status: 200, body: %{"data" => data}}} ->
        config = %{
          creation_statements: Map.get(data, "creation_statements", []),
          credential_type: Map.get(data, "credential_type", "password"),
          credential_config: Map.get(data, "credential_config", %{}),
          db_name: Map.get(data, "db_name"),
          default_ttl: Map.get(data, "default_ttl", 0),
          max_ttl: Map.get(data, "max_ttl", 0),
          renew_statements: Map.get(data, "renew_statements", []),
          revocation_statements: Map.get(data, "revocation_statements", []),
          rollback_statements: Map.get(data, "rollback_statements", [])
        }

        {:ok, config}

      {:ok, response} ->
        {:error, Error.from_http_response(response.status, response.body)}

      {:error, reason} ->
        {:error, Error.new(:http_error, "HTTP request failed", details: %{reason: reason})}
    end
  end

  @doc """
  List all configured dynamic database roles.

  ## Examples

      {:ok, roles} = Database.list_roles()
      ["readonly", "readwrite", "admin"]

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
  Delete a dynamic database role.

  ## Examples

      :ok = Database.delete_role("old-role")

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
  Generate credentials for a dynamic database role.

  Generates dynamic database credentials based on the given role definition.

  ## Parameters

  - `name` - Role name to generate credentials for
  - `opts` - Request options

  ## Returns

  - `{:ok, credentials}` - Successfully generated credentials
  - `{:error, error}` - Failed to generate credentials

  ## Examples

      {:ok, creds} = Database.generate_credentials("readonly")
      %{
        username: "root-1430158508-126",
        password: "132ae3ef-5a64-7499-351e-bfe59f3a2a21"
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

    Logger.info("Generating database credentials", %{
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

        Logger.info("Successfully generated database credentials", %{
          role_name: name,
          mount_path: mount_path
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_success(duration, telemetry_metadata)
        {:ok, credentials}

      {:ok, response} ->
        error = Error.from_http_response(response.status, response.body)

        Logger.error("Failed to generate database credentials", %{
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

  # Static Role Management Operations
  # These functions are imported from StaticRoles module

  @impl Behaviour
  defdelegate create_static_role(name, config, opts \\ []), to: StaticRoles

  @impl Behaviour
  defdelegate read_static_role(name, opts \\ []), to: StaticRoles

  @impl Behaviour
  defdelegate list_static_roles(opts \\ []), to: StaticRoles

  @impl Behaviour
  defdelegate delete_static_role(name, opts \\ []), to: StaticRoles

  @impl Behaviour
  defdelegate get_static_credentials(name, opts \\ []), to: StaticRoles

  @impl Behaviour
  defdelegate rotate_static_role_credentials(name, opts \\ []), to: StaticRoles
end
