defmodule Vaultx.Secrets.Database.Behaviour do
  @moduledoc """
  Behaviour definition for HashiCorp Vault Database secrets engine operations.

  This behaviour defines the interface that Database secrets engine implementations
  must provide, ensuring consistency and type safety across different implementations.

  ## Core Operations

  The Database secrets engine supports the following operations:

  ### Connection Management Operations
  - `configure_connection/3` - Configure database connection parameters
  - `read_connection/2` - Read database connection configuration
  - `list_connections/1` - List all configured connections
  - `delete_connection/2` - Delete a database connection
  - `reset_connection/2` - Reset a database connection
  - `reload_plugin/2` - Reload all connections for a plugin
  - `rotate_root_credentials/2` - Rotate root credentials for a connection

  ### Dynamic Role Management Operations
  - `create_role/3` - Create or update a dynamic database role
  - `read_role/2` - Read a dynamic database role configuration
  - `list_roles/1` - List all configured dynamic roles
  - `delete_role/2` - Delete a dynamic database role
  - `generate_credentials/2` - Generate dynamic database credentials

  ### Static Role Management Operations
  - `create_static_role/3` - Create or update a static database role
  - `read_static_role/2` - Read a static database role configuration
  - `list_static_roles/1` - List all configured static roles
  - `delete_static_role/2` - Delete a static database role
  - `get_static_credentials/2` - Get current static role credentials
  - `rotate_static_role_credentials/2` - Manually rotate static role credentials

  ## API Compliance

  This behaviour ensures compliance with:
  - [Vault Database Secrets Engine API](https://developer.hashicorp.com/vault/api-docs/secret/databases)
  - [Database Secrets Engine Guide](https://developer.hashicorp.com/vault/docs/secrets/databases)

  """

  alias Vaultx.Base.Error

  @typedoc """
  Database connection name.
  Must be a non-empty string with valid characters.
  """
  @type connection_name :: String.t()

  @typedoc """
  Database role name.
  Must be a non-empty string with valid characters.
  """
  @type role_name :: String.t()

  @typedoc """
  Database connection configuration parameters.
  """
  @type connection_config :: %{
          required(:plugin_name) => String.t(),
          optional(:plugin_version) => String.t(),
          optional(:verify_connection) => boolean(),
          optional(:allowed_roles) => [String.t()],
          optional(:root_rotation_statements) => [String.t()],
          optional(:password_policy) => String.t(),
          optional(:skip_static_role_import_rotation) => boolean(),
          optional(:rotation_period) => non_neg_integer(),
          optional(:rotation_schedule) => String.t(),
          optional(:rotation_window) => non_neg_integer(),
          optional(:disable_automated_rotation) => boolean(),
          optional(:connection_url) => String.t(),
          optional(:username) => String.t(),
          optional(:password) => String.t(),
          optional(:disable_escaping) => boolean()
        }

  @typedoc """
  Database role configuration parameters.
  """
  @type role_config :: %{
          required(:db_name) => String.t(),
          required(:creation_statements) => [String.t()],
          optional(:default_ttl) => non_neg_integer(),
          optional(:max_ttl) => non_neg_integer(),
          optional(:revocation_statements) => [String.t()],
          optional(:rollback_statements) => [String.t()],
          optional(:renew_statements) => [String.t()],
          optional(:credential_type) => String.t(),
          optional(:credential_config) => map()
        }

  @typedoc """
  Database static role configuration parameters.
  """
  @type static_role_config :: %{
          required(:username) => String.t(),
          required(:db_name) => String.t(),
          optional(:password) => String.t(),
          optional(:self_managed_password) => String.t(),
          optional(:rotation_period) => non_neg_integer(),
          optional(:rotation_schedule) => String.t(),
          optional(:rotation_window) => non_neg_integer(),
          optional(:rotation_statements) => [String.t()],
          optional(:skip_import_rotation) => boolean(),
          optional(:credential_type) => String.t(),
          optional(:credential_config) => map()
        }

  @typedoc """
  Generated database credentials.
  """
  @type credentials :: %{
          username: String.t(),
          password: String.t()
        }

  @typedoc """
  Static role credentials with metadata.
  """
  @type static_credentials :: %{
          username: String.t(),
          password: String.t(),
          last_vault_rotation: String.t(),
          ttl: non_neg_integer(),
          rotation_period: non_neg_integer() | nil,
          rotation_schedule: String.t() | nil,
          rotation_window: non_neg_integer() | nil
        }

  @typedoc """
  Options for Database secrets engine operations.
  """
  @type operation_opts :: [
          mount_path: String.t(),
          timeout: pos_integer(),
          retry_attempts: non_neg_integer()
        ]

  @typedoc """
  Result of a configuration operation.
  """
  @type configure_result :: :ok | {:error, Error.t()}

  @typedoc """
  Result of a read configuration operation.
  """
  @type read_config_result :: {:ok, map()} | {:error, Error.t()}

  @typedoc """
  Result of a list operation.
  """
  @type list_result :: {:ok, [String.t()]} | {:error, Error.t()}

  @typedoc """
  Result of a role creation operation.
  """
  @type create_role_result :: :ok | {:error, Error.t()}

  @typedoc """
  Result of a role read operation.
  """
  @type read_role_result :: {:ok, role_config()} | {:error, Error.t()}

  @typedoc """
  Result of a static role read operation.
  """
  @type read_static_role_result :: {:ok, static_role_config()} | {:error, Error.t()}

  @typedoc """
  Result of a role delete operation.
  """
  @type delete_role_result :: :ok | {:error, Error.t()}

  @typedoc """
  Result of a credential generation operation.
  """
  @type generate_credentials_result :: {:ok, credentials()} | {:error, Error.t()}

  @typedoc """
  Result of a static credential retrieval operation.
  """
  @type get_static_credentials_result :: {:ok, static_credentials()} | {:error, Error.t()}

  @typedoc """
  Result of a plugin reload operation.
  """
  @type reload_plugin_result ::
          {:ok, %{connections: [String.t()], count: non_neg_integer()}} | {:error, Error.t()}

  # Connection Management Operations

  @doc """
  Configure a database connection.

  Sets up the connection parameters that Vault will use to communicate
  with the database and generate credentials.

  ## Parameters

  - `name` - Connection name
  - `config` - Connection configuration parameters
  - `opts` - Operation options

  ## Returns

  - `:ok` - Successfully configured connection
  - `{:error, error}` - Failed to configure connection

  ## Examples

      config = %{
        plugin_name: "mysql-database-plugin",
        connection_url: "{{username}}:{{password}}@tcp(127.0.0.1:3306)/",
        username: "vaultuser",
        password: "secretpassword",
        allowed_roles: ["readonly"]
      }
      :ok = MyDatabase.configure_connection("mysql", config, [])

  """
  @callback configure_connection(connection_name(), connection_config(), operation_opts()) ::
              configure_result()

  @doc """
  Read database connection configuration.

  ## Parameters

  - `name` - Connection name to read
  - `opts` - Operation options

  ## Returns

  - `{:ok, config}` - Successfully read connection configuration
  - `{:error, error}` - Failed to read connection

  ## Examples

      {:ok, config} = MyDatabase.read_connection("mysql", [])

  """
  @callback read_connection(connection_name(), operation_opts()) :: read_config_result()

  @doc """
  List all configured database connections.

  ## Parameters

  - `opts` - Operation options

  ## Returns

  - `{:ok, connections}` - Successfully listed connections
  - `{:error, error}` - Failed to list connections

  ## Examples

      {:ok, connections} = MyDatabase.list_connections([])

  """
  @callback list_connections(operation_opts()) :: list_result()

  @doc """
  Delete a database connection.

  ## Parameters

  - `name` - Connection name to delete
  - `opts` - Operation options

  ## Returns

  - `:ok` - Successfully deleted connection
  - `{:error, error}` - Failed to delete connection

  ## Examples

      :ok = MyDatabase.delete_connection("old-connection", [])

  """
  @callback delete_connection(connection_name(), operation_opts()) :: configure_result()

  @doc """
  Reset a database connection.

  Closes the connection and restarts it with stored configuration.

  ## Parameters

  - `name` - Connection name to reset
  - `opts` - Operation options

  ## Returns

  - `:ok` - Successfully reset connection
  - `{:error, error}` - Failed to reset connection

  ## Examples

      :ok = MyDatabase.reset_connection("mysql", [])

  """
  @callback reset_connection(connection_name(), operation_opts()) :: configure_result()

  @doc """
  Reload all connections for a specific plugin.

  ## Parameters

  - `plugin_name` - Plugin name to reload
  - `opts` - Operation options

  ## Returns

  - `{:ok, result}` - Successfully reloaded plugin connections
  - `{:error, error}` - Failed to reload plugin

  ## Examples

      {:ok, result} = MyDatabase.reload_plugin("postgresql-database-plugin", [])

  """
  @callback reload_plugin(String.t(), operation_opts()) :: reload_plugin_result()

  @doc """
  Rotate root credentials for a database connection.

  ## Parameters

  - `name` - Connection name to rotate credentials for
  - `opts` - Operation options

  ## Returns

  - `:ok` - Successfully rotated root credentials
  - `{:error, error}` - Failed to rotate credentials

  ## Examples

      :ok = MyDatabase.rotate_root_credentials("mysql", [])

  """
  @callback rotate_root_credentials(connection_name(), operation_opts()) :: configure_result()

  # Dynamic Role Management Operations

  @doc """
  Create or update a dynamic database role.

  Configures a role that can be used to generate dynamic database credentials.
  The role defines the database statements and constraints for credential generation.

  ## Parameters

  - `name` - Role name
  - `config` - Role configuration parameters
  - `opts` - Operation options

  ## Returns

  - `:ok` - Successfully created/updated role
  - `{:error, error}` - Failed to create/update role

  ## Examples

      config = %{
        db_name: "mysql",
        creation_statements: [
          "CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}'",
          "GRANT SELECT ON *.* TO '{{name}}'@'%'"
        ],
        default_ttl: 3600,
        max_ttl: 86400
      }
      :ok = MyDatabase.create_role("readonly", config, [])

  """
  @callback create_role(role_name(), role_config(), operation_opts()) :: create_role_result()

  @doc """
  Read a dynamic database role configuration.

  ## Parameters

  - `name` - Role name to read
  - `opts` - Operation options

  ## Returns

  - `{:ok, config}` - Successfully read role configuration
  - `{:error, error}` - Failed to read role

  ## Examples

      {:ok, config} = MyDatabase.read_role("readonly", [])

  """
  @callback read_role(role_name(), operation_opts()) :: read_role_result()

  @doc """
  List all configured dynamic database roles.

  ## Parameters

  - `opts` - Operation options

  ## Returns

  - `{:ok, roles}` - Successfully listed roles
  - `{:error, error}` - Failed to list roles

  ## Examples

      {:ok, roles} = MyDatabase.list_roles([])

  """
  @callback list_roles(operation_opts()) :: list_result()

  @doc """
  Delete a dynamic database role.

  ## Parameters

  - `name` - Role name to delete
  - `opts` - Operation options

  ## Returns

  - `:ok` - Successfully deleted role
  - `{:error, error}` - Failed to delete role

  ## Examples

      :ok = MyDatabase.delete_role("old-role", [])

  """
  @callback delete_role(role_name(), operation_opts()) :: delete_role_result()

  @doc """
  Generate credentials for a dynamic database role.

  Generates dynamic database credentials based on the given role definition.

  ## Parameters

  - `name` - Role name to generate credentials for
  - `opts` - Operation options

  ## Returns

  - `{:ok, credentials}` - Successfully generated credentials
  - `{:error, error}` - Failed to generate credentials

  ## Examples

      {:ok, creds} = MyDatabase.generate_credentials("readonly", [])

  """
  @callback generate_credentials(role_name(), operation_opts()) :: generate_credentials_result()

  # Static Role Management Operations

  @doc """
  Create or update a static database role.

  Configures a static role that maps to an existing database user.
  Static roles are automatically rotated based on configured schedules.

  ## Parameters

  - `name` - Static role name
  - `config` - Static role configuration parameters
  - `opts` - Operation options

  ## Returns

  - `:ok` - Successfully created/updated static role
  - `{:error, error}` - Failed to create/update static role

  ## Examples

      config = %{
        db_name: "mysql",
        username: "static-database-user",
        rotation_statements: [
          "ALTER USER \"{{name}}\" IDENTIFIED BY '{{password}}';"
        ],
        rotation_period: 3600
      }
      :ok = MyDatabase.create_static_role("static-user", config, [])

  """
  @callback create_static_role(role_name(), static_role_config(), operation_opts()) ::
              create_role_result()

  @doc """
  Read a static database role configuration.

  ## Parameters

  - `name` - Static role name to read
  - `opts` - Operation options

  ## Returns

  - `{:ok, config}` - Successfully read static role configuration
  - `{:error, error}` - Failed to read static role

  ## Examples

      {:ok, config} = MyDatabase.read_static_role("static-user", [])

  """
  @callback read_static_role(role_name(), operation_opts()) :: read_static_role_result()

  @doc """
  List all configured static database roles.

  ## Parameters

  - `opts` - Operation options

  ## Returns

  - `{:ok, roles}` - Successfully listed static roles
  - `{:error, error}` - Failed to list static roles

  ## Examples

      {:ok, roles} = MyDatabase.list_static_roles([])

  """
  @callback list_static_roles(operation_opts()) :: list_result()

  @doc """
  Delete a static database role.

  ## Parameters

  - `name` - Static role name to delete
  - `opts` - Operation options

  ## Returns

  - `:ok` - Successfully deleted static role
  - `{:error, error}` - Failed to delete static role

  ## Examples

      :ok = MyDatabase.delete_static_role("old-static-role", [])

  """
  @callback delete_static_role(role_name(), operation_opts()) :: delete_role_result()

  @doc """
  Get current credentials for a static database role.

  ## Parameters

  - `name` - Static role name to get credentials for
  - `opts` - Operation options

  ## Returns

  - `{:ok, credentials}` - Successfully retrieved static credentials
  - `{:error, error}` - Failed to get static credentials

  ## Examples

      {:ok, creds} = MyDatabase.get_static_credentials("static-user", [])

  """
  @callback get_static_credentials(role_name(), operation_opts()) ::
              get_static_credentials_result()

  @doc """
  Manually rotate credentials for a static database role.

  ## Parameters

  - `name` - Static role name to rotate credentials for
  - `opts` - Operation options

  ## Returns

  - `:ok` - Successfully rotated static role credentials
  - `{:error, error}` - Failed to rotate credentials

  ## Examples

      :ok = MyDatabase.rotate_static_role_credentials("static-user", [])

  """
  @callback rotate_static_role_credentials(role_name(), operation_opts()) :: configure_result()
end
