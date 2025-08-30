defmodule Vaultx.Secrets.RabbitMQ.Behaviour do
  @moduledoc """
  Behaviour definition for HashiCorp Vault RabbitMQ secrets engine operations.

  This behaviour defines the interface that RabbitMQ secrets engine implementations
  must provide, ensuring consistency and type safety across different implementations.

  ## Core Operations

  The RabbitMQ secrets engine supports the following operations:

  ### Configuration Operations
  - `configure_connection/2` - Configure RabbitMQ connection parameters
  - `configure_lease/2` - Configure lease settings for generated credentials

  ### Role Management Operations  
  - `create_role/3` - Create or update a RabbitMQ role
  - `read_role/2` - Read a RabbitMQ role configuration
  - `delete_role/2` - Delete a RabbitMQ role

  ### Credential Operations
  - `generate_credentials/2` - Generate dynamic RabbitMQ credentials

  ## API Compliance

  This behaviour ensures compliance with:
  - [Vault RabbitMQ Secrets Engine API](https://developer.hashicorp.com/vault/api-docs/secret/rabbitmq)
  - [RabbitMQ Management API](https://www.rabbitmq.com/management.html)

  """

  alias Vaultx.Base.Error

  @typedoc """
  RabbitMQ role name.
  Must be a non-empty string with valid characters.
  """
  @type role_name :: String.t()

  @typedoc """
  RabbitMQ connection configuration parameters.
  """
  @type connection_config :: %{
          required(:connection_uri) => String.t(),
          required(:username) => String.t(),
          required(:password) => String.t(),
          optional(:verify_connection) => boolean(),
          optional(:password_policy) => String.t(),
          optional(:username_template) => String.t()
        }

  @typedoc """
  RabbitMQ lease configuration parameters.
  """
  @type lease_config :: %{
          optional(:ttl) => non_neg_integer(),
          optional(:max_ttl) => non_neg_integer()
        }

  @typedoc """
  RabbitMQ role configuration parameters.
  """
  @type role_config :: %{
          optional(:tags) => String.t(),
          optional(:vhosts) => String.t(),
          optional(:vhost_topics) => String.t()
        }

  @typedoc """
  Generated RabbitMQ credentials.
  """
  @type credentials :: %{
          username: String.t(),
          password: String.t()
        }

  @typedoc """
  Options for RabbitMQ secrets engine operations.
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
  Result of a role creation operation.
  """
  @type create_role_result :: :ok | {:error, Error.t()}

  @typedoc """
  Result of a role read operation.
  """
  @type read_role_result :: {:ok, role_config()} | {:error, Error.t()}

  @typedoc """
  Result of a role delete operation.
  """
  @type delete_role_result :: :ok | {:error, Error.t()}

  @typedoc """
  Result of a credential generation operation.
  """
  @type generate_credentials_result :: {:ok, credentials()} | {:error, Error.t()}

  @doc """
  Configure connection information for RabbitMQ.

  Sets up the connection parameters that Vault will use to communicate
  with RabbitMQ and generate credentials.

  ## Parameters

  - `config` - Connection configuration parameters
  - `opts` - Operation options

  ## Returns

  - `:ok` - Successfully configured connection
  - `{:error, error}` - Failed to configure connection

  ## Examples

      config = %{
        connection_uri: "http://localhost:15672",
        username: "admin",
        password: "admin123"
      }
      :ok = MyRabbitMQ.configure_connection(config, [])

  """
  @callback configure_connection(connection_config(), operation_opts()) :: configure_result()

  @doc """
  Configure lease settings for generated credentials.

  Sets the default TTL and maximum TTL for dynamically generated
  RabbitMQ credentials.

  ## Parameters

  - `config` - Lease configuration parameters
  - `opts` - Operation options

  ## Returns

  - `:ok` - Successfully configured lease settings
  - `{:error, error}` - Failed to configure lease settings

  ## Examples

      config = %{
        ttl: 1800,
        max_ttl: 3600
      }
      :ok = MyRabbitMQ.configure_lease(config, [])

  """
  @callback configure_lease(lease_config(), operation_opts()) :: configure_result()

  @doc """
  Create or update a RabbitMQ role.

  Configures a role that can be used to generate RabbitMQ credentials.
  The role defines the permissions, virtual hosts, and tags that will be
  assigned to generated users.

  ## Parameters

  - `name` - Role name
  - `config` - Role configuration parameters
  - `opts` - Operation options

  ## Returns

  - `:ok` - Successfully created/updated role
  - `{:error, error}` - Failed to create/update role

  ## Examples

      config = %{
        tags: "management",
        vhosts: "{\"/\": {\"configure\":\".*\", \"write\":\".*\", \"read\": \".*\"}}"
      }
      :ok = MyRabbitMQ.create_role("web-role", config, [])

  """
  @callback create_role(role_name(), role_config(), operation_opts()) :: create_role_result()

  @doc """
  Read a RabbitMQ role configuration.

  ## Parameters

  - `name` - Role name to read
  - `opts` - Operation options

  ## Returns

  - `{:ok, config}` - Successfully read role configuration
  - `{:error, error}` - Failed to read role

  ## Examples

      {:ok, config} = MyRabbitMQ.read_role("web-role", [])

  """
  @callback read_role(role_name(), operation_opts()) :: read_role_result()

  @doc """
  Delete a RabbitMQ role.

  ## Parameters

  - `name` - Role name to delete
  - `opts` - Operation options

  ## Returns

  - `:ok` - Successfully deleted role
  - `{:error, error}` - Failed to delete role

  ## Examples

      :ok = MyRabbitMQ.delete_role("old-role", [])

  """
  @callback delete_role(role_name(), operation_opts()) :: delete_role_result()

  @doc """
  Generate credentials for a RabbitMQ role.

  Generates dynamic RabbitMQ credentials based on the given role definition.

  ## Parameters

  - `name` - Role name to generate credentials for
  - `opts` - Operation options

  ## Returns

  - `{:ok, credentials}` - Successfully generated credentials
  - `{:error, error}` - Failed to generate credentials

  ## Examples

      {:ok, creds} = MyRabbitMQ.generate_credentials("web-role", [])

  """
  @callback generate_credentials(role_name(), operation_opts()) :: generate_credentials_result()
end
