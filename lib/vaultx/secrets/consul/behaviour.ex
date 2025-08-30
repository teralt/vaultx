defmodule Vaultx.Secrets.Consul.Behaviour do
  @moduledoc """
  Behaviour definition for HashiCorp Vault Consul secrets engine operations.

  This behaviour defines the interface that Consul secrets engine implementations
  must provide, ensuring consistency and type safety across different implementations.

  ## Core Operations

  The Consul secrets engine supports the following operations:

  ### Configuration Operations
  - `configure_access/2` - Configure Consul connection parameters

  ### Role Management Operations  
  - `create_role/3` - Create or update a Consul role
  - `read_role/2` - Read a Consul role configuration
  - `list_roles/1` - List all configured roles
  - `delete_role/2` - Delete a Consul role

  ### Credential Operations
  - `generate_credentials/2` - Generate dynamic Consul ACL tokens

  ## API Compliance

  This behaviour ensures compliance with:
  - [Vault Consul Secrets Engine API](https://developer.hashicorp.com/vault/api-docs/secret/consul)
  - [Consul ACL System](https://developer.hashicorp.com/consul/docs/security/acl)

  """

  alias Vaultx.Base.Error

  @typedoc """
  Consul role name.
  Must be a non-empty string with valid characters.
  """
  @type role_name :: String.t()

  @typedoc """
  Consul access configuration parameters.
  """
  @type access_config :: %{
          required(:address) => String.t(),
          optional(:scheme) => String.t(),
          optional(:token) => String.t(),
          optional(:ca_cert) => String.t(),
          optional(:client_cert) => String.t(),
          optional(:client_key) => String.t()
        }

  @typedoc """
  Consul role configuration parameters.
  """
  @type role_config :: %{
          # Modern Consul (1.4+)
          optional(:consul_policies) => [String.t()],
          optional(:consul_roles) => [String.t()],
          optional(:service_identities) => [String.t()],
          optional(:node_identities) => [String.t()],
          optional(:consul_namespace) => String.t(),
          optional(:partition) => String.t(),
          optional(:ttl) => String.t(),
          optional(:max_ttl) => String.t(),
          optional(:local) => boolean(),
          # Legacy Consul (pre-1.4)
          optional(:token_type) => String.t(),
          optional(:policy) => String.t(),
          optional(:policies) => [String.t()],
          optional(:lease) => String.t()
        }

  @typedoc """
  Generated Consul credentials.
  """
  @type credentials :: %{
          token: String.t()
        }

  @typedoc """
  Options for Consul secrets engine operations.
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
  Result of a role list operation.
  """
  @type list_roles_result :: {:ok, [String.t()]} | {:error, Error.t()}

  @typedoc """
  Result of a role delete operation.
  """
  @type delete_role_result :: :ok | {:error, Error.t()}

  @typedoc """
  Result of a credential generation operation.
  """
  @type generate_credentials_result :: {:ok, credentials()} | {:error, Error.t()}

  @doc """
  Configure access information for Consul.

  Sets up the connection parameters that Vault will use to communicate
  with Consul and generate ACL tokens.

  ## Parameters

  - `config` - Access configuration parameters
  - `opts` - Operation options

  ## Returns

  - `:ok` - Successfully configured access
  - `{:error, error}` - Failed to configure access

  ## Examples

      config = %{
        address: "127.0.0.1:8500",
        scheme: "https",
        token: "management-token"
      }
      :ok = MyConsul.configure_access(config, [])

  """
  @callback configure_access(access_config(), operation_opts()) :: configure_result()

  @doc """
  Create or update a Consul role.

  Configures a role that can be used to generate Consul ACL tokens.
  The role defines the policies, roles, and identities that will be
  attached to generated tokens.

  ## Parameters

  - `name` - Role name
  - `config` - Role configuration parameters
  - `opts` - Operation options

  ## Returns

  - `:ok` - Successfully created/updated role
  - `{:error, error}` - Failed to create/update role

  ## Examples

      config = %{
        consul_policies: ["web-policy", "db-read-policy"],
        ttl: "1h",
        max_ttl: "24h"
      }
      :ok = MyConsul.create_role("web-service", config, [])

  """
  @callback create_role(role_name(), role_config(), operation_opts()) :: create_role_result()

  @doc """
  Read a Consul role configuration.

  ## Parameters

  - `name` - Role name to read
  - `opts` - Operation options

  ## Returns

  - `{:ok, config}` - Successfully read role configuration
  - `{:error, error}` - Failed to read role

  ## Examples

      {:ok, config} = MyConsul.read_role("web-service", [])

  """
  @callback read_role(role_name(), operation_opts()) :: read_role_result()

  @doc """
  List all configured Consul roles.

  ## Parameters

  - `opts` - Operation options

  ## Returns

  - `{:ok, roles}` - Successfully listed roles
  - `{:error, error}` - Failed to list roles

  ## Examples

      {:ok, roles} = MyConsul.list_roles([])

  """
  @callback list_roles(operation_opts()) :: list_roles_result()

  @doc """
  Delete a Consul role.

  ## Parameters

  - `name` - Role name to delete
  - `opts` - Operation options

  ## Returns

  - `:ok` - Successfully deleted role
  - `{:error, error}` - Failed to delete role

  ## Examples

      :ok = MyConsul.delete_role("old-role", [])

  """
  @callback delete_role(role_name(), operation_opts()) :: delete_role_result()

  @doc """
  Generate credentials for a Consul role.

  Generates a dynamic Consul ACL token based on the given role definition.

  ## Parameters

  - `name` - Role name to generate credentials for
  - `opts` - Operation options

  ## Returns

  - `{:ok, credentials}` - Successfully generated credentials
  - `{:error, error}` - Failed to generate credentials

  ## Examples

      {:ok, creds} = MyConsul.generate_credentials("web-service", [])

  """
  @callback generate_credentials(role_name(), operation_opts()) :: generate_credentials_result()
end
