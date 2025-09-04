defmodule Vaultx.Secrets.Nomad.Behaviour do
  @moduledoc """
  Behaviour definition for HashiCorp Vault Nomad secrets engine operations.

  This behaviour defines the interface that Nomad secrets engine implementations
  must provide, ensuring consistency and type safety across different implementations.

  ## Core Operations

  The Nomad secrets engine supports the following operations:

  ### Configuration Operations
  - `configure_access/2` - Configure Nomad connection parameters
  - `read_access_config/1` - Read Nomad access configuration
  - `configure_lease/2` - Configure lease settings for generated tokens
  - `read_lease_config/1` - Read lease configuration
  - `delete_lease_config/1` - Delete lease configuration

  ### Role Management Operations  
  - `create_role/3` - Create or update a Nomad role
  - `read_role/2` - Read a Nomad role configuration
  - `list_roles/1` - List all configured roles
  - `delete_role/2` - Delete a Nomad role

  ### Credential Operations
  - `generate_credentials/2` - Generate dynamic Nomad tokens

  ## API Compliance

  This behaviour ensures compliance with:
  - [Vault Nomad Secrets Engine API](https://developer.hashicorp.com/vault/api-docs/secret/nomad)
  - [Nomad ACL System](https://developer.hashicorp.com/nomad/docs/operations/acl)

  """

  alias Vaultx.Base.Error

  @typedoc """
  Nomad role name.
  Must be a non-empty string with valid characters.
  """
  @type role_name :: String.t()

  @typedoc """
  Nomad access configuration parameters.
  """
  @type access_config :: %{
          required(:address) => String.t(),
          optional(:token) => String.t(),
          optional(:max_token_name_length) => non_neg_integer(),
          optional(:ca_cert) => String.t(),
          optional(:client_cert) => String.t(),
          optional(:client_key) => String.t()
        }

  @typedoc """
  Nomad lease configuration parameters.
  """
  @type lease_config :: %{
          optional(:ttl) => String.t(),
          optional(:max_ttl) => String.t()
        }

  @typedoc """
  Nomad role configuration parameters.
  """
  @type role_config :: %{
          optional(:policies) => String.t(),
          optional(:global) => boolean(),
          optional(:type) => String.t()
        }

  @typedoc """
  Generated Nomad credentials.
  """
  @type credentials :: %{
          accessor_id: String.t(),
          secret_id: String.t()
        }

  @typedoc """
  Options for Nomad secrets engine operations.
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
  Configure access information for Nomad.

  Sets up the connection parameters that Vault will use to communicate
  with Nomad and generate tokens.

  ## Parameters

  - `config` - Access configuration parameters
  - `opts` - Operation options

  ## Returns

  - `:ok` - Successfully configured access
  - `{:error, error}` - Failed to configure access

  ## Examples

      config = %{
        address: "http://127.0.0.1:4646",
        token: "management-token"
      }
      :ok = MyNomad.configure_access(config, [])

  """
  @callback configure_access(access_config(), operation_opts()) :: configure_result()

  @doc """
  Read access configuration for Nomad.

  ## Parameters

  - `opts` - Operation options

  ## Returns

  - `{:ok, config}` - Successfully read access configuration
  - `{:error, error}` - Failed to read access configuration

  ## Examples

      {:ok, config} = MyNomad.read_access_config([])

  """
  @callback read_access_config(operation_opts()) :: read_config_result()

  @doc """
  Configure lease settings for generated tokens.

  ## Parameters

  - `config` - Lease configuration parameters
  - `opts` - Operation options

  ## Returns

  - `:ok` - Successfully configured lease
  - `{:error, error}` - Failed to configure lease

  ## Examples

      config = %{
        ttl: "1h",
        max_ttl: "24h"
      }
      :ok = MyNomad.configure_lease(config, [])

  """
  @callback configure_lease(lease_config(), operation_opts()) :: configure_result()

  @doc """
  Read lease configuration.

  ## Parameters

  - `opts` - Operation options

  ## Returns

  - `{:ok, config}` - Successfully read lease configuration
  - `{:error, error}` - Failed to read lease configuration

  ## Examples

      {:ok, config} = MyNomad.read_lease_config([])

  """
  @callback read_lease_config(operation_opts()) :: read_config_result()

  @doc """
  Delete lease configuration.

  ## Parameters

  - `opts` - Operation options

  ## Returns

  - `:ok` - Successfully deleted lease configuration
  - `{:error, error}` - Failed to delete lease configuration

  ## Examples

      :ok = MyNomad.delete_lease_config([])

  """
  @callback delete_lease_config(operation_opts()) :: configure_result()

  @doc """
  Create or update a Nomad role.

  Configures a role that can be used to generate Nomad tokens.
  The role defines the policies and type of tokens that will be generated.

  ## Parameters

  - `name` - Role name
  - `config` - Role configuration parameters
  - `opts` - Operation options

  ## Returns

  - `:ok` - Successfully created/updated role
  - `{:error, error}` - Failed to create/update role

  ## Examples

      config = %{
        policies: "readonly",
        type: "client"
      }
      :ok = MyNomad.create_role("monitoring", config, [])

  """
  @callback create_role(role_name(), role_config(), operation_opts()) :: create_role_result()

  @doc """
  Read a Nomad role configuration.

  ## Parameters

  - `name` - Role name to read
  - `opts` - Operation options

  ## Returns

  - `{:ok, config}` - Successfully read role configuration
  - `{:error, error}` - Failed to read role

  ## Examples

      {:ok, config} = MyNomad.read_role("monitoring", [])

  """
  @callback read_role(role_name(), operation_opts()) :: read_role_result()

  @doc """
  List all configured Nomad roles.

  ## Parameters

  - `opts` - Operation options

  ## Returns

  - `{:ok, roles}` - Successfully listed roles
  - `{:error, error}` - Failed to list roles

  ## Examples

      {:ok, roles} = MyNomad.list_roles([])

  """
  @callback list_roles(operation_opts()) :: list_roles_result()

  @doc """
  Delete a Nomad role.

  ## Parameters

  - `name` - Role name to delete
  - `opts` - Operation options

  ## Returns

  - `:ok` - Successfully deleted role
  - `{:error, error}` - Failed to delete role

  ## Examples

      :ok = MyNomad.delete_role("old-role", [])

  """
  @callback delete_role(role_name(), operation_opts()) :: delete_role_result()

  @doc """
  Generate credentials for a Nomad role.

  Generates a dynamic Nomad token based on the given role definition.

  ## Parameters

  - `name` - Role name to generate credentials for
  - `opts` - Operation options

  ## Returns

  - `{:ok, credentials}` - Successfully generated credentials
  - `{:error, error}` - Failed to generate credentials

  ## Examples

      {:ok, creds} = MyNomad.generate_credentials("monitoring", [])

  """
  @callback generate_credentials(role_name(), operation_opts()) :: generate_credentials_result()
end
