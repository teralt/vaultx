defmodule Vaultx.Auth.Behaviour do
  @moduledoc """
  Comprehensive behaviour for HashiCorp Vault authentication methods.

  This behaviour defines the unified interface that all Vault authentication
  methods must implement, providing consistency across different authentication
  mechanisms while allowing each method to handle its specific requirements
  and capabilities.

  ## Supported Authentication Methods

  This behaviour supports all Vault authentication methods:
  - AppRole: Machine-to-machine authentication
  - AWS: EC2 and IAM-based authentication
  - JWT/OIDC: JSON Web Token authentication
  - LDAP: Directory service authentication
  - UserPass: Username/password authentication
  - Token: Direct token authentication

  ## Core Operations

  ### Primary Operations
  - `authenticate/2` - Perform authentication and obtain tokens
  - `validate_credentials/1` - Validate credential format and requirements

  ### Token Management (Optional)
  - `refresh_token/2` - Refresh existing tokens (if supported)
  - `revoke_token/2` - Revoke tokens (if supported)
  - `metadata/0` - Return authentication method capabilities

  ## Authentication Response Structure

  Successful authentication returns comprehensive token information:
  - `client_token` - Vault token for API requests
  - `accessor` - Token accessor for management operations
  - `policies` - Attached policy list
  - `lease_duration` - Token TTL in seconds
  - `renewable` - Token renewal capability
  - `entity_id` - Identity entity identifier
  - `token_type` - Token type (service, batch, recovery)
  - `metadata` - Method-specific authentication metadata

  ## API Compliance

  This behaviour ensures compliance with HashiCorp Vault authentication APIs:
  - [Vault Auth Methods](https://developer.hashicorp.com/vault/docs/auth)
  - [Token API](https://developer.hashicorp.com/vault/api-docs/auth/token)

  ## Examples

      defmodule MyApp.CustomAuth do
        @behaviour Vaultx.Auth.Behaviour

        @impl true
        def authenticate(credentials, opts) do
          # Custom authentication logic
          {:ok, %{
            client_token: "hvs.token123",
            accessor: "hmac-sha256:accessor123",
            policies: ["default", "myapp"],
            lease_duration: 3600,
            renewable: true,
            entity_id: "entity-123",
            token_type: "service",
            metadata: %{auth_method: "custom"}
          }}
        end

        @impl true
        def validate_credentials(credentials) do
          # Validate credentials format
          :ok
        end

        @impl true
        def refresh_token(token, opts) do
          # Refresh token if supported
          {:error, :not_supported}
        end

        @impl true
        def revoke_token(token, opts) do
          # Revoke token if supported
          {:error, :not_supported}
        end

        @impl true
        def metadata do
          %{
            name: "Custom Authentication",
            supports_refresh: false,
            supports_revocation: true,
            required_fields: [:username, :password],
            optional_fields: [:domain]
          }
        end
      end
  """

  alias Vaultx.Base.Error

  @type credentials :: map()
  @type token :: String.t()
  @type options :: keyword()

  @type auth_response :: %{
          client_token: String.t(),
          accessor: String.t() | nil,
          policies: [String.t()],
          lease_duration: non_neg_integer(),
          renewable: boolean(),
          entity_id: String.t() | nil,
          token_type: String.t() | nil,
          metadata: map()
        }

  @type auth_result :: {:ok, auth_response()} | {:error, Error.t()}
  @type validation_result :: :ok | {:error, Error.t()}
  @type refresh_result :: {:ok, auth_response()} | {:error, Error.t()}
  @type revoke_result :: :ok | {:error, Error.t()}
  @type method_metadata :: %{
          name: String.t(),
          supports_refresh: boolean(),
          supports_revocation: boolean(),
          required_fields: [atom()],
          optional_fields: [atom()],
          description: String.t() | nil
        }

  @doc """
  Authenticates with Vault using the provided credentials.

  This is the main authentication function that each method must implement.
  It should validate the credentials, make the appropriate API call to Vault,
  and return either a structured authentication response or an error.

  ## Parameters

    * `credentials` - A map containing the authentication credentials
    * `opts` - Additional options for the authentication request

  ## Returns

    * `{:ok, auth_response}` - Authentication successful with structured response
    * `{:error, %Vaultx.Base.Error{}}` - Authentication failed with detailed error

  ## Examples

      iex> MyAuth.authenticate(%{username: "user", password: "pass"}, [])
      {:ok, %{
        client_token: "hvs.CAESIJ1234567890",
        accessor: "hmac-sha256:accessor123",
        policies: ["default", "myapp"],
        lease_duration: 3600,
        renewable: true,
        entity_id: "entity-123",
        token_type: "service",
        metadata: %{auth_method: "userpass"}
      }}

      iex> MyAuth.authenticate(%{username: "user", password: "wrong"}, [])
      {:error, %Vaultx.Base.Error{type: :authentication_failed}}
  """
  @callback authenticate(credentials(), options()) :: auth_result()

  @doc """
  Validates the format and completeness of authentication credentials.

  This function should check that all required fields are present and
  properly formatted before attempting authentication. It should not
  make any network calls.

  ## Parameters

    * `credentials` - A map containing the authentication credentials

  ## Returns

    * `:ok` - Credentials are valid
    * `{:error, %Vaultx.Base.Error{}}` - Credentials are invalid with details

  ## Examples

      iex> MyAuth.validate_credentials(%{username: "user", password: "pass"})
      :ok

      iex> MyAuth.validate_credentials(%{username: "user"})
      {:error, %Vaultx.Base.Error{type: :invalid_request, message: "Missing password"}}
  """
  @callback validate_credentials(credentials()) :: validation_result()

  @doc """
  Refreshes an existing authentication token.

  Not all authentication methods support token refresh. Methods that don't
  support refresh should return `{:error, :not_supported}`.

  ## Parameters

    * `token` - The current authentication token
    * `opts` - Additional options for the refresh request

  ## Returns

    * `{:ok, auth_response}` - Token refreshed successfully with new auth data
    * `{:error, :not_supported}` - Method doesn't support token refresh
    * `{:error, %Vaultx.Base.Error{}}` - Refresh failed with detailed error

  ## Examples

      iex> MyAuth.refresh_token("hvs.old_token", [])
      {:ok, %{
        client_token: "hvs.new_token",
        accessor: "hmac-sha256:new_accessor",
        policies: ["default", "myapp"],
        lease_duration: 3600,
        renewable: true,
        entity_id: "entity-123",
        token_type: "service",
        metadata: %{renewed: true}
      }}

      iex> MyAuth.refresh_token("hvs.old_token", [])
      {:error, :not_supported}
  """
  @callback refresh_token(token(), options()) :: refresh_result()

  @doc """
  Revokes an authentication token.

  This function should revoke the provided token, making it invalid for
  future use. Not all authentication methods may support token revocation.

  ## Parameters

    * `token` - The authentication token to revoke
    * `opts` - Additional options for the revocation request

  ## Returns

    * `:ok` - Token revoked successfully
    * `{:error, :not_supported}` - Method doesn't support token revocation
    * `{:error, %Vaultx.Base.Error{}}` - Revocation failed with detailed error

  ## Examples

      iex> MyAuth.revoke_token("hvs.token123", [])
      :ok

      iex> MyAuth.revoke_token("hvs.token123", [])
      {:error, :not_supported}
  """
  @callback revoke_token(token(), options()) :: revoke_result()

  @doc """
  Returns metadata about the authentication method.

  This function provides information about the authentication method's
  capabilities and requirements.

  ## Returns

  A map containing:
    * `:name` - Human-readable name of the authentication method
    * `:supports_refresh` - Whether the method supports token refresh
    * `:supports_revocation` - Whether the method supports token revocation
    * `:required_fields` - List of required credential fields
    * `:optional_fields` - List of optional credential fields
    * `:description` - Optional description of the authentication method

  ## Examples

      iex> MyAuth.metadata()
      %{
        name: "Custom Authentication",
        supports_refresh: false,
        supports_revocation: true,
        required_fields: [:username, :password],
        optional_fields: [:domain],
        description: "Custom username/password authentication"
      }
  """
  @callback metadata() :: method_metadata()

  @optional_callbacks [refresh_token: 2, revoke_token: 2]
end
