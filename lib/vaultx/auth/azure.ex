defmodule Vaultx.Auth.Azure do
  @moduledoc """
  Azure authentication method for HashiCorp Vault.

  This module implements comprehensive Azure authentication for Vault, supporting
  Azure Managed Service Identity (MSI) and Service Principal authentication.
  It provides secure, scalable authentication for Azure workloads with full
  support for Azure Virtual Machines, Virtual Machine Scale Sets, and other
  Azure resources.

  ## Azure Authentication Types

  ### Managed Service Identity (MSI)
  - Virtual Machine Authentication: Uses Azure VM instance metadata
  - Virtual Machine Scale Set: Supports VMSS-based authentication
  - Resource Identity: Authenticates using Azure resource identity
  - JWT Token Validation: Validates Azure-issued JWT tokens

  ### Service Principal Authentication
  - Client Credentials: Uses client ID and secret
  - Certificate Authentication: X.509 certificate-based auth
  - Federated Identity: Azure AD federated identity support

  ## Advanced Features

  - Multi-Tenant: Works across Azure tenants
  - Auto-Discovery: Automatic Azure metadata detection
  - Security: Built-in token validation and replay prevention
  - Flexibility: Configurable authentication parameters
  - Enterprise: Azure Government and sovereign cloud support

  ## API Compliance

  Fully implements HashiCorp Vault Azure authentication:
  - [Azure Auth Method](https://developer.hashicorp.com/vault/api-docs/auth/azure)
  - [Azure Auth Configuration](https://developer.hashicorp.com/vault/docs/auth/azure)

  ## Authentication Examples

  ### Virtual Machine Authentication

  Azure VMs can authenticate using their managed identity:

      {:ok, auth_response} = Vaultx.Auth.Azure.authenticate(%{
        role: "my-vm-role",
        jwt: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
        subscription_id: "12345678-1234-1234-1234-123456789012",
        resource_group_name: "my-resource-group",
        vm_name: "my-vm"
      })

  ### Virtual Machine Scale Set Authentication

      {:ok, auth_response} = Vaultx.Auth.Azure.authenticate(%{
        role: "my-vmss-role",
        jwt: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
        subscription_id: "12345678-1234-1234-1234-123456789012",
        resource_group_name: "my-resource-group",
        vmss_name: "my-vmss"
      })

  ### Resource ID Authentication

      {:ok, auth_response} = Vaultx.Auth.Azure.authenticate(%{
        role: "my-resource-role",
        jwt: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
        subscription_id: "12345678-1234-1234-1234-123456789012",
        resource_group_name: "my-resource-group",
        resource_id: "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/my-rg/providers/Microsoft.Compute/virtualMachines/my-vm"
      })

  ## Vault Configuration

  Before using this authentication method, configure it in Vault:

      # Enable Azure auth method
      vault auth enable azure

      # Configure Azure credentials
      vault write auth/azure/config \\
        tenant_id="12345678-1234-1234-1234-123456789012" \\
        resource="https://management.azure.com/" \\
        client_id="87654321-4321-4321-4321-210987654321" \\
        client_secret="your-client-secret"

      # Create VM role
      vault write auth/azure/role/my-vm-role \\
        bound_service_principal_ids="12345678-1234-1234-1234-123456789012" \\
        bound_resource_groups="my-resource-group" \\
        token_policies="my-policy" \\
        token_ttl="1h" \\
        token_max_ttl="24h"

      # Create VMSS role
      vault write auth/azure/role/my-vmss-role \\
        bound_scale_sets="my-vmss" \\
        bound_resource_groups="my-resource-group" \\
        token_policies="my-policy"

  ## Security Considerations

  - JWT tokens are validated against Azure's public keys
  - Resource metadata is verified against Azure APIs
  - Role bindings enforce resource-level access control
  - Supports Azure Government and sovereign clouds
  - Built-in protection against token replay attacks

  """

  alias Vaultx.Auth.Behaviour
  alias Vaultx.Base.{Error, Logger, Telemetry}
  alias Vaultx.Transport.HTTP

  @behaviour Behaviour

  @default_mount_path "azure"

  @doc """
  Authenticate with Azure using managed identity or service principal.

  This function performs Azure authentication by submitting a JWT token
  obtained from Azure Instance Metadata Service (IMDS) along with
  resource metadata to verify the identity.

  ## Parameters

  - `credentials` - Azure authentication credentials
  - `opts` - Authentication options

  ## Credential Parameters

  ### Required Parameters
  - `role` - Name of the Vault role to authenticate against
  - `jwt` - JWT token from Azure IMDS or service principal

  ### Resource Identification (choose one set)
  - `subscription_id` + `resource_group_name` + `vm_name` - For VM authentication
  - `subscription_id` + `resource_group_name` + `vmss_name` - For VMSS authentication
  - `resource_id` - Full Azure resource ID

  ## Examples

      # VM authentication
      credentials = %{
        role: "my-vm-role",
        jwt: "eyJhbGciOiJSUzI1NiIs...",
        subscription_id: "12345678-1234-1234-1234-123456789012",
        resource_group_name: "my-rg",
        vm_name: "my-vm"
      }
      {:ok, auth} = Azure.authenticate(credentials)

      # VMSS authentication
      credentials = %{
        role: "my-vmss-role",
        jwt: "eyJhbGciOiJSUzI1NiIs...",
        subscription_id: "12345678-1234-1234-1234-123456789012",
        resource_group_name: "my-rg",
        vmss_name: "my-vmss"
      }
      {:ok, auth} = Azure.authenticate(credentials)

  ## Returns

  - `{:ok, auth_response}` - Successful authentication with token details
  - `{:error, error}` - Authentication failure

  """
  @impl Behaviour
  def authenticate(credentials, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    telemetry_metadata = %{
      operation: :authenticate,
      auth_method: :azure,
      mount_path: mount_path,
      role: Map.get(credentials, :role)
    }

    start_time = System.monotonic_time()

    Telemetry.operation_start(telemetry_metadata)

    Logger.info("Starting Azure authentication", %{
      role: Map.get(credentials, :role),
      mount_path: mount_path,
      vm_name: Map.get(credentials, :vm_name),
      vmss_name: Map.get(credentials, :vmss_name),
      resource_id: Map.get(credentials, :resource_id)
    })

    case validate_credentials(credentials) do
      :ok ->
        perform_authentication(credentials, mount_path, opts, telemetry_metadata, start_time)

      {:error, error} ->
        Logger.error("Azure credential validation failed", %{
          error: error,
          role: Map.get(credentials, :role)
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}
    end
  end

  @doc """
  Validate Azure authentication credentials.

  Ensures all required parameters are present and properly formatted
  for Azure authentication.

  ## Parameters

  - `credentials` - Azure authentication credentials to validate

  ## Returns

  - `:ok` - Credentials are valid
  - `{:error, error}` - Validation failed with details

  """
  @impl Behaviour
  def validate_credentials(credentials) when is_map(credentials) do
    with :ok <- validate_required_fields(credentials),
         :ok <- validate_resource_identification(credentials),
         :ok <- validate_jwt_format(credentials) do
      :ok
    end
  end

  def validate_credentials(_),
    do: {:error, Error.new(:invalid_credentials, "Credentials must be a map")}

  @doc """
  Return metadata about the Azure authentication method.

  Provides information about the capabilities and features
  supported by this authentication method.

  ## Returns

  A map containing authentication method metadata including:
  - `type` - Authentication method type
  - `description` - Human-readable description
  - `supports_refresh` - Whether token refresh is supported
  - `supports_revocation` - Whether token revocation is supported

  """
  @impl Behaviour
  def metadata do
    %{
      name: "azure",
      description: "Azure Managed Service Identity and Service Principal authentication",
      required_fields: [:role, :jwt],
      optional_fields: [
        :subscription_id,
        :resource_group_name,
        :vm_name,
        :vmss_name,
        :resource_id
      ],
      supports_refresh: false,
      supports_revocation: false
    }
  end

  # Private Functions

  defp perform_authentication(credentials, mount_path, opts, telemetry_metadata, start_time) do
    path = "/#{mount_path}/login"

    case HTTP.post(path, credentials, opts) do
      {:ok, %{status: 200, body: %{"auth" => auth_data}}} ->
        auth_response = %{
          client_token: Map.get(auth_data, "client_token"),
          accessor: Map.get(auth_data, "accessor"),
          policies: Map.get(auth_data, "policies", []),
          token_policies: Map.get(auth_data, "token_policies", []),
          lease_duration: Map.get(auth_data, "lease_duration"),
          renewable: Map.get(auth_data, "renewable", false),
          entity_id: Map.get(auth_data, "entity_id"),
          token_type: Map.get(auth_data, "token_type"),
          metadata: Map.get(auth_data, "metadata", %{})
        }

        Logger.info("Azure authentication successful", %{
          role: Map.get(credentials, :role),
          entity_id: auth_response.entity_id,
          token_type: auth_response.token_type,
          lease_duration: auth_response.lease_duration
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_success(duration, telemetry_metadata)
        {:ok, auth_response}

      {:ok, response} ->
        error = Error.from_http_response(response.status, response.body)

        Logger.error("Azure authentication failed", %{
          role: Map.get(credentials, :role),
          status: response.status,
          error: error
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}

      {:error, reason} ->
        error = Error.new(:http_error, "HTTP request failed", details: %{reason: reason})

        Logger.error("Azure authentication HTTP error", %{
          role: Map.get(credentials, :role),
          error: error
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}
    end
  end

  defp validate_required_fields(credentials) do
    required_fields = [:role, :jwt]

    missing_fields =
      required_fields
      |> Enum.reject(&Map.has_key?(credentials, &1))

    case missing_fields do
      [] ->
        :ok

      fields ->
        {:error, Error.new(:invalid_credentials, "Missing required fields: #{inspect(fields)}")}
    end
  end

  defp validate_resource_identification(credentials) do
    has_vm_info =
      Map.has_key?(credentials, :vm_name) &&
        Map.has_key?(credentials, :subscription_id) &&
        Map.has_key?(credentials, :resource_group_name)

    has_vmss_info =
      Map.has_key?(credentials, :vmss_name) &&
        Map.has_key?(credentials, :subscription_id) &&
        Map.has_key?(credentials, :resource_group_name)

    has_resource_id = Map.has_key?(credentials, :resource_id)

    cond do
      has_vm_info or has_vmss_info or has_resource_id ->
        :ok

      true ->
        {:error,
         Error.new(
           :invalid_credentials,
           "Must provide either (subscription_id + resource_group_name + vm_name/vmss_name) or resource_id"
         )}
    end
  end

  defp validate_jwt_format(credentials) do
    jwt = Map.get(credentials, :jwt)

    if is_binary(jwt) && String.contains?(jwt, ".") do
      :ok
    else
      {:error, Error.new(:invalid_credentials, "JWT must be a valid JWT token string")}
    end
  end
end
