defmodule Vaultx.Auth.AliCloud do
  @moduledoc """
  Alibaba Cloud (AliCloud) authentication method for HashiCorp Vault.

  This module implements the AliCloud authentication method for Vault, providing
  secure authentication using Alibaba Cloud's Resource Access Management (RAM)
  service with comprehensive support for role-based authentication and identity
  verification through signed STS GetCallerIdentity requests.

  ## Features

  - RAM Role Authentication: Authenticate using Alibaba Cloud RAM roles
  - STS Integration: Uses Alibaba Cloud Security Token Service
  - Request Signing: Validates signed GetCallerIdentity requests
  - Identity Verification: Comprehensive identity and permission validation
  - Cross-Account Support: Works with cross-account role assumptions
  - Enterprise Ready: Production-grade security and reliability

  ## API Compliance

  Fully implements HashiCorp Vault AliCloud authentication:
  - [AliCloud Auth Method](https://developer.hashicorp.com/vault/api-docs/auth/alicloud)
  - [AliCloud Auth Configuration](https://developer.hashicorp.com/vault/docs/auth/alicloud)

  ## Usage Examples

  ### Basic Authentication

      {:ok, auth_response} = Vaultx.Auth.AliCloud.authenticate(%{
        role: "dev-role",
        identity_request_url: "aWRlbnRpdHlfcmVxdWVzdF91cmw=",
        identity_request_headers: "aWRlbnRpdHlfcmVxdWVzdF9oZWFkZXJz"
      })

  ### Authentication with Custom Mount Path

      {:ok, auth_response} = Vaultx.Auth.AliCloud.authenticate(%{
        role: "prod-role",
        identity_request_url: "aWRlbnRpdHlfcmVxdWVzdF91cmw=",
        identity_request_headers: "aWRlbnRpdHlfcmVxdWVzdF9oZWFkZXJz"
      }, mount_path: "custom-alicloud")

  ### Authentication with Additional Options

      {:ok, auth_response} = Vaultx.Auth.AliCloud.authenticate(%{
        role: "my-role",
        identity_request_url: "aWRlbnRpdHlfcmVxdWVzdF91cmw=",
        identity_request_headers: "aWRlbnRpdHlfcmVxdWVzdF9oZWFkZXJz"
      }, [
        mount_path: "alicloud",
        timeout: 30_000,
        retry_attempts: 3
      ])

  ## Vault Configuration

  Before using this authentication method, configure it in Vault:

      # Enable AliCloud auth method
      vault auth enable alicloud

      # Create a role
      vault write auth/alicloud/role/dev-role \\
        arn="acs:ram::5138828231865461:role/dev-role" \\
        policies="dev,default"

      # Create another role with token configuration
      vault write auth/alicloud/role/prod-role \\
        arn="acs:ram::5138828231865461:role/prod-role" \\
        token_policies="prod,default" \\
        token_ttl=1h \\
        token_max_ttl=4h

  ## Authentication Process

  The AliCloud authentication process involves:

  1. Request Preparation: Client prepares a signed STS GetCallerIdentity request
  2. Base64 Encoding: URL and headers are base64 encoded
  3. Vault Submission: Encoded request data is sent to Vault
  4. Signature Verification: Vault verifies the request signature
  5. Identity Validation: Vault validates the caller identity
  6. Token Issuance: Vault issues a token with appropriate policies

  ## Security Considerations

  - Use appropriate RAM policies with minimal required permissions
  - Regularly rotate access keys and credentials
  - Monitor authentication events in Vault audit logs
  - Configure appropriate role bindings and policies
  - Use least privilege principle for policy assignments
  - Consider request replay protection mechanisms
  - Validate identity request signatures properly

  ## Required Permissions

  The authenticating RAM role/user must have the following permissions:
  - `sts:GetCallerIdentity` - To retrieve caller identity information
  - Appropriate permissions for the intended Vault operations

  ## Error Handling

  Common authentication errors include:
  - Invalid or expired credentials
  - Insufficient RAM permissions
  - Malformed request signatures
  - Role not found or not configured
  - Network connectivity issues
  """

  @behaviour Vaultx.Auth.Behaviour

  alias Vaultx.Base.{Error, Logger, Security, Telemetry}
  alias Vaultx.Transport.HTTP

  # Default mount path for AliCloud auth method
  @default_mount_path "alicloud"

  @impl true
  def authenticate(credentials, opts \\ []) do
    with :ok <- validate_credentials(credentials),
         :ok <- Security.audit_log(:authentication, :attempt, %{method: :alicloud}) do
      mount_path = Keyword.get(opts, :mount_path, @default_mount_path)
      path = "auth/#{mount_path}/login"

      request_body = %{
        role: Map.get(credentials, :role),
        identity_request_url: Map.get(credentials, :identity_request_url),
        identity_request_headers: Map.get(credentials, :identity_request_headers)
      }

      metadata = %{
        method: :alicloud,
        mount_path: mount_path,
        role: Map.get(credentials, :role)
      }

      Logger.debug("Attempting AliCloud authentication", metadata)
      Telemetry.auth_start(metadata)

      start_time = System.monotonic_time()

      case HTTP.request(:post, path, request_body, [], opts) do
        {:ok, %{body: %{"auth" => auth_info}}} ->
          duration = System.monotonic_time() - start_time

          auth_response = build_auth_response(auth_info)

          Logger.info(
            "AliCloud authentication successful",
            Map.merge(metadata, %{
              account_id: auth_info["metadata"]["account_id"],
              user_id: auth_info["metadata"]["user_id"],
              arn: auth_info["metadata"]["arn"],
              identity_type: auth_info["metadata"]["identity_type"],
              token_policies: auth_info["policies"],
              lease_duration: auth_info["lease_duration"],
              renewable: auth_info["renewable"],
              entity_id: auth_info["entity_id"]
            })
          )

          Telemetry.auth_success(duration, metadata)
          Security.audit_log(:authentication, :success, metadata)

          {:ok, auth_response}

        {:ok, %{body: response}} ->
          duration = System.monotonic_time() - start_time

          error =
            Error.from_http_response(
              Map.get(response, "status", 400),
              response,
              details: %{auth_method: :alicloud}
            )

          Logger.error("AliCloud authentication failed", Map.put(metadata, :error, error))
          Telemetry.auth_failure(duration, Map.put(metadata, :error, error))
          Security.audit_log(:authentication, :failure, Map.put(metadata, :error, error.type))

          {:error, error}

        {:error, error} ->
          duration = System.monotonic_time() - start_time

          Logger.error("AliCloud authentication error", Map.put(metadata, :error, error))
          Telemetry.auth_failure(duration, Map.put(metadata, :error, error))
          Security.audit_log(:authentication, :failure, Map.put(metadata, :error, error.type))

          {:error, error}
      end
    end
  end

  @impl true
  def validate_credentials(credentials) when is_map(credentials) do
    with :ok <- validate_required_field(credentials, :role, "Role is required"),
         :ok <-
           validate_required_field(
             credentials,
             :identity_request_url,
             "Identity request URL is required"
           ),
         :ok <-
           validate_required_field(
             credentials,
             :identity_request_headers,
             "Identity request headers are required"
           ),
         :ok <-
           validate_base64_field(
             credentials,
             :identity_request_url,
             "Identity request URL must be valid base64"
           ),
         :ok <-
           validate_base64_field(
             credentials,
             :identity_request_headers,
             "Identity request headers must be valid base64"
           ) do
      :ok
    end
  end

  def validate_credentials(_) do
    {:error, Error.new(:invalid_credentials, "Credentials must be a map")}
  end

  @impl true
  def refresh_token(_token, _opts) do
    {:error, Error.new(:not_supported, "AliCloud auth method does not support token refresh")}
  end

  @impl true
  def revoke_token(_token, _opts) do
    {:error, Error.new(:not_supported, "AliCloud auth method does not support token revocation")}
  end

  @impl true
  def metadata do
    %{
      name: "AliCloud Authentication",
      supports_refresh: false,
      supports_revocation: false,
      required_fields: [:role, :identity_request_url, :identity_request_headers],
      optional_fields: [],
      description: "Authenticate using Alibaba Cloud RAM roles and STS GetCallerIdentity requests"
    }
  end

  # Private helper functions

  defp build_auth_response(auth_info) do
    %{
      client_token: auth_info["client_token"],
      accessor: auth_info["accessor"],
      policies: auth_info["policies"] || [],
      lease_duration: auth_info["lease_duration"] || 0,
      renewable: auth_info["renewable"] || false,
      entity_id: auth_info["entity_id"],
      token_type: auth_info["token_type"] || "service",
      metadata: auth_info["metadata"] || %{}
    }
  end

  defp validate_required_field(credentials, field, error_message) do
    case Map.get(credentials, field) do
      nil -> {:error, Error.new(:invalid_credentials, error_message)}
      "" -> {:error, Error.new(:invalid_credentials, error_message)}
      value when is_binary(value) -> :ok
      _value -> {:error, Error.new(:invalid_credentials, error_message)}
    end
  end

  defp validate_base64_field(credentials, field, error_message) do
    # At this point, validate_required_field has already ensured the value is a non-empty binary
    value = Map.get(credentials, field)

    case Base.decode64(value) do
      {:ok, _} -> :ok
      :error -> {:error, Error.new(:invalid_credentials, error_message)}
    end
  end
end
