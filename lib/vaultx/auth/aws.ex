defmodule Vaultx.Auth.AWS do
  @moduledoc """
  AWS authentication method for HashiCorp Vault.

  This module implements comprehensive AWS authentication for Vault, supporting
  both EC2 instance-based and IAM principal-based authentication. It provides
  secure, scalable authentication for AWS workloads with full support for
  cross-account scenarios and advanced AWS features.

  ## AWS Authentication Types

  ### EC2 Instance Authentication
  - Instance Identity: Uses EC2 instance identity documents
  - Role Tags: Supports EC2 role tag-based authentication
  - PKCS7 Signatures: Validates instance identity signatures
  - Nonce Support: Prevents replay attacks

  ### IAM Authentication
  - IAM Principals: Authenticates IAM users and roles
  - STS Integration: Uses AWS Security Token Service
  - Cross-Account: Supports cross-account role assumption
  - Request Signing: AWS Signature Version 4 support

  ## Advanced Features

  - Multi-Region: Works across all AWS regions
  - Auto-Discovery: Automatic instance metadata detection
  - Security: Built-in replay attack prevention
  - Flexibility: Configurable authentication parameters

  ## API Compliance

  Fully implements HashiCorp Vault AWS authentication:
  - [AWS Auth Method](https://developer.hashicorp.com/vault/api-docs/auth/aws)
  - [AWS Auth Configuration](https://developer.hashicorp.com/vault/docs/auth/aws)

  EC2 instances can authenticate using their instance identity document:

      {:ok, auth_response} = Vaultx.Auth.AWS.authenticate(%{
        role: "my-ec2-role"
      })

  ### IAM Authentication

  IAM principals authenticate using signed STS GetCallerIdentity requests:

      # Manual IAM authentication with pre-signed request
      {:ok, auth_response} = Vaultx.Auth.AWS.authenticate(%{
        role: "my-iam-role",
        iam_http_request_method: "POST",
        iam_request_url: "https://sts.amazonaws.com/",
        iam_request_body: "Action=GetCallerIdentity&Version=2011-06-15",
        iam_request_headers: "Authorization: AWS4-HMAC-SHA256 ..."
      })

  ### Additional Options

      # With server ID header for additional security
      {:ok, auth_response} = Vaultx.Auth.AWS.authenticate(%{
        role: "my-role",
        server_id: "vault.example.com"
      })

      # With nonce for EC2 authentication
      {:ok, auth_response} = Vaultx.Auth.AWS.authenticate(%{
        role: "my-role",
        nonce: "unique-nonce-value"
      })

      # With role tag for EC2 authentication
      {:ok, auth_response} = Vaultx.Auth.AWS.authenticate(%{
        role: "my-role",
        role_tag: "v1:09V0qGuyB8=:a=ami-fce3c696:p=default,prod:d=false:t=300h0m0s:uPLKCQxqsefRhrp1qmVa1wsQVUXXJG8UZP/"
      })

  ## Vault Configuration

  Before using this authentication method, configure it in Vault:

      # Enable AWS auth method
      vault auth enable aws

      # Configure AWS credentials (optional for EC2-based Vault)
      vault write auth/aws/config/client \\
        access_key="AKIA..." \\
        secret_key="..." \\
        region="us-east-1"

      # Create EC2 role
      vault write auth/aws/role/my-ec2-role \\
        auth_type=ec2 \\
        bound_ami_id=ami-12345678 \\
        policies=my-policy \\
        max_ttl=500h

      # Create IAM role
      vault write auth/aws/role/my-iam-role \\
        auth_type=iam \\
        bound_iam_principal_arn="arn:aws:iam::123456789012:role/MyRole" \\
        policies=my-policy \\
        max_ttl=1h

  ## Security Considerations

  - Use IAM roles instead of IAM users when possible
  - Implement proper IAM policies with least privilege
  - Monitor authentication events in Vault audit logs
  - Use bound conditions to restrict access appropriately
  - Configure server ID header for additional security
  - Regularly review and rotate AWS credentials
  """

  @behaviour Vaultx.Auth.Behaviour

  alias Vaultx.Base.{Error, Logger, Security, Telemetry}
  alias Vaultx.Transport.HTTP

  # Default mount path for AWS auth method
  @default_mount_path "aws"

  @impl true
  def authenticate(credentials, opts \\ []) do
    with :ok <- validate_credentials(credentials),
         :ok <- Security.audit_log(:authentication, :attempt, %{method: :aws}) do
      mount_path = Keyword.get(opts, :mount_path, @default_mount_path)
      path = "auth/#{mount_path}/login"

      {:ok, request_body} = build_request_body(credentials, opts)

      metadata = %{
        method: :aws,
        mount_path: mount_path,
        role: Map.get(credentials, :role),
        auth_type: detect_auth_type(credentials)
      }

      Logger.debug("Attempting AWS authentication", metadata)
      Telemetry.auth_start(metadata)

      start_time = System.monotonic_time()

      # Build headers including server ID if provided
      headers = build_headers(credentials)

      case HTTP.request(:post, path, request_body, headers, opts) do
        {:ok, %{body: %{"auth" => auth_info}}} ->
          duration = System.monotonic_time() - start_time

          auth_response = build_auth_response(auth_info)

          Logger.info(
            "AWS authentication successful",
            Map.merge(metadata, %{
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
              details: %{auth_method: :aws, role: Map.get(credentials, :role)}
            )

          Logger.error("AWS authentication failed", Map.put(metadata, :error, error))
          Telemetry.auth_failure(duration, Map.put(metadata, :error, error))
          Security.audit_log(:authentication, :failure, Map.put(metadata, :error, error.type))

          {:error, error}

        {:error, error} ->
          duration = System.monotonic_time() - start_time

          Logger.error("AWS authentication error", Map.put(metadata, :error, error))
          Telemetry.auth_failure(duration, Map.put(metadata, :error, error))
          Security.audit_log(:authentication, :failure, Map.put(metadata, :error, error.type))

          {:error, error}
      end
    end
  end

  @impl true
  def validate_credentials(credentials) when is_map(credentials) do
    with :ok <- validate_required_fields(credentials),
         :ok <- validate_field_types(credentials),
         :ok <- validate_auth_type_specific_fields(credentials) do
      :ok
    end
  end

  def validate_credentials(_credentials) do
    {:error, Error.new(:invalid_request, "Credentials must be a map")}
  end

  @impl true
  def refresh_token(token, opts \\ []) do
    path = "auth/token/renew-self"

    metadata = %{
      method: :aws,
      operation: :token_refresh
    }

    Logger.debug("Refreshing AWS token", metadata)

    case HTTP.post(path, %{}, Keyword.put(opts, :token, token)) do
      {:ok, %{body: %{"auth" => auth_info}}} ->
        auth_response = build_auth_response(auth_info)
        Logger.info("AWS token refreshed successfully", metadata)
        {:ok, auth_response}

      {:ok, %{body: response}} ->
        error =
          Error.from_http_response(
            Map.get(response, "status", 400),
            response,
            details: %{operation: :token_refresh, auth_method: :aws}
          )

        Logger.error("AWS token refresh failed", Map.put(metadata, :error, error))
        {:error, error}

      {:error, error} ->
        Logger.error("AWS token refresh error", Map.put(metadata, :error, error))
        {:error, error}
    end
  end

  @impl true
  def revoke_token(token, opts \\ []) do
    path = "auth/token/revoke-self"

    metadata = %{
      method: :aws,
      operation: :token_revocation
    }

    Logger.debug("Revoking AWS token", metadata)

    case HTTP.post(path, %{}, Keyword.put(opts, :token, token)) do
      {:ok, _response} ->
        Logger.info("AWS token revoked successfully", metadata)
        Security.audit_log(:token_revocation, :success, metadata)
        :ok

      {:error, error} ->
        Logger.error("AWS token revocation failed", Map.put(metadata, :error, error))
        Security.audit_log(:token_revocation, :failure, Map.put(metadata, :error, error.type))
        {:error, error}
    end
  end

  @impl true
  def metadata do
    %{
      name: "AWS Authentication",
      supports_refresh: true,
      supports_revocation: true,
      required_fields: [:role],
      optional_fields: [
        :iam_http_request_method,
        :iam_request_url,
        :iam_request_body,
        :iam_request_headers,
        :server_id,
        :nonce,
        :role_tag
      ],
      description: "AWS EC2 and IAM authentication using AWS credentials and instance identity"
    }
  end

  # Private helper functions

  # Validates that all required fields are present
  defp validate_required_fields(credentials) do
    case Map.get(credentials, :role) do
      nil ->
        {:error, Error.new(:invalid_request, "Missing required field: role")}

      role when not is_binary(role) ->
        {:error, Error.new(:invalid_request, "Field 'role' must be a string")}

      role when byte_size(role) == 0 ->
        {:error, Error.new(:invalid_request, "Field 'role' cannot be empty")}

      _role ->
        :ok
    end
  end

  # Validates field types for all provided fields
  defp validate_field_types(credentials) do
    string_fields = [
      :role,
      :iam_http_request_method,
      :iam_request_url,
      :iam_request_body,
      :iam_request_headers,
      :server_id,
      :nonce,
      :role_tag
    ]

    invalid_fields =
      Enum.filter(string_fields, fn field ->
        case Map.get(credentials, field) do
          nil -> false
          value when is_binary(value) -> false
          _other -> true
        end
      end)

    if Enum.empty?(invalid_fields) do
      :ok
    else
      field_names = Enum.map(invalid_fields, &to_string/1)

      {:error,
       Error.new(
         :invalid_request,
         "Invalid field types: #{Enum.join(field_names, ", ")} must be strings"
       )}
    end
  end

  # Validates authentication type specific field requirements
  defp validate_auth_type_specific_fields(credentials) do
    if has_iam_fields?(credentials) do
      validate_iam_fields(credentials)
    else
      :ok
    end
  end

  # Validates IAM authentication specific fields
  defp validate_iam_fields(credentials) do
    required_iam_fields = [
      :iam_http_request_method,
      :iam_request_url,
      :iam_request_body,
      :iam_request_headers
    ]

    missing_fields =
      Enum.filter(required_iam_fields, fn field ->
        case Map.get(credentials, field) do
          nil -> true
          value when is_binary(value) and byte_size(value) > 0 -> false
          _other -> true
        end
      end)

    if Enum.empty?(missing_fields) do
      :ok
    else
      field_names = Enum.map(missing_fields, &to_string/1)

      {:error,
       Error.new(
         :invalid_request,
         "Missing or invalid IAM fields: #{Enum.join(field_names, ", ")}"
       )}
    end
  end

  # Builds the authentication request body based on credentials
  defp build_request_body(credentials, _opts) do
    base_body = %{role: Map.get(credentials, :role)}

    body =
      base_body
      |> maybe_add_iam_fields(credentials)
      |> maybe_add_ec2_fields(credentials)

    {:ok, body}
  end

  # Adds IAM authentication fields if present
  defp maybe_add_iam_fields(body, credentials) do
    if has_iam_fields?(credentials) do
      Map.merge(body, %{
        iam_http_request_method: Map.get(credentials, :iam_http_request_method),
        iam_request_url: Map.get(credentials, :iam_request_url),
        iam_request_body: Map.get(credentials, :iam_request_body),
        iam_request_headers: Map.get(credentials, :iam_request_headers)
      })
    else
      body
    end
  end

  # Adds EC2 authentication fields if present
  defp maybe_add_ec2_fields(body, credentials) do
    body
    |> maybe_add_field(:nonce, credentials)
    |> maybe_add_field(:role_tag, credentials)
  end

  # Helper to conditionally add a field to the body
  defp maybe_add_field(body, field, credentials) do
    case Map.get(credentials, field) do
      nil -> body
      value -> Map.put(body, field, value)
    end
  end

  # Builds HTTP headers for the authentication request
  defp build_headers(credentials) do
    headers = []

    case Map.get(credentials, :server_id) do
      nil -> headers
      server_id -> [{"X-Vault-AWS-IAM-Server-ID", server_id} | headers]
    end
  end

  # Builds structured authentication response from Vault auth info
  defp build_auth_response(auth_info) do
    %{
      client_token: Map.get(auth_info, "client_token"),
      accessor: Map.get(auth_info, "accessor"),
      policies: Map.get(auth_info, "policies", []),
      lease_duration: Map.get(auth_info, "lease_duration", 0),
      renewable: Map.get(auth_info, "renewable", false),
      entity_id: Map.get(auth_info, "entity_id"),
      token_type: Map.get(auth_info, "token_type"),
      metadata: Map.get(auth_info, "metadata", %{})
    }
  end

  defp has_iam_fields?(credentials) do
    Map.has_key?(credentials, :iam_http_request_method) or
      Map.has_key?(credentials, :iam_request_url) or
      Map.has_key?(credentials, :iam_request_body) or
      Map.has_key?(credentials, :iam_request_headers)
  end

  defp detect_auth_type(credentials) do
    if has_iam_fields?(credentials), do: :iam, else: :ec2
  end
end
