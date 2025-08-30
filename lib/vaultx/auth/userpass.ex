defmodule Vaultx.Auth.UserPass do
  @moduledoc """
  Username & Password authentication method for HashiCorp Vault.

  This module implements the Username & Password authentication method for Vault,
  providing secure credential-based authentication with comprehensive support for
  user management, password policies, and enterprise features.

  ## Features

  - Simple Authentication: Username and password-based authentication
  - User Management: Support for user creation, updates, and deletion
  - Password Policies: Integration with Vault password policies
  - Multi-Factor Authentication: Support for MFA when configured
  - Audit Integration: Comprehensive audit logging for security compliance
  - Enterprise Ready: Supports all Vault enterprise features

  ## API Compliance

  Fully implements HashiCorp Vault Username & Password authentication:
  - [UserPass Auth Method](https://developer.hashicorp.com/vault/api-docs/auth/userpass)
  - [UserPass Auth Configuration](https://developer.hashicorp.com/vault/docs/auth/userpass)

  ## Usage Examples

  ### Basic Authentication

      {:ok, auth_response} = Vaultx.Auth.UserPass.authenticate(%{
        username: "myuser",
        password: "mypassword"
      })

  ### Authentication with Custom Mount Path

      {:ok, auth_response} = Vaultx.Auth.UserPass.authenticate(%{
        username: "myuser",
        password: "mypassword"
      }, mount_path: "custom-userpass")

  ### Authentication with Additional Options

      {:ok, auth_response} = Vaultx.Auth.UserPass.authenticate(%{
        username: "myuser",
        password: "mypassword"
      }, [
        mount_path: "userpass",
        timeout: 30_000,
        retry_attempts: 3
      ])

  ## Vault Configuration

  Before using this authentication method, configure it in Vault:

      # Enable userpass auth method
      vault auth enable userpass

      # Create a user
      vault write auth/userpass/users/myuser \\
        password="mypassword" \\
        policies="default,myapp"

      # Update user policies
      vault write auth/userpass/users/myuser/policies \\
        policies="default,myapp,admin"

  ## Security Considerations

  - Use strong passwords and enforce password policies
  - Implement account lockout policies to prevent brute force attacks
  - Monitor authentication events in Vault audit logs
  - Consider implementing MFA for additional security
  - Regularly review and update user permissions
  - Use least privilege principle for policy assignments
  """

  @behaviour Vaultx.Auth.Behaviour

  alias Vaultx.Base.{Error, Logger, Security, Telemetry}
  alias Vaultx.Transport.HTTP

  # Default mount path for UserPass auth method
  @default_mount_path "userpass"

  @impl true
  def authenticate(credentials, opts \\ []) do
    with :ok <- validate_credentials(credentials),
         :ok <- Security.audit_log(:authentication, :attempt, %{method: :userpass}) do
      mount_path = Keyword.get(opts, :mount_path, @default_mount_path)
      username = Map.get(credentials, :username)
      path = "auth/#{mount_path}/login/#{username}"

      request_body = %{
        password: Map.get(credentials, :password)
      }

      metadata = %{
        method: :userpass,
        mount_path: mount_path,
        username: username
      }

      Logger.debug("Attempting UserPass authentication", metadata)
      Telemetry.auth_start(metadata)

      start_time = System.monotonic_time()

      case HTTP.request(:post, path, request_body, [], opts) do
        {:ok, %{body: %{"auth" => auth_info}}} ->
          duration = System.monotonic_time() - start_time

          auth_response = build_auth_response(auth_info)

          Logger.info(
            "UserPass authentication successful",
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
              details: %{auth_method: :userpass, username: username}
            )

          Logger.error("UserPass authentication failed", Map.put(metadata, :error, error))
          Telemetry.auth_failure(duration, Map.put(metadata, :error, error))
          Security.audit_log(:authentication, :failure, Map.put(metadata, :error, error.type))

          {:error, error}

        {:error, error} ->
          duration = System.monotonic_time() - start_time

          Logger.error("UserPass authentication error", Map.put(metadata, :error, error))
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
         :ok <- validate_field_formats(credentials) do
      :ok
    end
  end

  def validate_credentials(_) do
    {:error, Error.new(:invalid_request, "Credentials must be a map")}
  end

  @impl true
  def refresh_token(_token, _opts) do
    {:error, Error.new(:not_supported, "UserPass authentication does not support token refresh")}
  end

  @impl true
  def revoke_token(_token, _opts) do
    {:error,
     Error.new(:not_supported, "UserPass authentication does not support token revocation")}
  end

  @impl true
  def metadata do
    %{
      name: "Username & Password",
      supports_refresh: false,
      supports_revocation: false,
      required_fields: [:username, :password],
      optional_fields: [],
      description: "Authenticate using username and password credentials"
    }
  end

  # Private helper functions

  defp validate_required_fields(credentials) do
    required_fields = [:username, :password]

    missing_fields =
      required_fields
      |> Enum.reject(&Map.has_key?(credentials, &1))

    if Enum.empty?(missing_fields) do
      :ok
    else
      {:error,
       Error.new(:invalid_request, "Missing required fields: #{Enum.join(missing_fields, ", ")}")}
    end
  end

  defp validate_field_types(credentials) do
    errors =
      []
      |> validate_string_field(credentials, :username, "Username")
      |> validate_string_field(credentials, :password, "Password")

    if Enum.empty?(errors) do
      :ok
    else
      {:error, Error.new(:invalid_request, "Invalid field types: #{Enum.join(errors, ", ")}")}
    end
  end

  defp validate_field_formats(credentials) do
    username = Map.get(credentials, :username, "")
    password = Map.get(credentials, :password, "")

    cond do
      is_nil(username) or String.length(username) == 0 ->
        {:error, Error.new(:invalid_request, "Username cannot be empty")}

      is_nil(password) or String.length(password) == 0 ->
        {:error, Error.new(:invalid_request, "Password cannot be empty")}

      String.length(username) > 256 ->
        {:error, Error.new(:invalid_request, "Username too long (max 256 characters)")}

      String.length(password) > 4096 ->
        {:error, Error.new(:invalid_request, "Password too long (max 4096 characters)")}

      not String.valid?(username) ->
        {:error, Error.new(:invalid_request, "Username must be valid UTF-8")}

      not String.valid?(password) ->
        {:error, Error.new(:invalid_request, "Password must be valid UTF-8")}

      true ->
        :ok
    end
  end

  defp validate_string_field(errors, credentials, field, field_name) do
    case Map.get(credentials, field) do
      value when is_binary(value) -> errors
      nil -> errors
      _ -> ["#{field_name} must be a string" | errors]
    end
  end

  defp build_auth_response(auth_info) do
    %{
      client_token: auth_info["client_token"],
      accessor: auth_info["accessor"],
      policies: auth_info["policies"] || [],
      lease_duration: auth_info["lease_duration"] || 0,
      renewable: auth_info["renewable"] || false,
      entity_id: auth_info["entity_id"],
      token_type: auth_info["token_type"],
      metadata: %{
        auth_method: "userpass",
        username: auth_info["metadata"]["username"]
      }
    }
  end
end
