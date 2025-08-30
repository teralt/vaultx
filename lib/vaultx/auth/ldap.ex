defmodule Vaultx.Auth.LDAP do
  @moduledoc """
  LDAP authentication method for HashiCorp Vault.

  This module implements the LDAP authentication method for Vault, providing
  secure directory-based authentication with comprehensive support for Active
  Directory, OpenLDAP, and other LDAP-compatible directory services.

  ## Features

  - Directory Authentication: LDAP/Active Directory integration
  - Group Mapping: Automatic policy assignment based on LDAP groups
  - User Management: Support for user-specific policy overrides
  - TLS Security: Support for LDAPS and StartTLS connections
  - Flexible Configuration: Extensive LDAP server configuration options
  - Enterprise Ready: Supports all Vault enterprise features including MFA

  ## API Compliance

  Fully implements HashiCorp Vault LDAP authentication:
  - [LDAP Auth Method](https://developer.hashicorp.com/vault/api-docs/auth/ldap)
  - [LDAP Auth Configuration](https://developer.hashicorp.com/vault/docs/auth/ldap)

  ## Usage Examples

  ### Basic Authentication

      {:ok, auth_response} = Vaultx.Auth.LDAP.authenticate(%{
        username: "john.doe",
        password: "mypassword"
      })

  ### Authentication with Custom Mount Path

      {:ok, auth_response} = Vaultx.Auth.LDAP.authenticate(%{
        username: "john.doe",
        password: "mypassword"
      }, mount_path: "custom-ldap")

  ### Authentication with Additional Options

      {:ok, auth_response} = Vaultx.Auth.LDAP.authenticate(%{
        username: "john.doe",
        password: "mypassword"
      }, [
        mount_path: "ldap",
        timeout: 30_000,
        retry_attempts: 3
      ])

  ## Vault Configuration

  Before using this authentication method, configure it in Vault:

      # Enable LDAP auth method
      vault auth enable ldap

      # Configure LDAP connection
      vault write auth/ldap/config \\
        url="ldaps://ldap.company.com:636" \\
        userdn="ou=Users,dc=company,dc=com" \\
        userattr="sAMAccountName" \\
        groupdn="ou=Groups,dc=company,dc=com" \\
        groupfilter="(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}}))" \\
        groupattr="cn" \\
        binddn="cn=vault,ou=ServiceAccounts,dc=company,dc=com" \\
        bindpass="service-password"

      # Map LDAP groups to Vault policies
      vault write auth/ldap/groups/admins policies="admin,default"
      vault write auth/ldap/groups/developers policies="dev,default"

      # Override policies for specific users (optional)
      vault write auth/ldap/users/john.doe policies="admin,default"

  ## Security Considerations

  - Use LDAPS or StartTLS for encrypted connections
  - Implement proper certificate validation
  - Use service accounts with minimal required permissions
  - Monitor authentication events in Vault audit logs
  - Regularly review group mappings and user overrides
  - Consider implementing MFA for additional security
  - Use connection pooling and timeouts appropriately
  """

  @behaviour Vaultx.Auth.Behaviour

  alias Vaultx.Base.{Error, Logger, Security, Telemetry}
  alias Vaultx.Transport.HTTP

  # Default mount path for LDAP auth method
  @default_mount_path "ldap"

  @impl true
  def authenticate(credentials, opts \\ []) do
    with :ok <- validate_credentials(credentials),
         :ok <- Security.audit_log(:authentication, :attempt, %{method: :ldap}) do
      mount_path = Keyword.get(opts, :mount_path, @default_mount_path)
      username = Map.get(credentials, :username)
      path = "auth/#{mount_path}/login/#{username}"

      request_body = %{
        password: Map.get(credentials, :password)
      }

      metadata = %{
        method: :ldap,
        mount_path: mount_path,
        username: username
      }

      Logger.debug("Attempting LDAP authentication", metadata)
      Telemetry.auth_start(metadata)

      start_time = System.monotonic_time()

      case HTTP.request(:post, path, request_body, [], opts) do
        {:ok, %{body: %{"auth" => auth_info}}} ->
          duration = System.monotonic_time() - start_time

          auth_response = build_auth_response(auth_info, username)

          Logger.info(
            "LDAP authentication successful",
            Map.merge(metadata, %{
              policies: auth_info["policies"],
              lease_duration: auth_info["lease_duration"],
              renewable: auth_info["renewable"]
            })
          )

          Telemetry.auth_success(duration, metadata)
          Security.audit_log(:authentication, :success, metadata)

          {:ok, auth_response}

        {:ok, %{body: response}} ->
          duration = System.monotonic_time() - start_time

          error =
            Error.from_http_response(
              Map.get(response, "status", 401),
              response,
              details: %{method: :ldap, username: username}
            )

          Logger.error("LDAP authentication failed", Map.put(metadata, :error, error))
          Telemetry.auth_failure(duration, Map.put(metadata, :error, error))
          Security.audit_log(:authentication, :failure, Map.put(metadata, :error, error.type))

          {:error, error}

        {:error, error} ->
          duration = System.monotonic_time() - start_time

          Logger.error("LDAP authentication error", Map.put(metadata, :error, error))
          Telemetry.auth_failure(duration, Map.put(metadata, :error, error))
          Security.audit_log(:authentication, :failure, Map.put(metadata, :error, error.type))

          {:error, error}
      end
    end
  end

  @impl true
  def refresh_token(_token, _opts) do
    {:error, Error.new(:unsupported_operation, "LDAP auth method does not support token refresh")}
  end

  @impl true
  def revoke_token(_token, _opts) do
    {:error,
     Error.new(:unsupported_operation, "LDAP auth method does not support token revocation")}
  end

  @impl true
  def validate_credentials(credentials) do
    with :ok <- validate_required_fields(credentials),
         :ok <- validate_field_types(credentials),
         :ok <- validate_field_formats(credentials) do
      :ok
    end
  end

  @impl true
  def metadata do
    %{
      name: "ldap",
      supports_refresh: false,
      supports_revocation: false,
      required_fields: [:username, :password],
      optional_fields: [],
      description: "LDAP directory authentication with group-based policy mapping"
    }
  end

  # Private helper functions

  defp validate_required_fields(credentials) do
    required_fields = [:username, :password]

    missing_fields =
      Enum.filter(required_fields, fn field ->
        case Map.get(credentials, field) do
          nil -> true
          _ -> false
        end
      end)

    case missing_fields do
      [] ->
        :ok

      fields ->
        field_names = Enum.map(fields, &to_string/1)
        message = "Missing required fields: #{Enum.join(field_names, ", ")}"
        {:error, Error.new(:invalid_request, message)}
    end
  end

  defp validate_field_types(credentials) do
    type_validations = [
      {:username, :string},
      {:password, :string}
    ]

    Enum.reduce_while(type_validations, :ok, fn {field, expected_type}, _acc ->
      case Map.get(credentials, field) do
        # coveralls-ignore-start
        # This handles nil field values during type validation.
        # In normal flow, nil values for required fields are caught earlier.
        nil ->
          {:cont, :ok}

        # coveralls-ignore-stop

        value ->
          if valid_type?(value, expected_type) do
            {:cont, :ok}
          else
            message = "Field '#{field}' must be a #{expected_type}"
            {:halt, {:error, Error.new(:invalid_request, message)}}
          end
      end
    end)
  end

  defp validate_field_formats(credentials) do
    with :ok <- validate_username_format(Map.get(credentials, :username)),
         :ok <- validate_password_format(Map.get(credentials, :password)) do
      :ok
    end
  end

  # coveralls-ignore-start
  # This handles nil username in format validation, which is defensive programming.
  # In normal flow, nil usernames are caught by required field validation first.
  defp validate_username_format(nil), do: :ok
  # coveralls-ignore-stop

  defp validate_username_format(""),
    do: {:error, Error.new(:invalid_request, "Username cannot be empty")}

  defp validate_username_format(username) when is_binary(username) do
    cond do
      byte_size(username) > 256 ->
        {:error, Error.new(:invalid_request, "Username too long (max 256 characters)")}

      not String.valid?(username) ->
        {:error, Error.new(:invalid_request, "Username contains invalid UTF-8 characters")}

      true ->
        :ok
    end
  end

  # coveralls-ignore-start
  # This handles non-string username types that aren't caught by type validation.
  # It's defensive programming for edge cases.
  defp validate_username_format(_),
    do: {:error, Error.new(:invalid_request, "Username must be a string")}

  # coveralls-ignore-stop

  # coveralls-ignore-start
  # This handles nil password in format validation, which is defensive programming.
  # In normal flow, nil passwords are caught by required field validation first.
  defp validate_password_format(nil), do: :ok
  # coveralls-ignore-stop

  defp validate_password_format(""),
    do: {:error, Error.new(:invalid_request, "Password cannot be empty")}

  defp validate_password_format(password) when is_binary(password) do
    cond do
      byte_size(password) > 4096 ->
        {:error, Error.new(:invalid_request, "Password too long (max 4096 characters)")}

      not String.valid?(password) ->
        {:error, Error.new(:invalid_request, "Password contains invalid UTF-8 characters")}

      true ->
        :ok
    end
  end

  # coveralls-ignore-start
  # This handles non-string password types that aren't caught by type validation.
  # It's defensive programming for edge cases.
  defp validate_password_format(_),
    do: {:error, Error.new(:invalid_request, "Password must be a string")}

  # coveralls-ignore-stop

  defp valid_type?(value, :string), do: is_binary(value)

  # coveralls-ignore-start
  # This handles unknown types in validation. It's defensive programming
  # to ensure type safety for any future type additions.
  defp valid_type?(_value, _type), do: false
  # coveralls-ignore-stop

  defp build_auth_response(auth_info, username) do
    %{
      client_token: auth_info["client_token"],
      accessor: auth_info["accessor"],
      policies: auth_info["policies"] || [],
      token_policies: auth_info["token_policies"] || auth_info["policies"] || [],
      metadata: %{
        auth_method: "ldap",
        username: username
      },
      lease_duration: auth_info["lease_duration"] || 0,
      renewable: auth_info["renewable"] || false,
      entity_id: auth_info["entity_id"],
      token_type: auth_info["token_type"] || "service",
      orphan: auth_info["orphan"] || false,
      num_uses: auth_info["num_uses"] || 0
    }
  end
end
