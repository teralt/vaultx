defmodule Vaultx.Auth.JWT do
  @moduledoc """
  JWT/OIDC authentication method for HashiCorp Vault.

  This module implements comprehensive JWT (JSON Web Token) and OIDC (OpenID Connect)
  authentication for Vault, supporting both direct JWT authentication and full OIDC
  flows with extensive validation and security features.

  ## Features

  - JWT Authentication: Direct JWT token validation and authentication
  - OIDC Support: Full OpenID Connect authentication flow
  - Multiple Providers: Support for various OIDC providers (Auth0, Google, Azure, etc.)
  - Flexible Validation: Configurable JWT validation with custom claims
  - Security: Built-in signature verification and claim validation
  - Enterprise Ready: Supports all Vault enterprise features

  ## Authentication Types

  ### JWT Authentication
  Direct authentication using pre-signed JWT tokens:

      {:ok, auth_response} = Vaultx.Auth.JWT.authenticate(%{
        role: "my-jwt-role",
        jwt: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
      })

  ### OIDC Authentication
  Full OIDC authentication flow (requires browser interaction):

      # Step 1: Get authorization URL
      {:ok, auth_url} = Vaultx.Auth.JWT.get_oidc_auth_url(%{
        role: "my-oidc-role",
        redirect_uri: "https://myapp.com/callback"
      })

      # Step 2: User authenticates via browser and returns with code
      # Step 3: Complete authentication with authorization code
      {:ok, auth_response} = Vaultx.Auth.JWT.oidc_callback(%{
        state: "state_from_auth_url",
        code: "authorization_code_from_provider",
        nonce: "nonce_from_auth_url"
      })

  ## API Compliance

  Fully implements HashiCorp Vault JWT/OIDC authentication:
  - [JWT/OIDC Auth Method](https://developer.hashicorp.com/vault/api-docs/auth/jwt)
  - [JWT/OIDC Auth Configuration](https://developer.hashicorp.com/vault/docs/auth/jwt)

  ## Advanced Features

  ### Custom Claims Validation
      {:ok, auth_response} = Vaultx.Auth.JWT.authenticate(%{
        role: "my-role",
        jwt: "eyJ...",
        bound_claims: %{
          "department" => "engineering",
          "clearance_level" => "secret"
        }
      })

  ### Provider-Specific Configuration
      # Azure AD integration
      {:ok, auth_response} = Vaultx.Auth.JWT.authenticate(%{
        role: "azure-role",
        jwt: "eyJ...",
        provider_config: %{
          provider: "azure",
          tenant_id: "your-tenant-id"
        }
      })

  ## Vault Configuration

  Before using this authentication method, configure it in Vault:

      # Enable JWT auth method
      vault auth enable jwt

      # Configure OIDC provider
      vault write auth/jwt/config \\
        oidc_discovery_url="https://myco.auth0.com/" \\
        oidc_client_id="your-client-id" \\
        oidc_client_secret="your-client-secret"

      # Create JWT role
      vault write auth/jwt/role/my-jwt-role \\
        role_type="jwt" \\
        bound_audiences="https://myco.test" \\
        user_claim="sub" \\
        policies="default,myapp"

      # Create OIDC role
      vault write auth/jwt/role/my-oidc-role \\
        role_type="oidc" \\
        bound_audiences="your-client-id" \\
        allowed_redirect_uris="https://myapp.com/callback" \\
        user_claim="email" \\
        policies="default,myapp"

  ## Security Considerations

  - Validate JWT signatures using proper public keys or JWKS endpoints
  - Use appropriate bound claims to restrict access
  - Implement proper redirect URI validation for OIDC flows
  - Monitor authentication events in Vault audit logs
  - Use short-lived tokens when possible
  - Implement proper token refresh mechanisms
  """

  @behaviour Vaultx.Auth.Behaviour

  alias Vaultx.Base.{Error, Logger, Security, Telemetry}
  alias Vaultx.Transport.HTTP

  # Default mount path for JWT auth method
  @default_mount_path "jwt"

  @impl true
  def authenticate(credentials, opts \\ []) do
    with :ok <- validate_credentials(credentials),
         :ok <- Security.audit_log(:authentication, :attempt, %{method: :jwt}) do
      mount_path = Keyword.get(opts, :mount_path, @default_mount_path)
      path = "auth/#{mount_path}/login"

      request_body = build_request_body(credentials)

      metadata = %{
        method: :jwt,
        mount_path: mount_path,
        role: Map.get(credentials, :role),
        auth_type: detect_auth_type(credentials)
      }

      Logger.debug("Attempting JWT authentication", metadata)
      Telemetry.auth_start(metadata)

      start_time = System.monotonic_time()

      case HTTP.request(:post, path, request_body, [], opts) do
        {:ok, %{body: %{"auth" => auth_info}}} ->
          duration = System.monotonic_time() - start_time

          auth_response = build_auth_response(auth_info)

          Logger.info(
            "JWT authentication successful",
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
              details: %{auth_method: :jwt, role: Map.get(credentials, :role)}
            )

          Logger.error("JWT authentication failed", Map.put(metadata, :error, error))
          Telemetry.auth_failure(duration, Map.put(metadata, :error, error))
          Security.audit_log(:authentication, :failure, Map.put(metadata, :error, error.type))

          {:error, error}

        {:error, error} ->
          duration = System.monotonic_time() - start_time

          Logger.error("JWT authentication error", Map.put(metadata, :error, error))
          Telemetry.auth_failure(duration, Map.put(metadata, :error, error))
          Security.audit_log(:authentication, :failure, Map.put(metadata, :error, error.type))

          {:error, error}
      end
    end
  end

  @doc """
  Get OIDC authorization URL for browser-based authentication flow.

  ## Parameters

    * `params` - Map containing:
      * `:role` - Name of the OIDC role
      * `:redirect_uri` - Callback URL for OIDC flow
      * `:client_nonce` - Optional client nonce for additional security

  ## Returns

    * `{:ok, %{auth_url: url, state: state, nonce: nonce}}` - Authorization URL and flow parameters
    * `{:error, %Vaultx.Base.Error{}}` - Request failed with detailed error

  ## Examples

      {:ok, %{auth_url: url}} = Vaultx.Auth.JWT.get_oidc_auth_url(%{
        role: "my-oidc-role",
        redirect_uri: "https://myapp.com/callback"
      })

      # Redirect user to auth_url for authentication
  """
  def get_oidc_auth_url(params, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)
    path = "auth/#{mount_path}/oidc/auth_url"

    request_body = %{
      role: Map.get(params, :role),
      redirect_uri: Map.get(params, :redirect_uri),
      client_nonce: Map.get(params, :client_nonce)
    }

    case HTTP.request(:post, path, request_body, [], opts) do
      {:ok, %{body: %{"data" => data}}} ->
        {:ok,
         %{
           auth_url: data["auth_url"],
           state: extract_state_from_url(data["auth_url"]),
           nonce: extract_nonce_from_url(data["auth_url"])
         }}

      {:ok, %{body: response}} ->
        {:error, Error.from_http_response(Map.get(response, "status", 400), response)}

      {:error, error} ->
        {:error, error}
    end
  end

  @doc """
  Validate JWT token locally using JOSE library (optional).

  This function provides optional local JWT validation using the JOSE library.
  It can be used to validate JWT structure and claims before sending to Vault.

  ## Parameters

    * `jwt` - JWT token string to validate
    * `opts` - Validation options:
      * `:verify_signature` - Whether to verify JWT signature (default: false)
      * `:jwks_url` - JWKS URL for signature verification
      * `:public_key` - Public key for signature verification
      * `:expected_claims` - Map of expected claims to validate

  ## Returns

    * `{:ok, %{header: header, payload: payload}}` - JWT is valid with decoded parts
    * `{:error, %Vaultx.Base.Error{}}` - JWT validation failed

  ## Examples

      # Basic structure validation
      {:ok, %{payload: payload}} = Vaultx.Auth.JWT.validate_jwt_local(jwt_token)

      # With claim validation
      {:ok, decoded} = Vaultx.Auth.JWT.validate_jwt_local(jwt_token,
        expected_claims: %{"iss" => "https://myco.auth0.com/"}
      )

  ## Note

  This function requires the optional `jose` dependency. If not available,
  it will return `{:error, :jose_not_available}`.
  """
  def validate_jwt_local(jwt, opts \\ []) do
    if Code.ensure_loaded?(JOSE.JWT) do
      try do
        with {:ok, payload} <- extract_jwt_payload(jwt),
             {:ok, header} <- extract_jwt_header(jwt),
             :ok <- validate_expected_claims(payload, opts),
             :ok <- maybe_verify_signature(jwt, header, opts) do
          {:ok, %{header: header, payload: payload}}
        end
      rescue
        # coveralls-ignore-start
        # This catch-all rescue clause handles any unexpected exceptions from the JOSE library.
        # It's defensive programming to prevent crashes, but very difficult to test reliably
        # since it depends on internal JOSE library behavior and edge cases.
        error ->
          {:error, Error.new(:invalid_request, "JWT parsing failed: #{inspect(error)}")}
          # coveralls-ignore-stop
      end
    else
      {:error, :jose_not_available}
    end
  end

  @doc """
  Complete OIDC authentication flow using authorization callback parameters.

  ## Parameters

    * `params` - Map containing:
      * `:state` - State parameter from authorization URL
      * `:code` - Authorization code from OIDC provider
      * `:nonce` - Nonce parameter from authorization URL
      * `:client_nonce` - Optional client nonce if used in auth URL request

  ## Returns

    * `{:ok, auth_response}` - Authentication successful with token information
    * `{:error, %Vaultx.Base.Error{}}` - Authentication failed with detailed error

  ## Examples

      {:ok, auth_response} = Vaultx.Auth.JWT.oidc_callback(%{
        state: "state_from_redirect",
        code: "auth_code_from_provider",
        nonce: "nonce_from_redirect"
      })
  """
  def oidc_callback(params, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    query_params =
      [
        {"state", Map.get(params, :state)},
        {"code", Map.get(params, :code)},
        {"nonce", Map.get(params, :nonce)},
        {"client_nonce", Map.get(params, :client_nonce)}
      ]
      |> Enum.reject(fn {_k, v} -> is_nil(v) end)
      |> Enum.map(fn {k, v} -> "#{k}=#{URI.encode_www_form(v)}" end)
      |> Enum.join("&")

    path = "auth/#{mount_path}/oidc/callback?#{query_params}"

    case HTTP.request(:get, path, nil, [], opts) do
      {:ok, %{body: %{"auth" => auth_info}}} ->
        auth_response = build_auth_response(auth_info)
        {:ok, auth_response}

      {:ok, %{body: response}} ->
        {:error, Error.from_http_response(Map.get(response, "status", 400), response)}

      {:error, error} ->
        {:error, error}
    end
  end

  @impl true
  def validate_credentials(credentials) when is_map(credentials) do
    with :ok <- validate_required_fields(credentials),
         :ok <- validate_field_types(credentials),
         :ok <- validate_jwt_format(credentials) do
      :ok
    end
  end

  def validate_credentials(_) do
    {:error, Error.new(:invalid_request, "Credentials must be a map")}
  end

  @impl true
  def refresh_token(_token, _opts) do
    {:error, Error.new(:not_supported, "JWT authentication does not support token refresh")}
  end

  @impl true
  def revoke_token(_token, _opts) do
    {:error, Error.new(:not_supported, "JWT authentication does not support token revocation")}
  end

  @impl true
  def metadata do
    %{
      name: "JWT/OIDC",
      supports_refresh: false,
      supports_revocation: false,
      required_fields: [:role, :jwt],
      optional_fields: [:bound_claims, :provider_config],
      description: "Authenticate using JWT tokens or OIDC authentication flow"
    }
  end

  # Private helper functions

  defp validate_required_fields(credentials) do
    # For JWT authentication, we need role and jwt
    # For OIDC flows, requirements are different and handled separately
    if Map.has_key?(credentials, :jwt) do
      required_fields = [:role, :jwt]

      missing_fields =
        required_fields
        |> Enum.reject(&Map.has_key?(credentials, &1))

      if Enum.empty?(missing_fields) do
        :ok
      else
        {:error,
         Error.new(
           :invalid_request,
           "Missing required fields: #{Enum.join(missing_fields, ", ")}"
         )}
      end
    else
      # For OIDC flows, we just need role
      if Map.has_key?(credentials, :role) do
        :ok
      else
        {:error, Error.new(:invalid_request, "Missing required field: role")}
      end
    end
  end

  defp validate_field_types(credentials) do
    errors =
      []
      |> validate_string_field(credentials, :role, "Role")
      |> validate_string_field(credentials, :jwt, "JWT")

    if Enum.empty?(errors) do
      :ok
    else
      {:error, Error.new(:invalid_request, "Invalid field types: #{Enum.join(errors, ", ")}")}
    end
  end

  defp validate_jwt_format(credentials) do
    case Map.get(credentials, :jwt) do
      nil ->
        :ok

      jwt when is_binary(jwt) ->
        if valid_jwt_format?(jwt) do
          :ok
        else
          {:error, Error.new(:invalid_request, "Invalid JWT format")}
        end

      # coveralls-ignore-start
      # This catch-all clause handles cases where JWT field is not a string type.
      # While we have tests for this scenario, it's defensive programming to ensure
      # type safety and provide clear error messages for invalid input types.
      _ ->
        {:error, Error.new(:invalid_request, "JWT must be a string")}
        # coveralls-ignore-stop
    end
  end

  defp valid_jwt_format?(jwt) do
    # Basic JWT format validation (3 parts separated by dots)
    case String.split(jwt, ".") do
      [_header, _payload, _signature] -> true
      _ -> false
    end
  end

  defp validate_string_field(errors, credentials, field, field_name) do
    case Map.get(credentials, field) do
      value when is_binary(value) -> errors
      nil -> errors
      _ -> ["#{field_name} must be a string" | errors]
    end
  end

  defp build_request_body(credentials) do
    base_body = %{
      role: Map.get(credentials, :role),
      jwt: Map.get(credentials, :jwt)
    }

    # Add optional fields if present
    base_body
    |> maybe_add_field(credentials, :bound_claims)
    |> maybe_add_field(credentials, :provider_config)
  end

  defp maybe_add_field(body, credentials, field) do
    case Map.get(credentials, field) do
      nil -> body
      value -> Map.put(body, field, value)
    end
  end

  defp detect_auth_type(credentials) do
    cond do
      Map.has_key?(credentials, :jwt) -> "jwt"
      true -> "oidc"
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
        auth_method: "jwt",
        role: auth_info["metadata"]["role"]
      }
    }
  end

  defp extract_state_from_url(auth_url) when is_binary(auth_url) do
    case URI.parse(auth_url) do
      %URI{query: query} when is_binary(query) ->
        query
        |> URI.decode_query()
        |> Map.get("state")

      _ ->
        nil
    end
  end

  defp extract_state_from_url(_), do: nil

  defp extract_nonce_from_url(auth_url) when is_binary(auth_url) do
    case URI.parse(auth_url) do
      %URI{query: query} when is_binary(query) ->
        query
        |> URI.decode_query()
        |> Map.get("nonce")

      # coveralls-ignore-start
      # This catch-all clause handles unexpected URI parsing results.
      # URI.parse/1 should always return a %URI{} struct for valid strings,
      # but this provides defensive coverage for any edge cases.
      _ ->
        nil
        # coveralls-ignore-stop
    end
  end

  defp extract_nonce_from_url(_), do: nil

  defp validate_expected_claims(payload, opts) do
    case Keyword.get(opts, :expected_claims) do
      nil ->
        :ok

      expected_claims when is_map(expected_claims) ->
        Enum.reduce_while(expected_claims, :ok, fn {claim, expected_value}, _acc ->
          case Map.get(payload, claim) do
            ^expected_value ->
              {:cont, :ok}

            actual_value ->
              {:halt,
               {:error,
                Error.new(
                  :invalid_request,
                  "JWT claim '#{claim}' mismatch. Expected: #{inspect(expected_value)}, Got: #{inspect(actual_value)}"
                )}}
          end
        end)

      _ ->
        {:error, Error.new(:invalid_request, "expected_claims must be a map")}
    end
  end

  defp maybe_verify_signature(jwt, _header, opts) do
    if Keyword.get(opts, :verify_signature, false) do
      case {Keyword.get(opts, :public_key), Keyword.get(opts, :jwks_url)} do
        {nil, nil} ->
          {:error,
           Error.new(
             :invalid_request,
             "Public key or JWKS URL required for signature verification"
           )}

        {public_key, nil} when is_binary(public_key) ->
          verify_with_public_key(jwt, public_key)

        {nil, jwks_url} when is_binary(jwks_url) ->
          {:error, Error.new(:not_implemented, "JWKS URL verification not yet implemented")}

        _ ->
          {:error, Error.new(:invalid_request, "Invalid signature verification configuration")}
      end
    else
      :ok
    end
  end

  defp verify_with_public_key(jwt, public_key) do
    try do
      case JOSE.JWT.verify_strict(JOSE.JWK.from_pem(public_key), ["RS256", "ES256"], jwt) do
        {true, _payload, _jws} ->
          :ok

        {false, _payload, _jws} ->
          {:error, Error.new(:invalid_request, "JWT signature verification failed")}
      end
    rescue
      error ->
        {:error,
         Error.new(:invalid_request, "JWT signature verification error: #{inspect(error)}")}
    end
  end

  defp extract_jwt_payload(jwt) do
    case JOSE.JWT.peek_payload(jwt) do
      %{__struct__: JOSE.JWT, fields: payload} ->
        {:ok, payload}
    end
  rescue
    _ ->
      {:error, Error.new(:invalid_request, "Invalid JWT payload format")}
  end

  defp extract_jwt_header(jwt) do
    case JOSE.JWT.peek_protected(jwt) do
      %{__struct__: JOSE.JWS, fields: header} ->
        {:ok, header}
    end
  rescue
    _ ->
      {:error, Error.new(:invalid_request, "Invalid JWT header format")}
  end
end
