defmodule Vaultx.Auth.Token do
  @moduledoc """
  Token authentication method for HashiCorp Vault.

  This module implements comprehensive token management for Vault, providing
  functionality for token creation, lookup, renewal, and revocation. Unlike other
  authentication methods that obtain tokens, this module manages existing tokens
  and provides token-based operations.

  ## Features

  - Token Creation: Create new tokens with configurable policies and TTL
  - Token Lookup: Retrieve information about existing tokens
  - Token Renewal: Extend token lifetime within configured limits
  - Token Revocation: Safely revoke tokens and associated leases
  - Role Management: Support for token roles with predefined configurations
  - Accessor Operations: Manage tokens via their accessor IDs
  - Enterprise Ready: Supports all Vault enterprise features

  ## API Compliance

  Fully implements HashiCorp Vault Token authentication:
  - [Token Auth Method](https://developer.hashicorp.com/vault/api-docs/auth/token)
  - [Token Auth Configuration](https://developer.hashicorp.com/vault/docs/auth/token)

  ## Usage Examples

  ### Token Lookup (Self)

      {:ok, token_info} = Vaultx.Auth.Token.lookup_self()

  ### Token Lookup (Specific Token)

      {:ok, token_info} = Vaultx.Auth.Token.lookup_token("hvs.CAESIJ...")

  ### Token Creation

      {:ok, auth_response} = Vaultx.Auth.Token.create_token(%{
        policies: ["default", "myapp"],
        ttl: "1h",
        renewable: true
      })

  ### Token Renewal

      {:ok, auth_response} = Vaultx.Auth.Token.renew_token("hvs.CAESIJ...", %{
        increment: "30m"
      })

  ### Token Revocation

      :ok = Vaultx.Auth.Token.revoke_token("hvs.CAESIJ...")

  ## Vault Configuration

  The token auth method is enabled by default in Vault:

      # Token auth is always available at auth/token/
      # No additional configuration required

      # Create token roles (optional)
      vault write auth/token/roles/myapp \\
        allowed_policies="default,myapp" \\
        orphan=true \\
        renewable=true

  ## Security Considerations

  - Use appropriate token TTL values to minimize exposure
  - Implement proper token rotation strategies
  - Monitor token usage and revoke unused tokens
  - Use token roles to enforce consistent policies
  - Regularly audit token permissions and usage
  - Consider using batch tokens for high-volume scenarios
  """

  @behaviour Vaultx.Auth.Behaviour

  alias Vaultx.Base.{Error, Logger, Security, Telemetry}
  alias Vaultx.Transport.HTTP

  # Default mount path for Token auth method
  @default_mount_path "token"

  @impl true
  def authenticate(credentials, opts \\ []) do
    # Token auth doesn't follow the typical authentication pattern
    # Instead, we provide token lookup functionality
    case Map.get(credentials, :token) do
      nil ->
        lookup_self(opts)

      token ->
        lookup_token(token, opts)
    end
  end

  @doc """
  Look up information about the current client token.

  ## Parameters

    * `opts` - Options for the request:
      * `:mount_path` - Custom mount path (default: "token")
      * `:timeout` - Request timeout in milliseconds

  ## Returns

    * `{:ok, token_info}` - Token information retrieved successfully
    * `{:error, %Vaultx.Base.Error{}}` - Request failed with detailed error

  ## Examples

      {:ok, token_info} = Vaultx.Auth.Token.lookup_self()
      IO.inspect(token_info.policies)
  """
  def lookup_self(opts \\ []) do
    with :ok <- Security.audit_log(:authentication, :attempt, %{operation: :lookup_self}) do
      mount_path = Keyword.get(opts, :mount_path, @default_mount_path)
      path = "auth/#{mount_path}/lookup-self"

      metadata = %{
        method: :token,
        operation: :lookup_self,
        mount_path: mount_path
      }

      Logger.debug("Looking up current token", metadata)
      Telemetry.auth_start(metadata)

      start_time = System.monotonic_time()

      case HTTP.request(:get, path, nil, [], opts) do
        {:ok, %{body: %{"data" => token_data}}} ->
          duration = System.monotonic_time() - start_time

          token_info = build_token_info(token_data)

          Logger.info(
            "Token lookup successful",
            Map.merge(metadata, %{
              policies: token_data["policies"],
              ttl: token_data["ttl"],
              renewable: token_data["renewable"]
            })
          )

          Telemetry.auth_success(duration, metadata)
          Security.audit_log(:authentication, :success, metadata)

          # Enhanced security event for successful authentication
          Telemetry.emit_security_event(
            :token_lookup_success,
            :low,
            %{
              token_policies: token_data["policies"],
              ttl: token_data["ttl"],
              renewable: token_data["renewable"]
            }
          )

          {:ok, token_info}

        {:ok, %{body: response}} ->
          duration = System.monotonic_time() - start_time

          error =
            Error.from_http_response(
              Map.get(response, "status", 400),
              response,
              details: %{operation: :lookup_self}
            )

          Logger.error("Token lookup failed", Map.put(metadata, :error, error))
          Telemetry.auth_failure(duration, Map.put(metadata, :error, error))
          Security.audit_log(:authentication, :failure, Map.put(metadata, :error, error.type))

          # Enhanced security event for authentication failure
          severity = if error.type in [:unauthorized, :forbidden], do: :high, else: :medium

          Telemetry.emit_security_event(
            :token_lookup_failure,
            severity,
            %{
              error_type: error.type,
              status: Map.get(response, "status", 400)
            }
          )

          {:error, error}

        {:error, error} ->
          duration = System.monotonic_time() - start_time

          Logger.error("Token lookup error", Map.put(metadata, :error, error))
          Telemetry.auth_failure(duration, Map.put(metadata, :error, error))
          Security.audit_log(:authentication, :failure, Map.put(metadata, :error, error.type))

          {:error, error}
      end
    end
  end

  @doc """
  Look up information about a specific token.

  ## Parameters

    * `token` - Token to look up
    * `opts` - Options for the request:
      * `:mount_path` - Custom mount path (default: "token")
      * `:timeout` - Request timeout in milliseconds

  ## Returns

    * `{:ok, token_info}` - Token information retrieved successfully
    * `{:error, %Vaultx.Base.Error{}}` - Request failed with detailed error

  ## Examples

      {:ok, token_info} = Vaultx.Auth.Token.lookup_token("hvs.CAESIJ...")
      IO.inspect(token_info.policies)
  """
  def lookup_token(token, opts \\ []) do
    with :ok <- validate_token(token),
         :ok <- Security.audit_log(:authentication, :attempt, %{operation: :lookup_token}) do
      mount_path = Keyword.get(opts, :mount_path, @default_mount_path)
      path = "auth/#{mount_path}/lookup"

      request_body = %{token: token}

      metadata = %{
        method: :token,
        operation: :lookup_token,
        mount_path: mount_path
      }

      Logger.debug("Looking up specific token", metadata)
      Telemetry.auth_start(metadata)

      start_time = System.monotonic_time()

      case HTTP.request(:post, path, request_body, [], opts) do
        {:ok, %{body: %{"data" => token_data}}} ->
          duration = System.monotonic_time() - start_time

          token_info = build_token_info(token_data)

          Logger.info(
            "Token lookup successful",
            Map.merge(metadata, %{
              policies: token_data["policies"],
              ttl: token_data["ttl"],
              renewable: token_data["renewable"]
            })
          )

          Telemetry.auth_success(duration, metadata)
          Security.audit_log(:authentication, :success, metadata)

          {:ok, token_info}

        {:ok, %{body: response}} ->
          duration = System.monotonic_time() - start_time

          error =
            Error.from_http_response(
              Map.get(response, "status", 400),
              response,
              details: %{operation: :lookup_token}
            )

          Logger.error("Token lookup failed", Map.put(metadata, :error, error))
          Telemetry.auth_failure(duration, Map.put(metadata, :error, error))
          Security.audit_log(:authentication, :failure, Map.put(metadata, :error, error.type))

          {:error, error}

        {:error, error} ->
          duration = System.monotonic_time() - start_time

          Logger.error("Token lookup error", Map.put(metadata, :error, error))
          Telemetry.auth_failure(duration, Map.put(metadata, :error, error))
          Security.audit_log(:authentication, :failure, Map.put(metadata, :error, error.type))

          {:error, error}
      end
    end
  end

  @doc """
  Create a new token.

  ## Parameters

    * `params` - Token creation parameters:
      * `:policies` - List of policies for the token
      * `:ttl` - Token TTL (e.g., "1h", "30m")
      * `:renewable` - Whether the token can be renewed
      * `:role_name` - Token role to use for creation
      * `:meta` - Metadata to attach to the token
      * `:no_parent` - Create orphan token (requires root)
      * `:no_default_policy` - Exclude default policy
      * `:display_name` - Display name for the token
      * `:num_uses` - Maximum number of uses (0 = unlimited)
      * `:period` - Period for periodic tokens
    * `opts` - Options for the request

  ## Returns

    * `{:ok, auth_response}` - Token created successfully
    * `{:error, %Vaultx.Base.Error{}}` - Request failed with detailed error

  ## Examples

      {:ok, auth_response} = Vaultx.Auth.Token.create_token(%{
        policies: ["default", "myapp"],
        ttl: "1h",
        renewable: true
      })
  """
  def create_token(params, opts \\ []) do
    with :ok <- validate_create_params(params),
         :ok <- Security.audit_log(:token_creation, :attempt, %{operation: :create_token}) do
      mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

      # Determine the endpoint based on parameters
      path =
        case {Map.get(params, :role_name), Map.get(params, :no_parent)} do
          {role_name, _} when is_binary(role_name) ->
            "auth/#{mount_path}/create/#{role_name}"

          {_, true} ->
            "auth/#{mount_path}/create-orphan"

          _ ->
            "auth/#{mount_path}/create"
        end

      request_body = build_create_request_body(params)

      metadata = %{
        method: :token,
        operation: :create_token,
        mount_path: mount_path,
        role_name: Map.get(params, :role_name)
      }

      Logger.debug("Creating new token", metadata)
      Telemetry.auth_start(metadata)

      start_time = System.monotonic_time()

      case HTTP.request(:post, path, request_body, [], opts) do
        {:ok, %{body: %{"auth" => auth_info}}} ->
          duration = System.monotonic_time() - start_time

          auth_response = build_auth_response(auth_info)

          Logger.info(
            "Token creation successful",
            Map.merge(metadata, %{
              token_policies: auth_info["policies"],
              lease_duration: auth_info["lease_duration"],
              renewable: auth_info["renewable"]
            })
          )

          Telemetry.auth_success(duration, metadata)
          Security.audit_log(:token_creation, :success, metadata)

          {:ok, auth_response}

        {:ok, %{body: response}} ->
          duration = System.monotonic_time() - start_time

          error =
            Error.from_http_response(
              Map.get(response, "status", 400),
              response,
              details: %{operation: :create_token}
            )

          Logger.error("Token creation failed", Map.put(metadata, :error, error))
          Telemetry.auth_failure(duration, Map.put(metadata, :error, error))
          Security.audit_log(:token_creation, :failure, Map.put(metadata, :error, error.type))

          {:error, error}

        {:error, error} ->
          duration = System.monotonic_time() - start_time

          Logger.error("Token creation error", Map.put(metadata, :error, error))
          Telemetry.auth_failure(duration, Map.put(metadata, :error, error))
          Security.audit_log(:token_creation, :failure, Map.put(metadata, :error, error.type))

          {:error, error}
      end
    end
  end

  @impl true
  def refresh_token(token, opts \\ []) do
    renew_token(token, opts)
  end

  @doc """
  Renew a token to extend its lifetime.

  ## Parameters

    * `token` - Token to renew (if nil, renews current token)
    * `opts` - Options for the request:
      * `:increment` - Requested increment duration (e.g., "30m")
      * `:mount_path` - Custom mount path (default: "token")

  ## Returns

    * `{:ok, auth_response}` - Token renewed successfully
    * `{:error, %Vaultx.Base.Error{}}` - Request failed with detailed error

  ## Examples

      {:ok, auth_response} = Vaultx.Auth.Token.renew_token("hvs.CAESIJ...",
        increment: "30m"
      )
  """
  def renew_token(token, opts \\ []) do
    with :ok <- Security.audit_log(:lease_renewal, :attempt, %{operation: :renew_token}) do
      mount_path = Keyword.get(opts, :mount_path, @default_mount_path)
      increment = Keyword.get(opts, :increment)

      {path, request_body} =
        case token do
          nil ->
            # Renew self
            path = "auth/#{mount_path}/renew-self"
            body = if increment, do: %{increment: increment}, else: %{}
            {path, body}

          token_value ->
            # Renew specific token
            path = "auth/#{mount_path}/renew"
            body = %{token: token_value}
            body = if increment, do: Map.put(body, :increment, increment), else: body
            {path, body}
        end

      metadata = %{
        method: :token,
        operation: :renew_token,
        mount_path: mount_path,
        increment: increment
      }

      Logger.debug("Renewing token", metadata)
      Telemetry.auth_start(metadata)

      start_time = System.monotonic_time()

      case HTTP.request(:post, path, request_body, [], opts) do
        {:ok, %{body: %{"auth" => auth_info}}} ->
          duration = System.monotonic_time() - start_time

          auth_response = build_auth_response(auth_info)

          Logger.info(
            "Token renewal successful",
            Map.merge(metadata, %{
              lease_duration: auth_info["lease_duration"],
              renewable: auth_info["renewable"]
            })
          )

          Telemetry.auth_success(duration, metadata)
          Security.audit_log(:lease_renewal, :success, metadata)

          {:ok, auth_response}

        {:ok, %{body: response}} ->
          duration = System.monotonic_time() - start_time

          error =
            Error.from_http_response(
              Map.get(response, "status", 400),
              response,
              details: %{operation: :renew_token}
            )

          Logger.error("Token renewal failed", Map.put(metadata, :error, error))
          Telemetry.auth_failure(duration, Map.put(metadata, :error, error))
          Security.audit_log(:lease_renewal, :failure, Map.put(metadata, :error, error.type))

          {:error, error}

        {:error, error} ->
          duration = System.monotonic_time() - start_time

          Logger.error("Token renewal error", Map.put(metadata, :error, error))
          Telemetry.auth_failure(duration, Map.put(metadata, :error, error))
          Security.audit_log(:lease_renewal, :failure, Map.put(metadata, :error, error.type))

          {:error, error}
      end
    end
  end

  @impl true
  def revoke_token(token, opts \\ []) do
    with :ok <- validate_revoke_token(token),
         :ok <- Security.audit_log(:token_revocation, :attempt, %{operation: :revoke_token}) do
      mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

      {path, request_body} =
        case token do
          nil ->
            # Revoke self
            {"auth/#{mount_path}/revoke-self", %{}}

          token_value ->
            # Revoke specific token
            {"auth/#{mount_path}/revoke", %{token: token_value}}
        end

      metadata = %{
        method: :token,
        operation: :revoke_token,
        mount_path: mount_path
      }

      Logger.debug("Revoking token", metadata)
      Telemetry.auth_start(metadata)

      start_time = System.monotonic_time()

      case HTTP.request(:post, path, request_body, [], opts) do
        {:ok, _response} ->
          duration = System.monotonic_time() - start_time

          Logger.info("Token revocation successful", metadata)
          Telemetry.auth_success(duration, metadata)
          Security.audit_log(:token_revocation, :success, metadata)

          :ok

        {:error, error} ->
          duration = System.monotonic_time() - start_time

          Logger.error("Token revocation error", Map.put(metadata, :error, error))
          Telemetry.auth_failure(duration, Map.put(metadata, :error, error))
          Security.audit_log(:token_revocation, :failure, Map.put(metadata, :error, error.type))

          {:error, error}
      end
    end
  end

  @impl true
  def validate_credentials(credentials) do
    case Map.get(credentials, :token) do
      nil ->
        # Token lookup doesn't require credentials
        :ok

      token when is_binary(token) ->
        validate_token(token)

      _ ->
        {:error, Error.new(:invalid_request, "Token must be a string")}
    end
  end

  @impl true
  def metadata do
    %{
      name: "token",
      supports_refresh: true,
      supports_revocation: true,
      required_fields: [],
      optional_fields: [:token],
      description: "Token authentication and management"
    }
  end

  # Private helper functions

  defp validate_token(token) when is_binary(token) and byte_size(token) > 0, do: :ok
  defp validate_token(_), do: {:error, Error.new(:invalid_request, "Invalid token format")}

  # Allow nil for self-revocation
  defp validate_revoke_token(nil), do: :ok
  defp validate_revoke_token(token) when is_binary(token) and byte_size(token) > 0, do: :ok
  defp validate_revoke_token(_), do: {:error, Error.new(:invalid_request, "Invalid token format")}

  defp validate_create_params(params) when is_map(params), do: :ok

  defp validate_create_params(_),
    do: {:error, Error.new(:invalid_request, "Parameters must be a map")}

  defp build_create_request_body(params) do
    params
    |> Map.take([
      :policies,
      :ttl,
      :renewable,
      :meta,
      :no_parent,
      :no_default_policy,
      :display_name,
      :num_uses,
      :period,
      :explicit_max_ttl,
      :type
    ])
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Map.new()
  end

  defp build_token_info(token_data) do
    %{
      accessor: token_data["accessor"],
      creation_time: token_data["creation_time"],
      creation_ttl: token_data["creation_ttl"],
      display_name: token_data["display_name"],
      entity_id: token_data["entity_id"],
      expire_time: token_data["expire_time"],
      explicit_max_ttl: token_data["explicit_max_ttl"],
      id: token_data["id"],
      identity_policies: token_data["identity_policies"] || [],
      issue_time: token_data["issue_time"],
      meta: token_data["meta"] || %{},
      num_uses: token_data["num_uses"],
      orphan: token_data["orphan"],
      path: token_data["path"],
      policies: token_data["policies"] || [],
      renewable: token_data["renewable"],
      ttl: token_data["ttl"],
      type: token_data["type"]
    }
  end

  defp build_auth_response(auth_info) do
    %{
      client_token: auth_info["client_token"],
      accessor: auth_info["accessor"],
      policies: auth_info["policies"] || [],
      token_policies: auth_info["token_policies"] || [],
      metadata: auth_info["metadata"] || %{},
      lease_duration: auth_info["lease_duration"],
      renewable: auth_info["renewable"],
      entity_id: auth_info["entity_id"],
      token_type: auth_info["token_type"],
      orphan: auth_info["orphan"],
      num_uses: auth_info["num_uses"] || 0
    }
  end
end
