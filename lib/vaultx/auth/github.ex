defmodule Vaultx.Auth.GitHub do
  @moduledoc """
  GitHub authentication method for HashiCorp Vault.

  This module implements the GitHub authentication method for Vault, providing
  secure authentication using GitHub personal access tokens with comprehensive
  support for organization membership, team-based policies, and user-specific
  permissions.

  ## Features

  - Token Authentication: GitHub personal access token-based authentication
  - Organization Membership: Verify users belong to configured GitHub organization
  - Team-Based Policies: Map GitHub teams to Vault policies
  - User-Specific Policies: Assign policies to individual GitHub users
  - Enterprise Support: Works with GitHub Enterprise Server
  - Audit Integration: Comprehensive audit logging for security compliance

  ## API Compliance

  Fully implements HashiCorp Vault GitHub authentication:
  - [GitHub Auth Method](https://developer.hashicorp.com/vault/api-docs/auth/github)
  - [GitHub Auth Configuration](https://developer.hashicorp.com/vault/docs/auth/github)

  ## Usage Examples

  ### Basic Authentication

      {:ok, auth_response} = Vaultx.Auth.GitHub.authenticate(%{
        token: "ghp_xxxxxxxxxxxxxxxxxxxx"
      })

  ### Authentication with Custom Mount Path

      {:ok, auth_response} = Vaultx.Auth.GitHub.authenticate(%{
        token: "ghp_xxxxxxxxxxxxxxxxxxxx"
      }, mount_path: "custom-github")

  ### Authentication with Additional Options

      {:ok, auth_response} = Vaultx.Auth.GitHub.authenticate(%{
        token: "ghp_xxxxxxxxxxxxxxxxxxxx"
      }, [
        mount_path: "github",
        timeout: 30_000,
        retry_attempts: 3
      ])

  ## Vault Configuration

  Before using this authentication method, configure it in Vault:

      # Enable GitHub auth method
      vault auth enable github

      # Configure GitHub organization
      vault write auth/github/config \\
        organization="my-org" \\
        base_url="https://api.github.com"

      # Map GitHub team to policies
      vault write auth/github/map/teams/dev \\
        value="dev-policy,default"

      # Map GitHub user to policies
      vault write auth/github/map/users/john-doe \\
        value="admin-policy,default"

  ## GitHub Token Requirements

  The GitHub personal access token must have the following permissions:
  - `read:org` - To verify organization membership
  - `read:user` - To read user information
  - `user:email` - To read user email (optional)

  ## Security Considerations

  - Use personal access tokens with minimal required scopes
  - Regularly rotate GitHub tokens
  - Monitor authentication events in Vault audit logs
  - Configure appropriate team and user mappings
  - Use least privilege principle for policy assignments
  - Consider token expiration policies
  """

  @behaviour Vaultx.Auth.Behaviour

  alias Vaultx.Base.{Error, Logger, Security, Telemetry}
  alias Vaultx.Transport.HTTP

  # Default mount path for GitHub auth method
  @default_mount_path "github"

  @impl true
  def authenticate(credentials, opts \\ []) do
    with :ok <- validate_credentials(credentials),
         :ok <- Security.audit_log(:authentication, :attempt, %{method: :github}) do
      mount_path = Keyword.get(opts, :mount_path, @default_mount_path)
      path = "auth/#{mount_path}/login"

      request_body = %{
        token: Map.get(credentials, :token)
      }

      metadata = %{
        method: :github,
        mount_path: mount_path
      }

      Logger.debug("Attempting GitHub authentication", metadata)
      Telemetry.auth_start(metadata)

      start_time = System.monotonic_time()

      case HTTP.request(:post, path, request_body, [], opts) do
        {:ok, %{body: %{"auth" => auth_info}}} ->
          duration = System.monotonic_time() - start_time

          auth_response = build_auth_response(auth_info)

          Logger.info(
            "GitHub authentication successful",
            Map.merge(metadata, %{
              username: auth_info["metadata"]["username"],
              org: auth_info["metadata"]["org"],
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
              details: %{auth_method: :github}
            )

          Logger.error("GitHub authentication failed", Map.put(metadata, :error, error))
          Telemetry.auth_failure(duration, Map.put(metadata, :error, error))
          Security.audit_log(:authentication, :failure, Map.put(metadata, :error, error.type))

          {:error, error}

        {:error, error} ->
          duration = System.monotonic_time() - start_time

          Logger.error("GitHub authentication error", Map.put(metadata, :error, error))
          Telemetry.auth_failure(duration, Map.put(metadata, :error, error))
          Security.audit_log(:authentication, :failure, Map.put(metadata, :error, error.type))

          {:error, error}
      end
    end
  end

  @impl true
  def validate_credentials(credentials) when is_map(credentials) do
    case Map.get(credentials, :token) do
      nil ->
        {:error, Error.new(:invalid_credentials, "GitHub token is required")}

      token when is_binary(token) ->
        if byte_size(token) == 0 do
          {:error, Error.new(:invalid_credentials, "GitHub token must be a non-empty string")}
        else
          if valid_github_token_format?(token) do
            :ok
          else
            {:error, Error.new(:invalid_credentials, "Invalid GitHub token format")}
          end
        end

      _ ->
        {:error, Error.new(:invalid_credentials, "GitHub token must be a non-empty string")}
    end
  end

  def validate_credentials(_) do
    {:error, Error.new(:invalid_credentials, "Credentials must be a map")}
  end

  @impl true
  def refresh_token(_token, _opts) do
    {:error, Error.new(:not_supported, "GitHub auth method does not support token refresh")}
  end

  @impl true
  def revoke_token(_token, _opts) do
    {:error, Error.new(:not_supported, "GitHub auth method does not support token revocation")}
  end

  @impl true
  def metadata do
    %{
      name: "GitHub Authentication",
      supports_refresh: false,
      supports_revocation: false,
      required_fields: [:token],
      optional_fields: [],
      description: "Authenticate using GitHub personal access tokens"
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

  defp valid_github_token_format?(token) do
    # GitHub personal access tokens have specific formats:
    # - Classic tokens (new format): ghp_xxxxxxxxxxxxxxxxxxxx (36 chars after ghp_, total 40 chars)
    # - Classic tokens (legacy): ghp_xxxxxxxxxxxxxxxxxxxx (40 chars after ghp_, total 44 chars)
    # - Fine-grained tokens: github_pat_xxxxxxxxxxxxxxxxxxxx
    # - OAuth tokens: gho_xxxxxxxxxxxxxxxxxxxx
    # - Installation tokens: ghs_xxxxxxxxxxxxxxxxxxxx
    # - Refresh tokens: ghr_xxxxxxxxxxxxxxxxxxxx
    cond do
      # New GitHub classic token format (2024+): ghp_ + 36 chars = 40 total
      String.starts_with?(token, "ghp_") and String.length(token) == 40 -> true
      # Legacy GitHub classic token format: ghp_ + 40 chars = 44 total (backward compatibility)
      String.starts_with?(token, "ghp_") and String.length(token) == 44 -> true
      String.starts_with?(token, "github_pat_") and String.length(token) >= 82 -> true
      String.starts_with?(token, "gho_") and String.length(token) == 40 -> true
      String.starts_with?(token, "ghs_") and String.length(token) == 40 -> true
      String.starts_with?(token, "ghr_") and String.length(token) == 40 -> true
      # Allow other formats for flexibility (e.g., GitHub Enterprise)
      # But require minimum length for security
      String.length(token) >= 20 and not String.starts_with?(token, "ghp_") -> true
      true -> false
    end
  end
end
