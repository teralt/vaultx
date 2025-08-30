defmodule Vaultx.Secrets.AWS.Credentials do
  @moduledoc """
  AWS credential generation and management for HashiCorp Vault AWS secrets engine.

  This module provides comprehensive credential generation functionality for AWS
  secrets engine, supporting all credential types including IAM users, assumed
  roles, federation tokens, and session tokens. It implements enterprise-grade
  security practices and follows AWS best practices for credential management.

  ## Credential Generation Capabilities

  ### Dynamic Credential Types
  - IAM User Credentials: Temporary IAM users with attached policies
  - Assumed Role Credentials: STS credentials via role assumption
  - Federation Token Credentials: Federated user credentials with policies
  - Session Token Credentials: Temporary session tokens with MFA support

  ### Static Credential Management
  - Static Role Credentials: Managed credentials for existing IAM users
  - Automatic Rotation: Configurable rotation periods
  - Cross-Account Access: Credentials across AWS accounts

  ## Security Features

  - Least Privilege Access: Minimal required permissions
  - Time-Limited Credentials: Configurable TTL for all credential types
  - MFA Support: Multi-factor authentication for session tokens
  - Audit Trail: Complete credential generation logging
  - Policy Enforcement: Strict policy validation and application

  ## API Compliance

  Fully implements HashiCorp Vault AWS credential generation:
  - [AWS Credential Generation](https://developer.hashicorp.com/vault/api-docs/secret/aws#generate-credentials)
  - [AWS Static Credentials](https://developer.hashicorp.com/vault/api-docs/secret/aws#get-static-credentials)
  - [AWS STS Integration](https://docs.aws.amazon.com/STS/latest/APIReference/)

  ## Usage Examples

      # Generate dynamic credentials
      {:ok, creds} = Credentials.generate("my-role", mount_path: "aws")

      # Generate credentials with custom TTL
      {:ok, creds} = Credentials.generate("my-role", ttl: "1h", mount_path: "aws")

      # Generate assumed role credentials
      {:ok, creds} = Credentials.generate("my-role",
        role_arn: "arn:aws:iam::123456789012:role/MyRole",
        role_session_name: "vault-session"
      )

      # Get static credentials
      {:ok, static_creds} = Credentials.get_static("my-static-role")

  ## Configuration

      config :vaultx, :aws,
        mount_path: "aws",
        default_ttl: "1h",
        max_ttl: "24h"

  """

  alias Vaultx.Base.{Error, Logger, Telemetry}
  alias Vaultx.Secrets.AWS.Behaviour
  alias Vaultx.Transport.HTTP

  @default_mount_path "aws"

  @typedoc """
  Credential generation options.
  """
  @type generate_opts :: [
          mount_path: String.t(),
          role_arn: String.t(),
          role_session_name: String.t(),
          ttl: String.t(),
          mfa_code: String.t(),
          timeout: pos_integer(),
          retry_attempts: non_neg_integer()
        ]

  @doc """
  Generate dynamic credentials for the specified role.

  This function generates AWS credentials based on the role configuration.
  The type of credentials generated depends on the role's credential_type:
  - `iam_user`: Creates temporary IAM user with attached policies
  - `assumed_role`: Generates STS credentials by assuming specified role
  - `federation_token`: Creates federated user credentials
  - `session_token`: Generates temporary session tokens

  ## Parameters

  - `role_name` - Name of the configured role
  - `opts` - Generation options (see `t:generate_opts/0`)

  ## Returns

  - `{:ok, credentials}` - Successfully generated credentials
  - `{:error, error}` - Generation failed

  ## Examples

      # Basic credential generation
      {:ok, creds} = Credentials.generate("my-role")
      %{
        access_key: "AKIA...",
        secret_key: "...",
        session_token: nil,
        arn: "arn:aws:iam::123456789012:user/vault-user-...",
        expiration: nil
      }

      # Assumed role with custom session name
      {:ok, creds} = Credentials.generate("assume-role",
        role_arn: "arn:aws:iam::123456789012:role/MyRole",
        role_session_name: "my-session",
        ttl: "2h"
      )

  """
  @spec generate(String.t(), generate_opts()) ::
          {:ok, Behaviour.credentials_result()} | {:error, Error.t()}
  def generate(role_name, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    telemetry_metadata = %{
      operation: :generate_credentials,
      role_name: role_name,
      mount_path: mount_path
    }

    Telemetry.operation_start(telemetry_metadata)
    start_time = System.monotonic_time()

    Logger.info("Generating AWS credentials", %{
      role_name: role_name,
      mount_path: mount_path,
      ttl: Keyword.get(opts, :ttl)
    })

    with {:ok, response} <- make_credential_request(role_name, opts, mount_path) do
      credentials = parse_credentials_response(response)

      Logger.info("Successfully generated AWS credentials", %{
        role_name: role_name,
        credential_type: detect_credential_type(credentials)
      })

      duration = System.monotonic_time() - start_time

      Telemetry.operation_success(
        duration,
        Map.merge(telemetry_metadata, %{
          credential_type: detect_credential_type(credentials)
        })
      )

      {:ok, credentials}
    else
      {:error, error} ->
        Logger.error("Failed to generate AWS credentials", %{
          role_name: role_name,
          error: error
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}
    end
  end

  @doc """
  Get static credentials for the specified static role.

  Static roles provide managed credentials for existing IAM users with
  automatic rotation capabilities.

  ## Parameters

  - `role_name` - Name of the configured static role
  - `opts` - Request options

  ## Returns

  - `{:ok, credentials}` - Current static credentials
  - `{:error, error}` - Request failed

  ## Examples

      {:ok, creds} = Credentials.get_static("my-static-role")
      %{
        access_key: "AKIA...",
        secret_key: "...",
        expiration: "2025-08-30T23:59:59Z"
      }

  """
  @spec get_static(String.t(), Keyword.t()) ::
          {:ok, Behaviour.credentials_result()} | {:error, Error.t()}
  def get_static(role_name, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    telemetry_metadata = %{
      operation: :get_static_credentials,
      role_name: role_name,
      mount_path: mount_path
    }

    Telemetry.operation_start(telemetry_metadata)
    start_time = System.monotonic_time()

    Logger.info("Retrieving static AWS credentials", %{
      role_name: role_name,
      mount_path: mount_path
    })

    path = "/#{mount_path}/static-creds/#{role_name}"

    case HTTP.get(path, opts) do
      {:ok, %{status: 200, body: body}} ->
        credentials = parse_static_credentials_response(body)

        Logger.info("Successfully retrieved static AWS credentials", %{
          role_name: role_name
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_success(duration, telemetry_metadata)
        {:ok, credentials}

      {:ok, response} ->
        error = Error.from_http_response(response.status, response.body)

        Logger.error("Failed to retrieve static AWS credentials", %{
          role_name: role_name,
          error: error
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}

      {:error, reason} ->
        error = Error.new(:http_error, "HTTP request failed", details: %{reason: reason})

        Logger.error("HTTP error retrieving static AWS credentials", %{
          role_name: role_name,
          error: error
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}
    end
  end

  # Private Functions

  defp make_credential_request(role_name, opts, mount_path) do
    # Determine the appropriate endpoint based on credential type
    base_path = determine_credential_path(role_name, opts, mount_path)
    query_params = build_query_params(opts)

    # Build full path with query parameters
    path =
      if Enum.empty?(query_params) do
        base_path
      else
        query_string =
          query_params
          |> Enum.map(fn {k, v} -> "#{k}=#{URI.encode_www_form(v)}" end)
          |> Enum.join("&")

        "#{base_path}?#{query_string}"
      end

    case HTTP.get(path, opts) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, body}

      {:ok, response} ->
        {:error, Error.from_http_response(response.status, response.body)}

      {:error, reason} ->
        {:error, Error.new(:http_error, "HTTP request failed", details: %{reason: reason})}
    end
  end

  defp determine_credential_path(role_name, opts, mount_path) do
    # Use /aws/sts for STS-based credentials, /aws/creds for IAM users
    case Keyword.get(opts, :credential_type) do
      type when type in ["assumed_role", "federation_token", "session_token"] ->
        "/#{mount_path}/sts/#{role_name}"

      _ ->
        "/#{mount_path}/creds/#{role_name}"
    end
  end

  defp build_query_params(opts) do
    opts
    |> Keyword.take([:role_arn, :role_session_name, :ttl, :mfa_code])
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Enum.map(fn {k, v} -> {to_string(k), to_string(v)} end)
  end

  defp parse_credentials_response(%{"data" => data}) do
    %{
      access_key: Map.get(data, "access_key"),
      secret_key: Map.get(data, "secret_key"),
      session_token: Map.get(data, "session_token"),
      arn: Map.get(data, "arn"),
      expiration: Map.get(data, "expiration")
    }
  end

  defp parse_static_credentials_response(%{"data" => data}) do
    %{
      access_key: Map.get(data, "access_key"),
      secret_key: Map.get(data, "secret_key"),
      expiration: Map.get(data, "expiration")
    }
  end

  defp parse_static_credentials_response(data) when is_map(data) do
    %{
      access_key: Map.get(data, "access_key"),
      secret_key: Map.get(data, "secret_key"),
      expiration: Map.get(data, "expiration")
    }
  end

  @doc false
  def detect_credential_type(%{session_token: nil}), do: "iam_user"
  def detect_credential_type(%{session_token: _}), do: "sts_credential"
  def detect_credential_type(_), do: "unknown"
end
