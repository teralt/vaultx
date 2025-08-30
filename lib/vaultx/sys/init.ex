defmodule Vaultx.Sys.Init do
  @moduledoc """
  HashiCorp Vault initialization operations.

  This module provides initialization capabilities for Vault, allowing you to
  initialize a new Vault server and generate the initial root token and unseal keys.
  Vault must be initialized before it can be unsealed and used.

  ## Initialization Operations

  ### Core Functionality
  - Initialize Vault: Set up a new Vault server with root token and unseal keys
  - Check Status: Determine if Vault has been initialized
  - Shamir Secret Sharing: Configure threshold-based unsealing
  - PGP Encryption: Encrypt unseal keys and root token with PGP keys

  ### Initialization Process
  - One-time Operation: Can only be performed once per Vault server
  - Root Token Generation: Creates the initial root token for administration
  - Unseal Key Generation: Creates key shares for unsealing Vault
  - Threshold Configuration: Sets minimum number of keys required to unseal

  ## Important Security Notes

  **Critical Security Considerations**
  - Initialization is a one-time operation that cannot be repeated
  - Root token has unlimited privileges and should be secured immediately
  - Unseal keys should be distributed among trusted operators
  - Consider using PGP encryption for key protection

  **Key Management**
  - Store unseal keys securely and separately
  - Distribute keys among multiple trusted operators
  - Consider using auto-unseal mechanisms for production
  - Revoke and regenerate root token after initial setup

  ## API Compliance

  Fully implements HashiCorp Vault Init API:
  - [Init API](https://developer.hashicorp.com/vault/api-docs/system/init)
  - [Vault Concepts](https://developer.hashicorp.com/vault/docs/concepts/seal)

  ## Usage Examples

  ### Basic Initialization

      {:ok, init_result} = Vaultx.Sys.Init.initialize(%{
        secret_shares: 5,
        secret_threshold: 3
      })

      # Store these securely!
      root_token = init_result.root_token
      unseal_keys = init_result.keys

  ### PGP-Encrypted Initialization

      pgp_keys = [
        "-----BEGIN PGP PUBLIC KEY BLOCK-----...",
        "-----BEGIN PGP PUBLIC KEY BLOCK-----..."
      ]

      {:ok, init_result} = Vaultx.Sys.Init.initialize(%{
        secret_shares: 3,
        secret_threshold: 2,
        pgp_keys: pgp_keys,
        root_token_pgp_key: "-----BEGIN PGP PUBLIC KEY BLOCK-----..."
      })

  ### Check Initialization Status

      case Vaultx.Sys.Init.status() do
        {:ok, %{initialized: true}} ->
          IO.puts("Vault is already initialized")
        {:ok, %{initialized: false}} ->
          IO.puts("Vault needs to be initialized")
        {:error, error} ->
          \IO.puts("Error checking status: \#{error.message}")
      end

  ## Initialization Response

  The initialization operation returns:

  - `keys`: Array of unseal key shares (encrypted if PGP keys provided)
  - `keys_base64`: Base64-encoded unseal keys
  - `root_token`: Initial root token (encrypted if PGP key provided)
  - `recovery_keys`: Recovery keys (for auto-unseal configurations)
  - `recovery_keys_base64`: Base64-encoded recovery keys

  ## Security Best Practices

  ### Immediate Actions After Initialization
  1. Securely store the root token and unseal keys
  2. Distribute unseal keys among trusted operators
  3. Unseal Vault using the required threshold of keys
  4. Create initial policies and authentication methods
  5. Revoke the initial root token and use policy-based access

  ### Production Considerations
  - Use auto-unseal mechanisms (Cloud KMS, HSM) when possible
  - Implement proper key rotation procedures
  - Monitor and audit all initialization activities
  - Use PGP encryption for additional key protection
  """

  alias Vaultx.Base.{Error, Logger, Telemetry}
  alias Vaultx.Transport.HTTP
  alias Vaultx.Types

  @typedoc """
  Initialization options.
  """
  @type init_opts :: %{
          :secret_shares => pos_integer(),
          :secret_threshold => pos_integer(),
          optional(:pgp_keys) => [String.t()],
          optional(:root_token_pgp_key) => String.t(),
          optional(:stored_shares) => pos_integer(),
          optional(:recovery_shares) => pos_integer(),
          optional(:recovery_threshold) => pos_integer(),
          optional(:recovery_pgp_keys) => [String.t()]
        }

  @typedoc """
  Initialization result.
  """
  @type init_result :: %{
          :keys => [String.t()],
          :keys_base64 => [String.t()],
          :root_token => String.t(),
          optional(:recovery_keys) => [String.t()],
          optional(:recovery_keys_base64) => [String.t()]
        }

  @typedoc """
  Initialization status.
  """
  @type init_status :: %{
          :initialized => boolean()
        }

  @doc """
  Initialize a new Vault server.

  This endpoint initializes a new Vault. The Vault must not have been previously
  initialized. The recovery options, as well as the stored shares option, are only
  available when using Vault Enterprise.

  ## Parameters

  - `opts` - Initialization options
    - `:secret_shares` - Number of shares to split the root key into (required)
    - `:secret_threshold` - Number of shares required to reconstruct the root key (required)
    - `:pgp_keys` - Array of PGP public keys to encrypt the unseal keys
    - `:root_token_pgp_key` - PGP public key to encrypt the root token
    - `:stored_shares` - Number of shares that should be encrypted and stored (Enterprise)
    - `:recovery_shares` - Number of recovery shares (Enterprise)
    - `:recovery_threshold` - Number of recovery shares required (Enterprise)
    - `:recovery_pgp_keys` - PGP keys for recovery shares (Enterprise)

  ## Returns

  Returns `{:ok, init_result()}` with initialization data,
  or `{:error, Error.t()}` on failure.

  ## Examples

      # Basic initialization
      {:ok, result} = Vaultx.Sys.Init.initialize(%{
        secret_shares: 5,
        secret_threshold: 3
      })

      # With PGP encryption
      {:ok, result} = Vaultx.Sys.Init.initialize(%{
        secret_shares: 3,
        secret_threshold: 2,
        pgp_keys: ["-----BEGIN PGP PUBLIC KEY BLOCK-----..."],
        root_token_pgp_key: "-----BEGIN PGP PUBLIC KEY BLOCK-----..."
      })

  ## Important Notes

  - This operation can only be performed once per Vault server
  - Store the returned keys and root token securely
  - Distribute unseal keys among trusted operators
  - Consider using PGP encryption for additional security

  """
  @spec initialize(init_opts(), Types.options()) :: {:ok, init_result()} | {:error, Error.t()}
  def initialize(opts, request_opts \\ []) when is_map(opts) do
    path = "sys/init"

    with :ok <- validate_init_opts(opts) do
      request_body = build_init_request(opts)

      metadata = %{
        operation: :initialize_vault,
        secret_shares: Map.get(opts, :secret_shares),
        secret_threshold: Map.get(opts, :secret_threshold),
        has_pgp_keys: Map.has_key?(opts, :pgp_keys),
        has_root_token_pgp: Map.has_key?(opts, :root_token_pgp_key)
      }

      Logger.debug("Initializing Vault", metadata)
      Telemetry.operation_start(metadata)

      start_time = System.monotonic_time()

      case HTTP.post(path, request_body, request_opts) do
        {:ok, %{status: 200, body: body}} ->
          duration = System.monotonic_time() - start_time

          result = parse_init_result(body)

          Logger.info("Successfully initialized Vault", metadata)
          Telemetry.operation_success(duration, metadata)

          {:ok, result}

        {:ok, %{status: status, body: body}} ->
          duration = System.monotonic_time() - start_time

          error =
            Error.new(:server_error, "Failed to initialize Vault: HTTP #{status}",
              details: %{status: status, body: body}
            )

          Logger.error("Failed to initialize Vault", Map.put(metadata, :error, error))
          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}

        {:error, error} ->
          duration = System.monotonic_time() - start_time

          Logger.error("Error initializing Vault", Map.put(metadata, :error, error))
          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}
      end
    end
  end

  @doc """
  Check the initialization status of Vault.

  This endpoint returns the initialization status of Vault. It returns a 200
  response if Vault is initialized and a 200 response if Vault is not initialized.

  ## Parameters

  - `opts` - Request options (optional)

  ## Returns

  Returns `{:ok, init_status()}` with initialization status,
  or `{:error, Error.t()}` on failure.

  ## Examples

      {:ok, status} = Vaultx.Sys.Init.status()

      if status.initialized do
        IO.puts("Vault is initialized")
      else
        IO.puts("Vault needs initialization")
      end

  """
  @spec status(Types.options()) :: {:ok, init_status()} | {:error, Error.t()}
  def status(opts \\ []) do
    path = "sys/init"

    metadata = %{operation: :check_init_status}
    Logger.debug("Checking Vault initialization status", metadata)
    Telemetry.operation_start(metadata)

    start_time = System.monotonic_time()

    case HTTP.get(path, opts) do
      {:ok, %{status: 200, body: body}} ->
        duration = System.monotonic_time() - start_time

        status = parse_init_status(body)

        Logger.debug(
          "Retrieved Vault initialization status",
          Map.put(metadata, :initialized, status.initialized)
        )

        Telemetry.operation_success(duration, metadata)

        {:ok, status}

      {:ok, %{status: status_code, body: body}} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:server_error, "Failed to check initialization status: HTTP #{status_code}",
            details: %{status: status_code, body: body}
          )

        Logger.error("Failed to check initialization status", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Error checking initialization status", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  # Private helper functions

  defp validate_init_opts(opts) do
    with :ok <- validate_required_fields(opts),
         :ok <- validate_threshold(opts),
         :ok <- validate_pgp_keys(opts) do
      :ok
    end
  end

  defp validate_required_fields(opts) do
    required_fields = [:secret_shares, :secret_threshold]

    missing_fields =
      required_fields
      |> Enum.filter(&(not Map.has_key?(opts, &1)))

    if missing_fields == [] do
      :ok
    else
      {:error,
       Error.new(:invalid_parameter, "Missing required fields: #{inspect(missing_fields)}",
         details: %{missing_fields: missing_fields, provided: Map.keys(opts)}
       )}
    end
  end

  defp validate_threshold(opts) do
    shares = Map.get(opts, :secret_shares, 0)
    threshold = Map.get(opts, :secret_threshold, 0)

    cond do
      shares < 1 ->
        {:error,
         Error.new(:invalid_parameter, "secret_shares must be at least 1",
           details: %{secret_shares: shares}
         )}

      threshold < 1 ->
        {:error,
         Error.new(:invalid_parameter, "secret_threshold must be at least 1",
           details: %{secret_threshold: threshold}
         )}

      threshold > shares ->
        {:error,
         Error.new(:invalid_parameter, "secret_threshold cannot exceed secret_shares",
           details: %{secret_shares: shares, secret_threshold: threshold}
         )}

      true ->
        :ok
    end
  end

  defp validate_pgp_keys(opts) do
    case Map.get(opts, :pgp_keys) do
      nil ->
        :ok

      keys when is_list(keys) ->
        shares = Map.get(opts, :secret_shares, 0)

        if length(keys) == shares do
          :ok
        else
          {:error,
           Error.new(:invalid_parameter, "Number of PGP keys must match secret_shares",
             details: %{pgp_keys_count: length(keys), secret_shares: shares}
           )}
        end

      _ ->
        {:error,
         Error.new(:invalid_parameter, "pgp_keys must be a list of strings",
           details: %{pgp_keys: Map.get(opts, :pgp_keys)}
         )}
    end
  end

  defp build_init_request(opts) do
    base_request = %{
      secret_shares: Map.fetch!(opts, :secret_shares),
      secret_threshold: Map.fetch!(opts, :secret_threshold)
    }

    opts
    |> Enum.reduce(base_request, fn {key, value}, acc ->
      case key do
        :secret_shares -> acc
        :secret_threshold -> acc
        _ -> Map.put(acc, key, value)
      end
    end)
  end

  defp parse_init_result(body) do
    %{
      keys: Map.get(body, "keys", []),
      keys_base64: Map.get(body, "keys_base64", []),
      root_token: Map.get(body, "root_token", "")
    }
    |> maybe_add_recovery_keys(body)
  end

  defp maybe_add_recovery_keys(result, body) do
    result
    |> maybe_put(:recovery_keys, Map.get(body, "recovery_keys"))
    |> maybe_put(:recovery_keys_base64, Map.get(body, "recovery_keys_base64"))
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp parse_init_status(body) do
    %{
      initialized: Map.get(body, "initialized", false) || false
    }
  end
end
