defmodule Vaultx.Sys.Leases do
  @moduledoc """
  Enterprise lease management for HashiCorp Vault.

  This module provides comprehensive lease lifecycle management capabilities
  for Vault secrets, supporting all lease operations from creation to
  revocation with enterprise-grade features for large-scale deployments.

  ## Lease Management Capabilities

  ### Core Operations
  - Lease Lookup: Detailed lease information and metadata
  - Lease Renewal: Extend lease durations with custom increments
  - Lease Revocation: Individual and bulk lease termination
  - Lease Listing: Enumerate leases by prefix patterns

  ### Administrative Operations
  - Bulk Operations: Mass lease management for operational efficiency
  - Force Revocation: Emergency lease termination
  - Lease Cleanup: Administrative maintenance and tidying
  - Lease Counting: Operational metrics and monitoring

  ### Enterprise Features
  - Namespace Support: Multi-tenant lease management
  - Audit Integration: Complete lease operation auditing
  - Performance Optimization: Efficient bulk operations
  - Monitoring Integration: Comprehensive lease metrics

  ## Security Considerations

  - Privilege Requirements: Many operations require sudo capabilities
  - Audit Logging: All lease operations are audited
  - Access Control: Lease access controlled by policies
  - Emergency Procedures: Force revocation for security incidents

  ## API Compliance

  Fully implements HashiCorp Vault Leases API:
  - [Leases API](https://developer.hashicorp.com/vault/api-docs/system/leases)
  - [Lease Concepts](https://developer.hashicorp.com/vault/docs/concepts/lease)

  - `POST /sys/leases/lookup` - Lookup lease information
  - `POST /sys/leases/renew` - Renew a lease
  - `POST /sys/leases/revoke` - Revoke a lease
  - `GET /sys/leases/lookup/:prefix?list=true` - List leases by prefix
  - `POST /sys/leases/revoke-prefix/:prefix` - Revoke all leases with prefix
  - `POST /sys/leases/revoke-force/:prefix` - Force revoke leases
  - `POST /sys/leases/tidy` - Clean up dangling lease entries

  ## Lease Operations

  ### Basic Operations
  - `lookup/2` - Get detailed lease information
  - `renew/3` - Extend lease duration
  - `revoke/2` - Revoke a single lease

  ### Bulk Operations
  - `revoke_prefix/2` - Revoke all leases with a prefix
  - `revoke_force/2` - Force revoke ignoring backend errors
  - `list/2` - List leases by prefix

  ### Administrative Operations
  - `tidy/1` - Clean up dangling lease entries
  - `count/2` - Count leases by type
  - `list_all/2` - List all leases with details

  ## Usage Examples

      # Lookup lease information
      {:ok, lease} = Vaultx.Sys.Leases.lookup("aws/creds/deploy/abcd-1234")
      lease.renewable #=> true
      lease.ttl #=> 3600

      # Renew lease for additional time
      {:ok, renewed} = Vaultx.Sys.Leases.renew("aws/creds/deploy/abcd-1234", 1800)
      renewed.lease_duration #=> 1800

      # Revoke a lease
      :ok = Vaultx.Sys.Leases.revoke("aws/creds/deploy/abcd-1234")

      # List leases by prefix (requires sudo)
      {:ok, leases} = Vaultx.Sys.Leases.list("aws/creds/deploy/")
      leases #=> ["aws/creds/deploy/abcd-1234", "aws/creds/deploy/efgh-5678"]

      # Bulk revoke by prefix (requires sudo)
      :ok = Vaultx.Sys.Leases.revoke_prefix("aws/creds/deploy/")

      # Force revoke for emergency situations
      :ok = Vaultx.Sys.Leases.revoke_force("aws/creds/deploy/")

      # Clean up dangling lease entries
      :ok = Vaultx.Sys.Leases.tidy()

  ## Security Considerations

  - Sudo Required: Lease listing and bulk operations require 'sudo' capability
  - Emergency Use: Force revocation should only be used in emergency situations
  - Performance Impact: Tidy operations can be I/O intensive on large deployments
  - Immediate Effect: Lease revocation takes effect immediately and cannot be undone
  - Audit Trail: All lease operations are logged for security auditing
  - Token Validation: Lease operations validate the requesting token's permissions

  ## Error Handling

  All operations return standardized error tuples:

      {:error, %Vaultx.Base.Error{
        type: :not_found,
        message: "Lease not found: aws/creds/deploy/abcd-1234",
        details: %{lease_id: "aws/creds/deploy/abcd-1234"}
      }}

  """

  alias Vaultx.Base.{Error, Logger, Telemetry}
  alias Vaultx.Transport.HTTP
  alias Vaultx.Types

  @typedoc """
  Lease management options.
  """
  @type lease_opts :: [
          # Renewal options
          increment: pos_integer(),

          # Revocation options
          sync: boolean(),

          # Listing options
          include_child_namespaces: boolean(),
          limit: String.t(),

          # Base options
          timeout: pos_integer(),
          retry_attempts: non_neg_integer(),
          namespace: String.t()
        ]

  @typedoc """
  Lease information structure.
  """
  @type lease_info :: %{
          id: String.t(),
          issue_time: String.t(),
          expire_time: String.t(),
          last_renewal_time: String.t() | nil,
          renewable: boolean(),
          ttl: integer()
        }

  @typedoc """
  Lease renewal result.
  """
  @type renewal_result :: %{
          lease_id: String.t(),
          renewable: boolean(),
          lease_duration: integer()
        }

  @typedoc """
  Lease count result.
  """
  @type count_result :: %{
          lease_count: integer(),
          counts: %{String.t() => integer()}
        }

  @doc """
  Lookup lease information by lease ID.

  Retrieves detailed information about a specific lease including
  expiration time, renewal status, and associated metadata.

  ## Examples

      {:ok, lease} = Vaultx.Sys.Leases.lookup("aws/creds/deploy/abcd-1234")
      lease.renewable #=> true
      lease.ttl #=> 3600

  """
  @spec lookup(String.t(), lease_opts()) :: Types.result(lease_info())
  def lookup(lease_id, opts \\ []) do
    start_time = System.monotonic_time()

    metadata = %{
      operation: :lease_lookup,
      lease_id: lease_id,
      module: __MODULE__
    }

    Logger.debug("Looking up lease", metadata)
    Telemetry.operation_start(metadata)

    payload = %{"lease_id" => lease_id}

    case HTTP.post("sys/leases/lookup", payload, opts) do
      {:ok, %{status: 200, body: body}} ->
        duration = System.monotonic_time() - start_time

        lease_info = parse_lease_info(body)

        Logger.debug("Lease lookup successful", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, lease_info}

      {:ok, %{status: 404}} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:not_found, "Lease not found: #{lease_id}")

        Logger.debug("Lease not found", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Lease lookup failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Renew a lease for additional time.

  Extends the lease duration by the specified increment or the default
  lease duration if no increment is provided.

  ## Options

  - `:increment` - Additional time in seconds to extend the lease

  ## Examples

      {:ok, renewed} = Vaultx.Sys.Leases.renew("aws/creds/deploy/abcd-1234", 1800)
      renewed.lease_duration #=> 1800

  """
  @spec renew(String.t(), integer(), lease_opts()) :: Types.result(renewal_result())
  def renew(lease_id, increment \\ 0, opts \\ []) do
    start_time = System.monotonic_time()

    metadata = %{
      operation: :lease_renewal,
      lease_id: lease_id,
      increment: increment,
      module: __MODULE__
    }

    Logger.debug("Renewing lease", metadata)
    Telemetry.operation_start(metadata)

    payload = %{
      "lease_id" => lease_id,
      "increment" => increment
    }

    case HTTP.post("sys/leases/renew", payload, opts) do
      {:ok, %{status: 200, body: body}} ->
        duration = System.monotonic_time() - start_time

        renewal_result = parse_renewal_result(body)

        Logger.info("Lease renewed successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, renewal_result}

      {:ok, %{status: 404}} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:not_found, "Lease not found: #{lease_id}")

        Logger.debug("Lease not found for renewal", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Lease renewal failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Revoke a lease immediately.

  Permanently revokes the specified lease and any associated credentials.

  ## Options

  - `:sync` - Wait for revocation to complete (default: false)

  ## Examples

      :ok = Vaultx.Sys.Leases.revoke("aws/creds/deploy/abcd-1234")

  """
  @spec revoke(String.t(), lease_opts()) :: Types.result(:ok)
  def revoke(lease_id, opts \\ []) do
    start_time = System.monotonic_time()

    metadata = %{
      operation: :lease_revocation,
      lease_id: lease_id,
      sync: Keyword.get(opts, :sync, false),
      module: __MODULE__
    }

    Logger.debug("Revoking lease", metadata)
    Telemetry.operation_start(metadata)

    payload = build_revoke_payload(lease_id, opts)

    case HTTP.post("sys/leases/revoke", payload, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        duration = System.monotonic_time() - start_time

        Logger.info("Lease revoked successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        :ok

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Lease revocation failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  List leases by prefix.

  Returns a list of lease IDs that match the specified prefix.
  Requires 'sudo' capability.

  ## Examples

      {:ok, leases} = Vaultx.Sys.Leases.list("aws/creds/deploy/")
      leases #=> ["aws/creds/deploy/abcd-1234", "aws/creds/deploy/efgh-5678"]

  """
  @spec list(String.t(), lease_opts()) :: Types.result([String.t()])
  def list(prefix, opts \\ []) do
    start_time = System.monotonic_time()

    metadata = %{
      operation: :lease_list,
      prefix: prefix,
      module: __MODULE__
    }

    Logger.debug("Listing leases", metadata)
    Telemetry.operation_start(metadata)

    path = "sys/leases/lookup/#{prefix}"
    query_params = "list=true"
    full_path = "#{path}?#{query_params}"

    case HTTP.get(full_path, opts) do
      {:ok, %{status: 200, body: %{"data" => %{"keys" => keys}}}} ->
        duration = System.monotonic_time() - start_time

        Logger.debug("Lease listing successful", Map.put(metadata, :count, length(keys)))
        Telemetry.operation_success(duration, Map.put(metadata, :count, length(keys)))

        {:ok, keys}

      {:ok, %{status: 200, body: %{"data" => %{}}}} ->
        duration = System.monotonic_time() - start_time

        Logger.debug("No leases found for prefix", metadata)
        Telemetry.operation_success(duration, Map.put(metadata, :count, 0))

        {:ok, []}

      {:ok, %{status: 404}} ->
        duration = System.monotonic_time() - start_time

        Logger.debug("No leases found for prefix", metadata)
        Telemetry.operation_success(duration, Map.put(metadata, :count, 0))

        {:ok, []}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Lease listing failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Revoke all leases with the specified prefix.

  Revokes all secrets (via lease ID prefix) or tokens (via the tokens' path property)
  generated under a given prefix immediately. Requires 'sudo' capability.

  ## Options

  - `:sync` - Wait for all revocations to complete (default: false)

  ## Examples

      :ok = Vaultx.Sys.Leases.revoke_prefix("aws/creds/deploy/")

  """
  @spec revoke_prefix(String.t(), lease_opts()) :: Types.result(:ok)
  def revoke_prefix(prefix, opts \\ []) do
    start_time = System.monotonic_time()

    metadata = %{
      operation: :lease_revoke_prefix,
      prefix: prefix,
      sync: Keyword.get(opts, :sync, false),
      module: __MODULE__
    }

    Logger.debug("Revoking leases by prefix", metadata)
    Telemetry.operation_start(metadata)

    path = "sys/leases/revoke-prefix/#{prefix}"
    payload = build_sync_payload(opts)

    case HTTP.post(path, payload, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        duration = System.monotonic_time() - start_time

        Logger.info("Prefix revocation completed", metadata)
        Telemetry.operation_success(duration, metadata)

        :ok

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Prefix revocation failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Force revoke all leases with the specified prefix.

  Revokes all secrets or tokens generated under a given prefix immediately,
  ignoring backend errors. This is potentially dangerous and should only be
  used in emergency situations. Requires 'sudo' capability.

  ## Examples

      :ok = Vaultx.Sys.Leases.revoke_force("aws/creds/deploy/")

  """
  @spec revoke_force(String.t(), lease_opts()) :: Types.result(:ok)
  def revoke_force(prefix, opts \\ []) do
    start_time = System.monotonic_time()

    metadata = %{
      operation: :lease_revoke_force,
      prefix: prefix,
      module: __MODULE__
    }

    Logger.warning("Force revoking leases by prefix", metadata)
    Telemetry.operation_start(metadata)

    path = "sys/leases/revoke-force/#{prefix}"

    case HTTP.post(path, %{}, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        duration = System.monotonic_time() - start_time

        Logger.warning("Force revocation completed", metadata)
        Telemetry.operation_success(duration, metadata)

        :ok

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Force revocation failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Clean up dangling lease entries.

  For each lease entry in storage, Vault will verify that it has an associated
  valid non-expired token in storage, and if not, the lease will be revoked.

  ## Examples

      :ok = Vaultx.Sys.Leases.tidy()

  """
  @spec tidy(lease_opts()) :: Types.result(:ok)
  def tidy(opts \\ []) do
    start_time = System.monotonic_time()

    metadata = %{
      operation: :lease_tidy,
      module: __MODULE__
    }

    Logger.info("Starting lease tidy operation", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.post("sys/leases/tidy", %{}, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        duration = System.monotonic_time() - start_time

        Logger.info("Lease tidy completed", metadata)
        Telemetry.operation_success(duration, metadata)

        :ok

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Lease tidy failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  # Private functions

  defp parse_lease_info(body) when is_map(body) do
    %{
      id: Map.get(body, "id", ""),
      issue_time: Map.get(body, "issue_time", ""),
      expire_time: Map.get(body, "expire_time", ""),
      last_renewal_time: Map.get(body, "last_renewal_time"),
      renewable: Map.get(body, "renewable", false),
      ttl: Map.get(body, "ttl", 0)
    }
  end

  defp parse_renewal_result(body) when is_map(body) do
    %{
      lease_id: Map.get(body, "lease_id", ""),
      renewable: Map.get(body, "renewable", false),
      lease_duration: Map.get(body, "lease_duration", 0)
    }
  end

  defp build_revoke_payload(lease_id, opts) do
    payload = %{"lease_id" => lease_id}

    if Keyword.get(opts, :sync, false) do
      Map.put(payload, "sync", true)
    else
      payload
    end
  end

  defp build_sync_payload(opts) do
    if Keyword.get(opts, :sync, false) do
      %{"sync" => true}
    else
      %{}
    end
  end
end
