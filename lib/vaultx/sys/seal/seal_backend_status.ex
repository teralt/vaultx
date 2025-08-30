defmodule Vaultx.Sys.SealBackendStatus do
  @moduledoc """
  HashiCorp Vault seal backend status operations.

  This module provides seal backend health monitoring capabilities for Vault,
  allowing you to check the status and health of each backing seal mechanism.
  This is particularly useful for auto-seal configurations with multiple backends.

  ## Seal Backend Status Features

  ### Core Information
  - Overall Health: Global health status of all seal backends
  - Individual Backend Status: Health of each configured seal backend
  - Unhealthy Tracking: Timestamp tracking for unhealthy backends
  - Backend Names: Identification of each seal backend

  ### Health Monitoring
  - Real-time Status: Current health state of seal backends
  - Failure Detection: Identification of unhealthy backends
  - Timestamp Tracking: When backends became unhealthy
  - Comprehensive Coverage: Status for all configured backends

  ### Use Cases
  - Infrastructure Monitoring: Track seal backend health
  - Alerting Systems: Detect seal backend failures
  - Operational Visibility: Understand seal configuration status
  - Troubleshooting: Identify problematic seal backends

  ## Important Notes

  **Unauthenticated Endpoint**
  - No authentication required to check backend status
  - Safe to call from monitoring and health check systems
  - Provides operational visibility without exposing secrets

  **Auto-Seal Configurations**
  - Most relevant for auto-seal setups (HSM, Cloud KMS, etc.)
  - May show limited information for Shamir seal configurations
  - Backend health affects Vault's ability to unseal automatically

  **High Availability Considerations**
  - Backend status may vary across cluster nodes
  - Use for comprehensive cluster health monitoring
  - Consider backend redundancy in HA configurations

  ## API Compliance

  Fully implements HashiCorp Vault Seal Backend Status API:
  - [Seal Backend Status API](https://developer.hashicorp.com/vault/api-docs/system/seal-backend-status)
  - [Auto-Seal Documentation](https://developer.hashicorp.com/vault/docs/configuration/seal)

  ## Usage Examples

  ### Basic Backend Status Check

      {:ok, status} = Vaultx.Sys.SealBackendStatus.get()

      if status.healthy do
        IO.puts("All seal backends are healthy")
      else
        IO.puts("Some backends are unhealthy since: \#{status.unhealthy_since}")

        Enum.each(status.backends, fn backend ->
          if not backend.healthy do
            IO.puts("Backend \#{backend.name} is unhealthy")
          end
        end)
      end

  ### Monitoring Integration

      case Vaultx.Sys.SealBackendStatus.get() do
        {:ok, status} ->
          if not status.healthy do
            unhealthy_backends = Enum.filter(status.backends, & not &1.healthy)
            send_alert("Unhealthy seal backends: \#{inspect(unhealthy_backends)}")
          end
        {:error, _} ->
          send_alert("Cannot check seal backend status")
      end

  ### Individual Backend Check

      {:ok, backend_status} = Vaultx.Sys.SealBackendStatus.get_backend_status("hsm")

      if backend_status.healthy do
        IO.puts("HSM backend is healthy")
      else
        IO.puts("HSM backend unhealthy since: \#{backend_status.unhealthy_since}")
      end

  ## Status Information

  The seal backend status response includes:

  ### Overall Status
  - `healthy`: Boolean indicating if all backends are healthy
  - `unhealthy_since`: Timestamp when any backend became unhealthy (if applicable)
  - `backends`: List of individual backend status information

  ### Individual Backend Status
  - `name`: Name/identifier of the seal backend
  - `healthy`: Boolean indicating if this backend is healthy
  - `unhealthy_since`: Timestamp when this backend became unhealthy (if applicable)

  ## Common Backend Types

  ### Cloud KMS Backends
  - AWS KMS: Amazon Key Management Service
  - Azure Key Vault: Microsoft Azure Key Vault
  - GCP Cloud KMS: Google Cloud Key Management Service

  ### Hardware Security Modules
  - PKCS#11: Hardware security module integration
  - HSM: Various HSM implementations

  ### Transit Backends
  - Vault Transit: Another Vault instance as seal backend
  - External Transit: External transit encryption services
  """

  alias Vaultx.Base.{Error, Logger, Telemetry}
  alias Vaultx.Transport.HTTP
  alias Vaultx.Types

  @typedoc """
  Individual seal backend status information.
  """
  @type backend_status :: %{
          :name => String.t(),
          :healthy => boolean(),
          optional(:unhealthy_since) => String.t()
        }

  @typedoc """
  Overall seal backend status information.
  """
  @type seal_backend_status :: %{
          :healthy => boolean(),
          :backends => [backend_status()],
          optional(:unhealthy_since) => String.t()
        }

  @doc """
  Get the status of all seal backends.

  This endpoint returns the health status of each backing seal, namely whether
  each backend is healthy. This is an unauthenticated endpoint.

  ## Parameters

  - `opts` - Request options (optional)

  ## Returns

  Returns `{:ok, seal_backend_status()}` with backend status information,
  or `{:error, Error.t()}` on failure.

  ## Examples

      {:ok, status} = Vaultx.Sys.SealBackendStatus.get()

      IO.puts("Overall healthy: \#{status.healthy}")

      Enum.each(status.backends, fn backend ->
        health_status = if backend.healthy, do: "healthy", else: "unhealthy"
        IO.puts("Backend \#{backend.name}: \#{health_status}")
      end)

  """
  @spec get(Types.options()) :: {:ok, seal_backend_status()} | {:error, Error.t()}
  def get(opts \\ []) do
    path = "sys/seal-backend-status"

    metadata = %{operation: :get_seal_backend_status}
    Logger.debug("Getting seal backend status", metadata)
    Telemetry.operation_start(metadata)

    start_time = System.monotonic_time()

    case HTTP.get(path, opts) do
      {:ok, %{status: 200, body: body}} ->
        duration = System.monotonic_time() - start_time

        status = parse_seal_backend_status(body)

        Logger.info(
          "Successfully retrieved seal backend status",
          Map.merge(metadata, %{
            overall_healthy: status.healthy,
            backend_count: length(status.backends)
          })
        )

        Telemetry.operation_success(duration, metadata)

        {:ok, status}

      {:ok, %{status: status_code, body: body}} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:server_error, "Failed to get seal backend status: HTTP #{status_code}",
            details: %{status: status_code, body: body}
          )

        Logger.error("Failed to get seal backend status", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("Error getting seal backend status", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Check if all seal backends are healthy.

  This is a convenience function that returns a simple boolean
  indicating the overall health of all seal backends.

  ## Parameters

  - `opts` - Request options (optional)

  ## Returns

  Returns `{:ok, boolean()}` where true means all backends are healthy,
  or `{:error, Error.t()}` on failure.

  ## Examples

      case Vaultx.Sys.SealBackendStatus.all_healthy?() do
        {:ok, true} -> IO.puts("All seal backends are healthy")
        {:ok, false} -> IO.puts("Some seal backends are unhealthy")
        {:error, error} -> IO.puts("Error: \#{error.message}")
      end

  """
  @spec all_healthy?(Types.options()) :: {:ok, boolean()} | {:error, Error.t()}
  def all_healthy?(opts \\ []) do
    case get(opts) do
      {:ok, status} -> {:ok, status.healthy}
      {:error, error} -> {:error, error}
    end
  end

  @doc """
  Get the status of a specific seal backend by name.

  This function filters the backend status to return information
  about a specific named backend.

  ## Parameters

  - `backend_name` - Name of the backend to check
  - `opts` - Request options (optional)

  ## Returns

  Returns `{:ok, backend_status()}` for the specified backend,
  or `{:error, Error.t()}` if backend not found or on failure.

  ## Examples

      {:ok, hsm_status} = Vaultx.Sys.SealBackendStatus.get_backend_status("hsm")

      if hsm_status.healthy do
        IO.puts("HSM backend is healthy")
      else
        IO.puts("HSM backend is unhealthy since: \#{hsm_status.unhealthy_since}")
      end

  """
  @spec get_backend_status(String.t(), Types.options()) ::
          {:ok, backend_status()} | {:error, Error.t()}
  def get_backend_status(backend_name, opts \\ []) do
    case get(opts) do
      {:ok, status} ->
        case Enum.find(status.backends, &(&1.name == backend_name)) do
          nil ->
            error =
              Error.new(:not_found, "Seal backend '#{backend_name}' not found",
                details: %{
                  requested_backend: backend_name,
                  available_backends: Enum.map(status.backends, & &1.name)
                }
              )

            {:error, error}

          backend ->
            {:ok, backend}
        end

      {:error, error} ->
        {:error, error}
    end
  end

  @doc """
  Get a list of all configured seal backend names.

  This function returns just the names of all configured seal backends.

  ## Parameters

  - `opts` - Request options (optional)

  ## Returns

  Returns `{:ok, [String.t()]}` with list of backend names,
  or `{:error, Error.t()}` on failure.

  ## Examples

      {:ok, backend_names} = Vaultx.Sys.SealBackendStatus.list_backend_names()
      IO.puts("Configured backends: \#{Enum.join(backend_names, ", ")}")

  """
  @spec list_backend_names(Types.options()) :: {:ok, [String.t()]} | {:error, Error.t()}
  def list_backend_names(opts \\ []) do
    case get(opts) do
      {:ok, status} ->
        backend_names = Enum.map(status.backends, & &1.name)
        {:ok, backend_names}

      {:error, error} ->
        {:error, error}
    end
  end

  @doc """
  Get a list of unhealthy seal backends.

  This function filters and returns only the backends that are currently unhealthy.

  ## Parameters

  - `opts` - Request options (optional)

  ## Returns

  Returns `{:ok, [backend_status()]}` with list of unhealthy backends,
  or `{:error, Error.t()}` on failure.

  ## Examples

      {:ok, unhealthy_backends} = Vaultx.Sys.SealBackendStatus.get_unhealthy_backends()

      if Enum.empty?(unhealthy_backends) do
        IO.puts("All backends are healthy")
      else
        Enum.each(unhealthy_backends, fn backend ->
          IO.puts("Unhealthy: \#{backend.name} since \#{backend.unhealthy_since}")
        end)
      end

  """
  @spec get_unhealthy_backends(Types.options()) :: {:ok, [backend_status()]} | {:error, Error.t()}
  def get_unhealthy_backends(opts \\ []) do
    case get(opts) do
      {:ok, status} ->
        unhealthy_backends = Enum.filter(status.backends, &(not &1.healthy))
        {:ok, unhealthy_backends}

      {:error, error} ->
        {:error, error}
    end
  end

  # Private helper functions

  defp parse_seal_backend_status(body) when is_map(body) do
    backends =
      case body["backends"] do
        backends_list when is_list(backends_list) ->
          Enum.map(backends_list, &parse_backend_status/1)

        _ ->
          []
      end

    %{
      healthy: body["healthy"],
      backends: backends
    }
    |> maybe_add_unhealthy_since(body)
  end

  defp parse_seal_backend_status(_body) do
    # Handle malformed response by returning minimal valid structure
    %{
      healthy: true,
      backends: []
    }
  end

  defp parse_backend_status(backend_data) do
    %{
      name: backend_data["name"],
      healthy: backend_data["healthy"]
    }
    |> maybe_add_backend_unhealthy_since(backend_data)
  end

  defp maybe_add_unhealthy_since(status, body) do
    case body["unhealthy_since"] do
      nil -> status
      timestamp -> Map.put(status, :unhealthy_since, timestamp)
    end
  end

  defp maybe_add_backend_unhealthy_since(backend, backend_data) do
    case backend_data["unhealthy_since"] do
      nil -> backend
      timestamp -> Map.put(backend, :unhealthy_since, timestamp)
    end
  end
end
