defmodule Vaultx.Base.Telemetry do
  @moduledoc """
  Enterprise observability and telemetry for Vaultx HashiCorp Vault client.

  This module provides comprehensive telemetry capabilities for monitoring
  Vault operations, performance metrics, and operational insights. It integrates
  seamlessly with Elixir's Telemetry ecosystem and can be completely disabled
  for maximum performance when observability is not required.

  ## Core Capabilities

  - Optional: Can be completely disabled via configuration
  - Zero Overhead: When disabled, all functions become no-ops
  - Comprehensive Events: Covers all major Vaultx operations
  - Structured Metadata: Rich context for monitoring and debugging
  - Performance Metrics: Duration, success/failure rates, and more

  ## Event Structure

  All events follow the pattern `[:vaultx, :operation, :event_type]`:

  - `[:vaultx, :http, :request, :start]` - HTTP request started
  - `[:vaultx, :http, :request, :stop]` - HTTP request completed
  - `[:vaultx, :auth, :start]` - Authentication started
  - `[:vaultx, :auth, :stop]` - Authentication completed
  - `[:vaultx, :secret, :read, :start]` - Secret read started
  - `[:vaultx, :secret, :read, :stop]` - Secret read completed
  - `[:vaultx, :secret, :write, :start]` - Secret write started
  - `[:vaultx, :secret, :write, :stop]` - Secret write completed

  ## Measurements

  - `:duration` - Operation duration in native time units
  - `:monotonic_time` - Monotonic time when event occurred
  - `:system_time` - System time when event occurred

  ## Metadata

  - `:operation` - The operation being performed
  - `:path` - Vault path being accessed
  - `:method` - HTTP method used
  - `:status` - HTTP status code (for stop events)
  - `:error` - Error information (for failed operations)

  ## Usage

      # Attach a handler for all HTTP events
      :ok = Vaultx.Base.Telemetry.attach(
        "my-http-handler",
        [[:vaultx, :http, :request, :start], [:vaultx, :http, :request, :stop]],
        &MyApp.TelemetryHandler.handle_event/4,
        %{}
      )

      # Use span for automatic start/stop events
      result = Vaultx.Base.Telemetry.span(
        [:operation, :read],
        %{path: "secret/myapp/config"},
        fn ->
          # Your operation here
          {:ok, %{"key" => "value"}}
        end
      )

  ## Configuration

      # Enable/disable telemetry
      config :vaultx, telemetry_enabled: true

      # Or via environment variable
      export VAULTX_TELEMETRY_ENABLED=true

  ## References

  - [Telemetry Library](https://hexdocs.pm/telemetry/) - Elixir telemetry system
  - [Vault Telemetry](https://developer.hashicorp.com/vault/docs/internals/telemetry) - Vault telemetry concepts

  """

  alias Vaultx.Base.Config

  @doc """
  Checks if telemetry is enabled.

  ## Examples

      iex> Vaultx.Base.Telemetry.enabled?()
      true

  """
  @spec enabled?() :: boolean()
  def enabled? do
    Config.feature_enabled?(:telemetry)
  end

  @doc """
  Checks if the telemetry library is available.

  ## Examples

      iex> Vaultx.Base.Telemetry.telemetry_available?()
      true

  """
  @spec telemetry_available?() :: boolean()
  def telemetry_available? do
    Code.ensure_loaded?(:telemetry)
  end

  @doc """
  Executes a Telemetry event if telemetry is enabled.

  This is a no-op when telemetry is disabled, providing zero overhead.

  ## Examples

      iex> Vaultx.Base.Telemetry.execute([:http, :request, :start], %{system_time: System.system_time()})
      :ok

  """
  @spec execute(list(atom()), map(), map()) :: :ok
  def execute(event_name, measurements, metadata \\ %{}) do
    if enabled?() and telemetry_available?() do
      :telemetry.execute([:vaultx | event_name], measurements, metadata)
    end

    :ok
  end

  @doc """
  Executes a span with automatic start/stop events if telemetry is enabled.

  When telemetry is disabled, this simply executes the function without
  emitting any events, providing zero overhead.

  ## Examples

      iex> result = Vaultx.Base.Telemetry.span([:operation, :read], %{path: "secret/test"}, fn ->
      ...>   {:ok, %{"key" => "value"}}
      ...> end)
      iex> result
      {:ok, %{"key" => "value"}}

  """
  @spec span(list(atom()), map(), function()) :: term()
  def span(event_name, metadata, fun) do
    if enabled?() and telemetry_available?() do
      :telemetry.span([:vaultx | event_name], metadata, fun)
    else
      # Execute function directly without telemetry overhead
      case fun.() do
        {result, _metadata} -> result
        result -> result
      end
    end
  end

  @doc """
  Measures the execution time of a function and emits telemetry events.

  This is a convenience function that combines start/stop events with duration measurement.

  ## Examples

      iex> result = Vaultx.Base.Telemetry.measure([:http, :request], %{method: :get}, fn ->
      ...>   # Perform HTTP request
      ...>   {:ok, %{status: 200}}
      ...> end)
      iex> result
      {:ok, %{status: 200}}

  """
  @spec measure(list(atom()), map(), function()) :: term()
  def measure(event_name, metadata, fun) do
    if enabled?() and telemetry_available?() do
      start_time = System.monotonic_time()
      start_metadata = Map.put(metadata, :monotonic_time, start_time)

      execute(event_name ++ [:start], %{system_time: System.system_time()}, start_metadata)

      try do
        result = fun.()
        duration = System.monotonic_time() - start_time

        stop_metadata =
          metadata
          |> Map.put(:duration, duration)
          |> Map.put(:result, :ok)

        execute(event_name ++ [:stop], %{duration: duration}, stop_metadata)

        result
      rescue
        error ->
          duration = System.monotonic_time() - start_time

          stop_metadata =
            metadata
            |> Map.put(:duration, duration)
            |> Map.put(:result, :error)
            |> Map.put(:error, error)

          execute(event_name ++ [:stop], %{duration: duration}, stop_metadata)

          reraise error, __STACKTRACE__
      end
    else
      fun.()
    end
  end

  @doc """
  Attaches a telemetry handler.

  This is a convenience wrapper around `:telemetry.attach/4`.

  ## Examples

      iex> :ok = Vaultx.Base.Telemetry.attach(
      ...>   "my-handler",
      ...>   [[:vaultx, :http, :request, :stop]],
      ...>   &MyHandler.handle_event/4,
      ...>   %{}
      ...> )

  """
  @spec attach(String.t(), [atom()] | [[atom()]], (... -> any()), map()) :: :ok | {:error, term()}
  def attach(handler_id, event_names, handler_function, config) do
    if telemetry_available?() do
      :telemetry.attach(handler_id, event_names, handler_function, config)
    else
      {:error, :telemetry_not_available}
    end
  end

  @doc """
  Attaches multiple telemetry handlers.

  This is a convenience wrapper around `:telemetry.attach_many/4`.

  ## Examples

      iex> :ok = Vaultx.Base.Telemetry.attach_many(
      ...>   "my-handlers",
      ...>   [[:vaultx, :http, :request, :start], [:vaultx, :http, :request, :stop]],
      ...>   &MyHandler.handle_event/4,
      ...>   %{}
      ...> )

  """
  @spec attach_many(String.t(), [[atom()]], (... -> any()), map()) :: :ok | {:error, term()}
  def attach_many(handler_id, event_names, handler_function, config) do
    if telemetry_available?() do
      :telemetry.attach_many(handler_id, event_names, handler_function, config)
    else
      {:error, :telemetry_not_available}
    end
  end

  @doc """
  Detaches a telemetry handler.

  This is a convenience wrapper around `:telemetry.detach/1`.

  ## Examples

      iex> :ok = Vaultx.Base.Telemetry.detach("my-handler")

  """
  @spec detach(String.t()) :: :ok | {:error, term()}
  def detach(handler_id) do
    if telemetry_available?() do
      :telemetry.detach(handler_id)
    else
      {:error, :telemetry_not_available}
    end
  end

  @doc """
  Lists all attached telemetry handlers.

  This is a convenience wrapper around `:telemetry.list_handlers/1`.

  ## Examples

      iex> handlers = Vaultx.Base.Telemetry.list_handlers([:vaultx])

  """
  @spec list_handlers([atom()]) :: [map()]
  def list_handlers(event_prefix) do
    if telemetry_available?() do
      :telemetry.list_handlers(event_prefix)
    else
      []
    end
  end

  @doc """
  Returns telemetry configuration and status.

  ## Examples

      iex> info = Vaultx.Base.Telemetry.info()
      iex> info.enabled
      true

  """
  @spec info() :: %{
          enabled: boolean(),
          handlers_count: non_neg_integer(),
          available_events: [list(atom())]
        }
  def info do
    handlers = list_handlers([:vaultx])

    %{
      enabled: enabled?(),
      handlers_count: length(handlers),
      available_events: available_events()
    }
  end

  # Convenience functions for common events

  @doc "Records the start of an authentication attempt"
  @spec auth_start(map()) :: :ok
  def auth_start(metadata \\ %{}) do
    execute([:auth, :start], %{system_time: System.system_time()}, metadata)
  end

  @doc "Records a successful authentication"
  @spec auth_success(non_neg_integer(), map()) :: :ok
  def auth_success(duration, metadata \\ %{}) do
    execute([:auth, :stop], %{duration: duration}, Map.put(metadata, :result, :success))
  end

  @doc "Records a failed authentication"
  @spec auth_failure(non_neg_integer(), map()) :: :ok
  def auth_failure(duration, metadata \\ %{}) do
    execute([:auth, :stop], %{duration: duration}, Map.put(metadata, :result, :failure))
  end

  @doc "Records the start of a Vault operation"
  @spec operation_start(map()) :: :ok
  def operation_start(metadata \\ %{}) do
    execute([:operation, :start], %{system_time: System.system_time()}, metadata)
  end

  @doc "Records a successful operation"
  @spec operation_success(non_neg_integer(), map()) :: :ok
  def operation_success(duration, metadata \\ %{}) do
    execute([:operation, :stop], %{duration: duration}, Map.put(metadata, :result, :success))
  end

  @doc "Records a failed operation"
  @spec operation_failure(non_neg_integer(), map()) :: :ok
  def operation_failure(duration, metadata \\ %{}) do
    execute([:operation, :stop], %{duration: duration}, Map.put(metadata, :result, :failure))
  end

  @doc "Records the start of an HTTP request"
  @spec http_request_start(map()) :: :ok
  def http_request_start(metadata \\ %{}) do
    execute([:http, :request, :start], %{system_time: System.system_time()}, metadata)
  end

  @doc "Records a completed HTTP request"
  @spec http_request_stop(non_neg_integer(), map()) :: :ok
  def http_request_stop(duration, metadata \\ %{}) do
    execute([:http, :request, :stop], %{duration: duration}, metadata)
  end

  @doc "Records an HTTP request exception"
  @spec http_request_exception(non_neg_integer(), map()) :: :ok
  def http_request_exception(duration, metadata \\ %{}) do
    execute([:http, :request, :exception], %{duration: duration}, metadata)
  end

  # Private functions

  defp available_events do
    operations = [
      [:http, :request],
      [:auth],
      [:secret, :read],
      [:secret, :write],
      [:secret, :delete],
      [:secret, :list],
      [:system, :health],
      [:system, :seal]
    ]

    for operation <- operations,
        event_type <- [:start, :stop] do
      [:vaultx | operation ++ [event_type]]
    end
  end
end
