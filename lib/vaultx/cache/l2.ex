defmodule Vaultx.Cache.L2 do
  @moduledoc """
  L2 Distributed Cache implementation.

  This module provides distributed caching capabilities using external storage
  systems like Redis or Memcached. It's designed for sharing cache data across
  multiple VaultX instances in a cluster environment.

  ## Features

  - Distributed Storage: Share cache across multiple nodes
  - Persistence: Survives application restarts
  - Scalability: Handle large datasets beyond memory limits
  - Network Optimization: Efficient serialization and compression
  - Failover Support: Graceful degradation when L2 is unavailable

  ## Supported Adapters

  - Redis (recommended for production)
  - Memcached (for simple use cases)
  - Custom adapters via behaviour implementation

  ## Performance Characteristics

  - Read latency: ~1-5ms (network dependent)
  - Write latency: ~2-10ms (network dependent)
  - Throughput: Limited by network and storage backend
  - Memory usage: Minimal (data stored externally)

  ## Configuration

      config :vaultx, :cache,
        l2_adapter: Vaultx.Cache.Adapters.Redis,
        l2_connection: [
          host: "localhost",
          port: 6379,
          database: 0,
          pool_size: 10
        ],
        l2_ttl_default: :timer.hours(1),
        l2_compression: true,
        l2_encryption: false
  """

  use GenServer

  alias Vaultx.Base.Logger
  alias Vaultx.Cache.{Adapters, Metrics}

  @cleanup_interval :timer.minutes(10)

  defstruct [
    :adapter,
    :adapter_state,
    :config,
    :cleanup_timer
  ]

  # Public API

  @doc """
  Starts the L2 cache.
  """
  def start_link(config) do
    GenServer.start_link(__MODULE__, config, name: __MODULE__)
  end

  @doc """
  Gets a value from L2 cache.
  """
  def get(key) do
    GenServer.call(__MODULE__, {:get, key})
  end

  @doc """
  Puts a value into L2 cache.
  """
  def put(key, value, opts \\ []) do
    GenServer.call(__MODULE__, {:put, key, value, opts})
  end

  @doc """
  Deletes a value from L2 cache.
  """
  def delete(key) do
    GenServer.call(__MODULE__, {:delete, key})
  end

  @doc """
  Clears L2 cache.
  """
  def clear(pattern \\ :all) do
    GenServer.call(__MODULE__, {:clear, pattern})
  end

  @doc """
  Performs cleanup of expired entries.
  """
  def cleanup do
    GenServer.cast(__MODULE__, :cleanup)
  end

  @doc """
  Gets L2 cache statistics.
  """
  def stats do
    GenServer.call(__MODULE__, :stats)
  end

  # GenServer callbacks

  @impl true
  def init(config) do
    adapter_module = Map.get(config, :l2_adapter, Adapters.Memory)

    case adapter_module.init(config) do
      {:ok, adapter_state} ->
        # Schedule cleanup
        cleanup_timer = schedule_cleanup(config)

        state = %__MODULE__{
          adapter: adapter_module,
          adapter_state: adapter_state,
          config: config,
          cleanup_timer: cleanup_timer
        }

        Logger.info("L2 cache started", %{adapter: adapter_module})
        {:ok, state}

      {:error, reason} ->
        Logger.error("Failed to start L2 cache", %{reason: reason})
        {:stop, reason}
    end
  end

  @impl true
  def handle_call({:get, key}, _from, state) do
    case state.adapter.get(key, state.adapter_state) do
      {:ok, value} ->
        Metrics.record_hit(:l2, key)
        {:reply, {:ok, value}, state}

      {:error, :not_found} ->
        {:reply, {:error, :not_found}, state}

      {:error, reason} ->
        Logger.warn("L2 cache get error", %{key: key, reason: reason})
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:put, key, value, opts}, _from, state) do
    ttl = Keyword.get(opts, :ttl, Map.get(state.config, :l2_ttl_default, :timer.hours(1)))

    case state.adapter.put(key, value, ttl, state.adapter_state) do
      :ok ->
        {:reply, :ok, state}

      {:error, reason} ->
        Logger.warn("L2 cache put error", %{key: key, reason: reason})
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:delete, key}, _from, state) do
    case state.adapter.delete(key, state.adapter_state) do
      :ok ->
        {:reply, :ok, state}

      {:error, reason} ->
        Logger.warn("L2 cache delete error", %{key: key, reason: reason})
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:clear, pattern}, _from, state) do
    case state.adapter.clear(pattern, state.adapter_state) do
      :ok ->
        {:reply, :ok, state}

      {:error, reason} ->
        Logger.warn("L2 cache clear error", %{pattern: pattern, reason: reason})
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call(:stats, _from, state) do
    case state.adapter.stats(state.adapter_state) do
      {:ok, stats} ->
        {:reply, stats, state}

      {:error, reason} ->
        Logger.warn("L2 cache stats error", %{reason: reason})
        {:reply, %{}, state}
    end
  end

  @impl true
  def handle_cast(:cleanup, state) do
    case state.adapter.cleanup(state.adapter_state) do
      :ok ->
        Logger.debug("L2 cache cleanup completed")

      {:error, reason} ->
        Logger.warn("L2 cache cleanup error", %{reason: reason})
    end

    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    case state.adapter.cleanup(state.adapter_state) do
      :ok ->
        Logger.debug("L2 cache cleanup completed")

      {:error, reason} ->
        Logger.warn("L2 cache cleanup error", %{reason: reason})
    end

    cleanup_timer = schedule_cleanup(state.config)
    {:noreply, %{state | cleanup_timer: cleanup_timer}}
  end

  # Private functions

  defp schedule_cleanup(config) do
    interval = Map.get(config, :l2_cleanup_interval, @cleanup_interval)
    Process.send_after(self(), :cleanup, interval)
  end
end
