defmodule Vaultx.Cache.L1 do
  @moduledoc """
  L1 Memory Cache implementation using ETS.

  This module provides high-performance in-memory caching using Erlang Term Storage (ETS).
  It's optimized for concurrent read/write operations with automatic TTL management
  and LRU eviction policies.

  ## Features

  - High Performance: Sub-microsecond access times
  - Concurrent Access: Optimized for high concurrency
  - TTL Management: Automatic expiration of cached items
  - LRU Eviction: Least Recently Used eviction when memory limits are reached
  - Memory Monitoring: Tracks memory usage and enforces limits
  - Atomic Operations: Thread-safe operations

  ## Performance Characteristics

  - Read latency: ~0.1-1μs
  - Write latency: ~1-5μs
  - Concurrent readers: Unlimited
  - Concurrent writers: Limited by ETS write_concurrency
  - Memory overhead: ~40 bytes per entry + data size

  ## Configuration

      config :vaultx, :cache,
        l1_max_size: 10_000,
        l1_ttl_default: :timer.minutes(15),
        l1_cleanup_interval: :timer.minutes(5),
        l1_eviction_policy: :lru
  """

  use GenServer

  alias Vaultx.Base.Logger

  @table_name :vaultx_l1_cache
  @access_table_name :vaultx_l1_access
  @cleanup_interval :timer.minutes(5)

  defstruct [
    :table,
    :access_table,
    :config,
    :cleanup_timer,
    :current_size,
    :max_size
  ]

  # Public API

  @doc """
  Starts the L1 cache.
  """
  def start_link(config) do
    GenServer.start_link(__MODULE__, config, name: __MODULE__)
  end

  @doc """
  Gets a value from L1 cache.
  """
  def get(key) do
    case :ets.lookup(@table_name, key) do
      [{^key, value, expires_at}] ->
        current_time = System.system_time(:millisecond)

        if current_time < expires_at do
          # Update access time for LRU
          :ets.insert(@access_table_name, {key, current_time})
          {:ok, value}
        else
          # Expired, remove it
          :ets.delete(@table_name, key)
          :ets.delete(@access_table_name, key)
          {:error, :not_found}
        end

      [] ->
        {:error, :not_found}
    end
  end

  @doc """
  Puts a value into L1 cache.
  """
  def put(key, value, opts \\ []) do
    GenServer.call(__MODULE__, {:put, key, value, opts})
  end

  @doc """
  Deletes a value from L1 cache.
  """
  def delete(key) do
    :ets.delete(@table_name, key)
    :ets.delete(@access_table_name, key)
    :ok
  end

  @doc """
  Clears L1 cache.
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
  Gets L1 cache statistics.
  """
  def stats do
    GenServer.call(__MODULE__, :stats)
  end

  # GenServer callbacks

  @impl true
  def init(config) do
    # Create ETS tables
    table =
      :ets.new(@table_name, [
        :set,
        :public,
        :named_table,
        {:read_concurrency, true},
        {:write_concurrency, true}
      ])

    access_table =
      :ets.new(@access_table_name, [
        :set,
        :public,
        :named_table,
        {:read_concurrency, true},
        {:write_concurrency, true}
      ])

    state = %__MODULE__{
      table: table,
      access_table: access_table,
      config: config,
      current_size: 0,
      max_size: Map.get(config, :l1_max_size, 10_000)
    }

    # Schedule cleanup
    cleanup_timer = schedule_cleanup(config)
    state = %{state | cleanup_timer: cleanup_timer}

    Logger.info("L1 cache started", %{
      max_size: state.max_size,
      cleanup_interval: @cleanup_interval
    })

    {:ok, state}
  end

  @impl true
  def handle_call({:put, key, value, opts}, _from, state) do
    ttl = Keyword.get(opts, :ttl, Map.get(state.config, :l1_ttl_default, :timer.minutes(15)))
    expires_at = System.system_time(:millisecond) + ttl
    current_time = System.system_time(:millisecond)

    # Check if we need to evict entries
    state = maybe_evict_entries(state)

    # Insert the new entry
    :ets.insert(@table_name, {key, value, expires_at})
    :ets.insert(@access_table_name, {key, current_time})

    # Update size counter
    new_size = :ets.info(@table_name, :size)
    state = %{state | current_size: new_size}

    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:clear, pattern}, _from, state) do
    case pattern do
      :all ->
        :ets.delete_all_objects(@table_name)
        :ets.delete_all_objects(@access_table_name)

      pattern when is_binary(pattern) ->
        # Convert wildcard pattern to regex
        regex_pattern =
          pattern
          |> String.replace("*", ".*")
          |> Regex.compile!()

        keys_to_delete =
          @table_name
          |> :ets.tab2list()
          |> Enum.filter(fn {key, _value, _expires_at} ->
            Regex.match?(regex_pattern, key)
          end)
          |> Enum.map(fn {key, _value, _expires_at} -> key end)

        Enum.each(keys_to_delete, fn key ->
          :ets.delete(@table_name, key)
          :ets.delete(@access_table_name, key)
        end)
    end

    new_size = :ets.info(@table_name, :size)
    state = %{state | current_size: new_size}

    {:reply, :ok, state}
  end

  @impl true
  def handle_call(:stats, _from, state) do
    stats = %{
      size: state.current_size,
      max_size: state.max_size,
      memory_usage: :ets.info(@table_name, :memory) * :erlang.system_info(:wordsize),
      hit_ratio: calculate_hit_ratio()
    }

    {:reply, stats, state}
  end

  @impl true
  def handle_cast(:cleanup, state) do
    state = perform_cleanup(state)
    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    state = perform_cleanup(state)
    cleanup_timer = schedule_cleanup(state.config)
    {:noreply, %{state | cleanup_timer: cleanup_timer}}
  end

  # Private functions

  defp maybe_evict_entries(state) do
    if state.current_size >= state.max_size do
      # Evict at least 10% of entries, but minimum 1
      evict_count = max(div(state.max_size, 10), 1)
      evict_lru_entries(state, evict_count)
    else
      state
    end
  end

  defp evict_lru_entries(state, count) do
    # Get least recently used entries
    lru_entries =
      @access_table_name
      |> :ets.tab2list()
      |> Enum.sort_by(fn {_key, access_time} -> access_time end)
      |> Enum.take(count)

    # Remove LRU entries
    Enum.each(lru_entries, fn {key, _access_time} ->
      :ets.delete(@table_name, key)
      :ets.delete(@access_table_name, key)
    end)

    Logger.debug("Evicted LRU entries from L1 cache", %{count: count})

    new_size = :ets.info(@table_name, :size)
    %{state | current_size: new_size}
  end

  defp perform_cleanup(state) do
    current_time = System.system_time(:millisecond)

    # Find and remove expired entries
    expired_keys =
      @table_name
      |> :ets.tab2list()
      |> Enum.filter(fn {_key, _value, expires_at} -> current_time >= expires_at end)
      |> Enum.map(fn {key, _value, _expires_at} -> key end)

    # Remove expired entries
    Enum.each(expired_keys, fn key ->
      :ets.delete(@table_name, key)
      :ets.delete(@access_table_name, key)
    end)

    expired_count = length(expired_keys)

    if expired_count > 0 do
      Logger.debug("Cleaned up expired L1 cache entries", %{count: expired_count})
    end

    new_size = :ets.info(@table_name, :size)
    %{state | current_size: new_size}
  end

  defp calculate_hit_ratio do
    # Get hit ratio from metrics system if available
    case Process.whereis(Vaultx.Cache.Metrics) do
      nil ->
        0.0

      _pid ->
        case Vaultx.Cache.Metrics.get_layer_stats(:l1) do
          {:ok, %{hit_ratio: ratio}} -> ratio
          _ -> 0.0
        end
    end
  end

  defp schedule_cleanup(config) do
    interval = Map.get(config, :l1_cleanup_interval, @cleanup_interval)
    Process.send_after(self(), :cleanup, interval)
  end
end
