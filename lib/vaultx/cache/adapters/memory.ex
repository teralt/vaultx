defmodule Vaultx.Cache.Adapters.Memory do
  @moduledoc """
  Simple in-memory L2 cache adapter.

  This adapter provides a basic in-memory cache that can be shared across processes
  using ETS. It's suitable for single-node deployments or when Redis is not available.

  ## Features

  - ETS-based storage for cross-process sharing
  - TTL support with automatic expiration
  - Pattern-based clearing
  - Memory usage tracking
  - No external dependencies

  ## Configuration

      config :vaultx, :cache,
        l2_adapter: Vaultx.Cache.Adapters.Memory,
        l2_max_size: 50_000,
        l2_ttl_default: :timer.hours(1)

  ## Limitations

  - Single-node only (no distribution)
  - Memory-limited storage
  - No persistence across restarts
  - Basic eviction policies
  """

  @behaviour Vaultx.Cache.Adapters.Behaviour

  alias Vaultx.Base.Logger

  @table_name :vaultx_l2_memory_cache

  defstruct [
    :table,
    :max_size
  ]

  @impl true
  def init(config) do
    max_size = Map.get(config, :l2_max_size, 50_000)

    # Create ETS table for shared access
    table =
      :ets.new(@table_name, [
        :set,
        :public,
        :named_table,
        {:read_concurrency, true},
        {:write_concurrency, true}
      ])

    state = %__MODULE__{
      table: table,
      max_size: max_size
    }

    # Note: Cleanup will be handled by the L2 GenServer

    Logger.info("Memory L2 cache adapter initialized", %{max_size: max_size})

    {:ok, state}
  end

  @impl true
  def get(key, state) do
    case :ets.lookup(state.table, key) do
      [{^key, value, expires_at}] ->
        current_time = System.system_time(:millisecond)

        if current_time < expires_at do
          {:ok, value}
        else
          # Expired, remove it
          :ets.delete(state.table, key)
          {:error, :not_found}
        end

      [] ->
        {:error, :not_found}
    end
  end

  @impl true
  def put(key, value, ttl, state) do
    expires_at = System.system_time(:millisecond) + ttl

    # Check if we need to evict entries
    maybe_evict_entries(state)

    # Insert the new entry
    :ets.insert(state.table, {key, value, expires_at})

    :ok
  end

  @impl true
  def delete(key, state) do
    :ets.delete(state.table, key)
    :ok
  end

  @impl true
  def clear(pattern, state) do
    case pattern do
      :all ->
        :ets.delete_all_objects(state.table)

      pattern when is_binary(pattern) ->
        # Simple pattern matching
        keys_to_delete =
          state.table
          |> :ets.tab2list()
          |> Enum.filter(fn {key, _value, _expires_at} ->
            String.contains?(key, String.replace(pattern, "*", ""))
          end)
          |> Enum.map(fn {key, _value, _expires_at} -> key end)

        Enum.each(keys_to_delete, fn key ->
          :ets.delete(state.table, key)
        end)
    end

    :ok
  end

  @impl true
  def cleanup(state) do
    current_time = System.system_time(:millisecond)

    # Find and remove expired entries
    expired_keys =
      state.table
      |> :ets.tab2list()
      |> Enum.filter(fn {_key, _value, expires_at} -> current_time >= expires_at end)
      |> Enum.map(fn {key, _value, _expires_at} -> key end)

    # Remove expired entries
    Enum.each(expired_keys, fn key ->
      :ets.delete(state.table, key)
    end)

    if length(expired_keys) > 0 do
      Logger.debug("Memory L2 cache cleanup completed", %{expired_entries: length(expired_keys)})
    end

    :ok
  end

  @impl true
  def stats(state) do
    size = :ets.info(state.table, :size)
    memory_usage = :ets.info(state.table, :memory) * :erlang.system_info(:wordsize)

    stats = %{
      size: size,
      max_size: state.max_size,
      memory_usage_bytes: memory_usage,
      utilization: if(state.max_size > 0, do: size / state.max_size, else: 0.0)
    }

    {:ok, stats}
  end

  # Private functions

  defp maybe_evict_entries(state) do
    current_size = :ets.info(state.table, :size)

    if current_size >= state.max_size do
      # Evict 10% of entries (oldest first)
      evict_count = div(state.max_size, 10)
      evict_oldest_entries(state, evict_count)
    end
  end

  defp evict_oldest_entries(state, count) do
    # Get all entries and sort by expiration time (oldest first)
    oldest_entries =
      state.table
      |> :ets.tab2list()
      |> Enum.sort_by(fn {_key, _value, expires_at} -> expires_at end)
      |> Enum.take(count)

    # Remove oldest entries
    Enum.each(oldest_entries, fn {key, _value, _expires_at} ->
      :ets.delete(state.table, key)
    end)

    Logger.debug("Evicted oldest entries from Memory L2 cache", %{count: count})
  end
end
