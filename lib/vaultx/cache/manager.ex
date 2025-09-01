defmodule Vaultx.Cache.Manager do
  @moduledoc """
  Cache manager that coordinates operations across multiple cache layers.

  This GenServer manages the lifecycle and coordination of all cache layers,
  handles cache warming, cleanup, and provides a unified interface for
  cache operations.
  """

  use GenServer

  alias Vaultx.Base.{Config, Error, Logger}
  alias Vaultx.Cache.{L1, L2, L3, Metrics}

  defstruct [
    :config,
    :l1_enabled,
    :l2_enabled,
    :l3_enabled,
    :l1_pid,
    :l2_pid,
    :l3_pid,
    :metrics_pid,
    :cleanup_timer
  ]

  @cleanup_interval :timer.minutes(5)

  # Public API

  @doc """
  Starts the cache manager.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Gets a value from the cache layers.
  """
  def get(key, opts \\ []) do
    GenServer.call(__MODULE__, {:get, key, opts})
  end

  @doc """
  Puts a value into the cache layers.
  """
  def put(key, value, opts \\ []) do
    GenServer.call(__MODULE__, {:put, key, value, opts})
  end

  @doc """
  Deletes a value from all cache layers.
  """
  def delete(key) do
    GenServer.call(__MODULE__, {:delete, key})
  end

  @doc """
  Gets multiple values from cache.
  """
  def get_many(keys, opts \\ []) do
    GenServer.call(__MODULE__, {:get_many, keys, opts})
  end

  @doc """
  Puts multiple key-value pairs.
  """
  def put_many(pairs, opts \\ []) do
    GenServer.call(__MODULE__, {:put_many, pairs, opts})
  end

  @doc """
  Warms the cache with preloaded data.
  """
  def warm(pattern, preload_fn) do
    GenServer.cast(__MODULE__, {:warm, pattern, preload_fn})
  end

  @doc """
  Clears cache layers.
  """
  def clear(pattern \\ :all) do
    GenServer.call(__MODULE__, {:clear, pattern})
  end

  # GenServer callbacks

  @impl true
  def init(opts) do
    config = build_cache_config(opts)

    # Validate configuration
    case validate_cache_config(config) do
      :ok ->
        :ok

      {:error, reason} ->
        Logger.error("Invalid cache configuration", %{reason: reason})
        {:stop, reason}
    end

    state = %__MODULE__{
      config: config,
      l1_enabled: config.l1_enabled,
      l2_enabled: config.l2_enabled,
      l3_enabled: config.l3_enabled
    }

    # Start cache layers
    {:ok, state} = start_cache_layers(state)

    # Start metrics collection (if not already started)
    metrics_pid =
      case Process.whereis(Metrics) do
        nil ->
          {:ok, pid} = Metrics.start_link()
          pid

        pid ->
          pid
      end

    state = %{state | metrics_pid: metrics_pid}

    # Schedule cleanup
    cleanup_timer = schedule_cleanup(state)
    state = %{state | cleanup_timer: cleanup_timer}

    Logger.info("Cache manager started", %{
      l1_enabled: state.l1_enabled,
      l2_enabled: state.l2_enabled,
      l3_enabled: state.l3_enabled
    })

    {:ok, state}
  end

  @impl true
  def handle_call({:get, key, opts}, _from, state) do
    result = do_get(key, opts, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:put, key, value, opts}, _from, state) do
    result = do_put(key, value, opts, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:delete, key}, _from, state) do
    result = do_delete(key, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_many, keys, opts}, _from, state) do
    result = do_get_many(keys, opts, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:put_many, pairs, opts}, _from, state) do
    result = do_put_many(pairs, opts, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:clear, pattern}, _from, state) do
    result = do_clear(pattern, state)
    {:reply, result, state}
  end

  @impl true
  def handle_cast({:warm, pattern, preload_fn}, state) do
    Task.start(fn -> do_warm(pattern, preload_fn, state) end)
    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    perform_cleanup(state)
    cleanup_timer = schedule_cleanup(state)
    {:noreply, %{state | cleanup_timer: cleanup_timer}}
  end

  @impl true
  def handle_info({:DOWN, _ref, :process, pid, reason}, state) do
    Logger.warn("Cache layer process died", %{pid: pid, reason: reason})

    # Attempt to restart the failed cache layer
    new_state = restart_failed_layer(pid, reason, state)

    {:noreply, new_state}
  end

  # Private functions

  defp build_cache_config(opts) do
    vault_config = Config.get()

    %{
      l1_enabled: Keyword.get(opts, :l1_enabled, vault_config.cache_l1_enabled),
      l2_enabled: Keyword.get(opts, :l2_enabled, vault_config.cache_l2_enabled),
      l3_enabled: Keyword.get(opts, :l3_enabled, vault_config.cache_l3_enabled),
      l1_max_size: Keyword.get(opts, :l1_max_size, vault_config.cache_l1_max_size),
      l1_ttl_default: Keyword.get(opts, :l1_ttl_default, vault_config.cache_l1_ttl_default),
      l1_cleanup_interval:
        Keyword.get(opts, :l1_cleanup_interval, vault_config.cache_l1_cleanup_interval),
      l2_adapter: Keyword.get(opts, :l2_adapter, vault_config.cache_l2_adapter),
      l2_max_size: Keyword.get(opts, :l2_max_size, vault_config.cache_l2_max_size),
      l2_ttl_default: Keyword.get(opts, :l2_ttl_default, vault_config.cache_l2_ttl_default),
      l3_storage_path: Keyword.get(opts, :l3_storage_path, vault_config.cache_l3_storage_path),
      l3_ttl_default: Keyword.get(opts, :l3_ttl_default, vault_config.cache_l3_ttl_default),
      l3_encryption: Keyword.get(opts, :l3_encryption, vault_config.cache_l3_encryption),
      eviction_policy: Keyword.get(opts, :eviction_policy, vault_config.cache_eviction_policy),
      max_memory_usage: Keyword.get(opts, :max_memory_usage, vault_config.cache_max_memory_usage),
      warming_enabled: Keyword.get(opts, :warming_enabled, vault_config.cache_warming_enabled),
      metrics_enabled: Keyword.get(opts, :metrics_enabled, vault_config.cache_metrics_enabled),
      manager_cleanup_interval:
        Keyword.get(opts, :manager_cleanup_interval, vault_config.cache_manager_cleanup_interval),
      l2_cleanup_interval:
        Keyword.get(opts, :l2_cleanup_interval, vault_config.cache_l2_cleanup_interval),
      l3_cleanup_interval:
        Keyword.get(opts, :l3_cleanup_interval, vault_config.cache_l3_cleanup_interval)
    }
  end

  defp start_cache_layers(state) do
    state =
      if state.l1_enabled do
        case L1.start_link(state.config) do
          {:ok, l1_pid} ->
            Process.monitor(l1_pid)
            %{state | l1_pid: l1_pid}

          {:error, reason} ->
            Logger.warn("Failed to start L1 cache, disabling", %{reason: reason})
            %{state | l1_enabled: false, l1_pid: nil}
        end
      else
        state
      end

    state =
      if state.l2_enabled do
        case L2.start_link(state.config) do
          {:ok, l2_pid} ->
            Process.monitor(l2_pid)
            %{state | l2_pid: l2_pid}

          {:error, reason} ->
            Logger.warn("Failed to start L2 cache, disabling", %{reason: reason})
            %{state | l2_enabled: false, l2_pid: nil}
        end
      else
        state
      end

    state =
      if state.l3_enabled do
        case L3.start_link(state.config) do
          {:ok, l3_pid} ->
            Process.monitor(l3_pid)
            %{state | l3_pid: l3_pid}

          {:error, reason} ->
            Logger.warn("Failed to start L3 cache, disabling", %{reason: reason})
            %{state | l3_enabled: false, l3_pid: nil}
        end
      else
        state
      end

    {:ok, state}
  end

  defp do_get(key, opts, state) do
    layer_preference = Keyword.get(opts, :layer, :all)

    # Try L1 first if enabled and requested
    if state.l1_enabled and layer_preference in [:all, :l1] do
      case L1.get(key) do
        {:ok, value} ->
          Metrics.record_hit(:l1, key)
          {:ok, value}

        {:error, :not_found} ->
          try_l2_get(key, opts, state)
      end
    else
      try_l2_get(key, opts, state)
    end
  end

  defp try_l2_get(key, opts, state) do
    layer_preference = Keyword.get(opts, :layer, :all)

    if state.l2_enabled and layer_preference in [:all, :l2] do
      case L2.get(key) do
        {:ok, value} ->
          Metrics.record_hit(:l2, key)
          # Promote to L1 if enabled
          if state.l1_enabled, do: L1.put(key, value)
          {:ok, value}

        {:error, :not_found} ->
          try_l3_get(key, opts, state)

        {:error, _} = error ->
          Logger.warn("L2 cache error, trying L3", %{key: key, error: error})
          try_l3_get(key, opts, state)
      end
    else
      try_l3_get(key, opts, state)
    end
  end

  defp try_l3_get(key, opts, state) do
    layer_preference = Keyword.get(opts, :layer, :all)

    if state.l3_enabled and layer_preference in [:all, :l3] do
      case L3.get(key) do
        {:ok, value} ->
          Metrics.record_hit(:l3, key)
          # Promote to higher layers if enabled
          if state.l2_enabled, do: L2.put(key, value)
          if state.l1_enabled, do: L1.put(key, value)
          {:ok, value}

        {:error, :not_found} ->
          Metrics.record_miss(key)
          {:error, :not_found}

        {:error, _} = error ->
          Metrics.record_miss(key)
          error
      end
    else
      Metrics.record_miss(key)
      {:error, :not_found}
    end
  end

  defp do_put(key, value, opts, state) do
    layer_preference = Keyword.get(opts, :layer, :all)
    ttl = Keyword.get(opts, :ttl)

    results = []

    # Put to L1 if enabled and requested
    results =
      if state.l1_enabled and layer_preference in [:all, :l1] do
        l1_ttl = ttl || state.config.l1_ttl_default
        result = L1.put(key, value, ttl: l1_ttl)
        [result | results]
      else
        results
      end

    # Put to L2 if enabled and requested
    results =
      if state.l2_enabled and layer_preference in [:all, :l2] do
        l2_ttl = ttl || state.config.l2_ttl_default
        result = L2.put(key, value, ttl: l2_ttl)
        [result | results]
      else
        results
      end

    # Put to L3 if enabled and requested
    results =
      if state.l3_enabled and layer_preference in [:all, :l3] do
        l3_ttl = ttl || state.config.l3_ttl_default
        result = L3.put(key, value, ttl: l3_ttl)
        [result | results]
      else
        results
      end

    # Return :ok if any layer succeeded
    if Enum.any?(results, &(&1 == :ok)) do
      :ok
    else
      {:error, Error.new(:cache_put_failed, "Failed to put value in any cache layer")}
    end
  end

  defp do_delete(key, state) do
    results = []

    results = if state.l1_enabled, do: [L1.delete(key) | results], else: results
    results = if state.l2_enabled, do: [L2.delete(key) | results], else: results
    results = if state.l3_enabled, do: [L3.delete(key) | results], else: results

    # Return :ok if any layer succeeded
    if Enum.any?(results, &(&1 == :ok)) do
      :ok
    else
      {:error, Error.new(:cache_delete_failed, "Failed to delete from any cache layer")}
    end
  end

  defp do_get_many(keys, opts, state) do
    results =
      keys
      |> Enum.map(fn key ->
        case do_get(key, opts, state) do
          {:ok, value} -> {key, value}
          {:error, _} -> {key, nil}
        end
      end)
      |> Map.new()

    {:ok, results}
  end

  defp do_put_many(pairs, opts, state) do
    results =
      pairs
      |> Enum.map(fn {key, value} ->
        do_put(key, value, opts, state)
      end)

    if Enum.all?(results, &(&1 == :ok)) do
      :ok
    else
      {:error, Error.new(:cache_put_many_failed, "Some put operations failed")}
    end
  end

  defp do_clear(pattern, state) do
    if state.l1_enabled, do: L1.clear(pattern)
    if state.l2_enabled, do: L2.clear(pattern)
    if state.l3_enabled, do: L3.clear(pattern)
    :ok
  end

  defp do_warm(pattern, preload_fn, state) do
    Logger.info("Starting cache warming", %{pattern: pattern})

    start_time = System.monotonic_time()

    try do
      # Generate keys based on pattern
      keys_to_warm = generate_keys_from_pattern(pattern)

      # Warm each key
      warmed_count =
        keys_to_warm
        |> Enum.map(fn key ->
          case preload_fn.(key) do
            {:ok, value} ->
              # Store in cache layers
              do_put(key, value, [], state)
              1

            {:error, _reason} ->
              0

            value when not is_tuple(value) ->
              # Direct value returned
              do_put(key, value, [], state)
              1
          end
        end)
        |> Enum.sum()

      duration = System.monotonic_time() - start_time

      Logger.info("Cache warming completed", %{
        pattern: pattern,
        keys_warmed: warmed_count,
        duration_ms: System.convert_time_unit(duration, :native, :millisecond)
      })
    rescue
      error ->
        Logger.error("Cache warming failed", %{
          pattern: pattern,
          error: inspect(error)
        })
    end
  end

  defp generate_keys_from_pattern(pattern) do
    # Simple pattern-based key generation
    # In a real implementation, this might query existing data sources
    # or use a predefined list of common keys

    case pattern do
      # Handle wildcard patterns
      pattern when is_binary(pattern) ->
        if String.contains?(pattern, "*") do
          # For demo purposes, generate some common keys
          base_pattern = String.replace(pattern, "*", "")

          [
            "#{base_pattern}config",
            "#{base_pattern}settings",
            "#{base_pattern}metadata",
            "#{base_pattern}permissions"
          ]
        else
          # Single key
          [pattern]
        end

      # Handle list of keys
      keys when is_list(keys) ->
        keys

      # Single key
      key ->
        [key]
    end
  end

  defp perform_cleanup(state) do
    if state.l1_enabled, do: L1.cleanup()
    if state.l2_enabled, do: L2.cleanup()
    if state.l3_enabled, do: L3.cleanup()
  end

  defp restart_failed_layer(failed_pid, reason, state) do
    cond do
      state.l1_pid == failed_pid and state.l1_enabled ->
        Logger.info("Restarting L1 cache layer")

        case L1.start_link(state.config) do
          {:ok, new_pid} ->
            Process.monitor(new_pid)
            %{state | l1_pid: new_pid}

          {:error, restart_reason} ->
            Logger.error("Failed to restart L1 cache", %{reason: restart_reason})
            %{state | l1_enabled: false, l1_pid: nil}
        end

      state.l2_pid == failed_pid and state.l2_enabled ->
        Logger.info("Restarting L2 cache layer")

        case L2.start_link(state.config) do
          {:ok, new_pid} ->
            Process.monitor(new_pid)
            %{state | l2_pid: new_pid}

          {:error, restart_reason} ->
            Logger.error("Failed to restart L2 cache", %{reason: restart_reason})
            %{state | l2_enabled: false, l2_pid: nil}
        end

      state.l3_pid == failed_pid and state.l3_enabled ->
        Logger.info("Restarting L3 cache layer")

        case L3.start_link(state.config) do
          {:ok, new_pid} ->
            Process.monitor(new_pid)
            %{state | l3_pid: new_pid}

          {:error, restart_reason} ->
            Logger.error("Failed to restart L3 cache", %{reason: restart_reason})
            %{state | l3_enabled: false, l3_pid: nil}
        end

      true ->
        Logger.warn("Unknown process died", %{pid: failed_pid, reason: reason})
        state
    end
  end

  defp validate_cache_config(config) do
    # Basic validation - can be expanded
    cond do
      config.l1_max_size <= 0 ->
        {:error, "L1 max_size must be positive"}

      config.l2_max_size <= 0 ->
        {:error, "L2 max_size must be positive"}

      config.l1_ttl_default <= 0 ->
        {:error, "L1 TTL must be positive"}

      config.l2_ttl_default <= 0 ->
        {:error, "L2 TTL must be positive"}

      config.l3_ttl_default <= 0 ->
        {:error, "L3 TTL must be positive"}

      true ->
        :ok
    end
  end

  defp schedule_cleanup(state) do
    interval = Map.get(state.config, :manager_cleanup_interval, @cleanup_interval)
    Process.send_after(self(), :cleanup, interval)
  end
end
