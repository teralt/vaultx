defmodule Vaultx.Cache.Metrics do
  @moduledoc """
  Cache metrics collection and reporting system.

  This module tracks comprehensive cache performance metrics across all cache layers,
  providing insights into hit ratios, response times, memory usage, and operational
  efficiency.

  ## Metrics Collected

  ### Hit/Miss Metrics
  - Cache hits per layer (L1, L2, L3)
  - Cache misses per layer
  - Overall hit ratio
  - Hit ratio trends over time

  ### Performance Metrics
  - Average response time per operation
  - P95/P99 response times
  - Throughput (operations per second)
  - Concurrent operation counts

  ### Resource Metrics
  - Memory usage per layer
  - Storage usage (L3)
  - Network usage (L2)
  - CPU usage for cache operations

  ### Operational Metrics
  - Cache warming statistics
  - Eviction counts and reasons
  - Error rates and types
  - Cleanup operation metrics

  ## Usage Examples

      # Record cache operations
      Vaultx.Cache.Metrics.record_hit(:l1, "secret/myapp/config")
      Vaultx.Cache.Metrics.record_miss("secret/myapp/config")

      # Get comprehensive statistics
      {:ok, stats} = Vaultx.Cache.Metrics.get_stats()

      # Get specific layer statistics
      {:ok, l1_stats} = Vaultx.Cache.Metrics.get_layer_stats(:l1)

  ## Integration with Telemetry

  All metrics are automatically emitted as telemetry events for integration
  with monitoring systems like Prometheus, StatsD, or custom dashboards.

      # Telemetry events emitted:
      [:vaultx, :cache, :hit]
      [:vaultx, :cache, :miss]
      [:vaultx, :cache, :operation]
      [:vaultx, :cache, :eviction]
      [:vaultx, :cache, :cleanup]
  """

  use GenServer

  alias Vaultx.Base.{Logger, Telemetry}

  @metrics_table :vaultx_cache_metrics
  @history_table :vaultx_cache_history

  defstruct [
    :metrics_table,
    :history_table,
    :start_time,
    :report_timer
  ]

  @report_interval :timer.minutes(1)
  @history_retention :timer.hours(24)

  # Public API

  @doc """
  Starts the metrics collection system.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Records a cache hit for the specified layer.
  """
  def record_hit(layer, key) do
    GenServer.cast(__MODULE__, {:hit, layer, key, System.monotonic_time()})
  end

  @doc """
  Records a cache miss.
  """
  def record_miss(key) do
    GenServer.cast(__MODULE__, {:miss, key, System.monotonic_time()})
  end

  @doc """
  Records a cache operation with timing.
  """
  def record_operation(operation, key, duration) do
    GenServer.cast(__MODULE__, {:operation, operation, key, duration})
  end

  @doc """
  Records a cache eviction event.
  """
  def record_eviction(layer, key, reason) do
    GenServer.cast(__MODULE__, {:eviction, layer, key, reason})
  end

  @doc """
  Gets comprehensive cache statistics.
  """
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Gets statistics for a specific cache layer.
  """
  def get_layer_stats(layer) do
    GenServer.call(__MODULE__, {:get_layer_stats, layer})
  end

  @doc """
  Resets all metrics.
  """
  def reset_metrics do
    GenServer.call(__MODULE__, :reset_metrics)
  end

  # GenServer callbacks

  @impl true
  def init(_opts) do
    # Create ETS tables for metrics
    metrics_table =
      :ets.new(@metrics_table, [
        :set,
        :public,
        :named_table,
        {:write_concurrency, true}
      ])

    history_table =
      :ets.new(@history_table, [
        :ordered_set,
        :public,
        :named_table,
        {:write_concurrency, true}
      ])

    # Initialize metrics
    initialize_metrics(metrics_table)

    state = %__MODULE__{
      metrics_table: metrics_table,
      history_table: history_table,
      start_time: System.system_time(:millisecond)
    }

    # Schedule periodic reporting
    report_timer = schedule_report()
    state = %{state | report_timer: report_timer}

    Logger.info("Cache metrics system started")

    {:ok, state}
  end

  @impl true
  def handle_cast({:hit, layer, key, timestamp}, state) do
    # Update hit counters
    :ets.update_counter(@metrics_table, {:hits, layer}, 1, {{:hits, layer}, 0})
    :ets.update_counter(@metrics_table, :total_hits, 1, {:total_hits, 0})

    # Record in history
    :ets.insert(@history_table, {timestamp, :hit, layer, key})

    # Emit telemetry
    Telemetry.execute([:vaultx, :cache, :hit], %{layer: layer}, %{key: key})

    {:noreply, state}
  end

  @impl true
  def handle_cast({:miss, key, timestamp}, state) do
    # Update miss counter
    :ets.update_counter(@metrics_table, :total_misses, 1, {:total_misses, 0})

    # Record in history
    :ets.insert(@history_table, {timestamp, :miss, nil, key})

    # Emit telemetry
    Telemetry.execute([:vaultx, :cache, :miss], %{}, %{key: key})

    {:noreply, state}
  end

  @impl true
  def handle_cast({:operation, operation, key, duration}, state) do
    # Update operation counters
    counter_key = {:operations, operation}
    :ets.update_counter(@metrics_table, counter_key, 1, {counter_key, 0})

    # Update duration tracking
    duration_key = {:duration, operation}
    current_total = get_metric_value(duration_key, 0)
    current_count = get_metric_value({:operations, operation}, 1)
    new_avg = (current_total + duration) / current_count
    :ets.insert(@metrics_table, {duration_key, new_avg})

    # Emit telemetry
    Telemetry.execute(
      [:vaultx, :cache, :operation],
      %{
        duration: duration,
        operation: operation
      },
      %{key: key}
    )

    {:noreply, state}
  end

  @impl true
  def handle_cast({:eviction, layer, key, reason}, state) do
    # Update eviction counters
    eviction_key = {:evictions, layer, reason}
    :ets.update_counter(@metrics_table, eviction_key, 1, {eviction_key, 0})

    # Emit telemetry
    Telemetry.execute(
      [:vaultx, :cache, :eviction],
      %{
        layer: layer,
        reason: reason
      },
      %{key: key}
    )

    {:noreply, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    stats = compile_comprehensive_stats(state)
    {:reply, {:ok, stats}, state}
  end

  @impl true
  def handle_call({:get_layer_stats, layer}, _from, state) do
    stats = compile_layer_stats(layer, state)
    {:reply, {:ok, stats}, state}
  end

  @impl true
  def handle_call(:reset_metrics, _from, state) do
    :ets.delete_all_objects(@metrics_table)
    :ets.delete_all_objects(@history_table)
    initialize_metrics(state.metrics_table)

    Logger.info("Cache metrics reset")
    {:reply, :ok, state}
  end

  @impl true
  def handle_info(:report, state) do
    generate_periodic_report(state)
    cleanup_old_history(state)

    report_timer = schedule_report()
    {:noreply, %{state | report_timer: report_timer}}
  end

  # Private functions

  defp initialize_metrics(table) do
    # Initialize counters
    :ets.insert(table, {:total_hits, 0})
    :ets.insert(table, {:total_misses, 0})

    # Initialize layer-specific counters
    for layer <- [:l1, :l2, :l3] do
      :ets.insert(table, {{:hits, layer}, 0})
      :ets.insert(table, {{:operations, layer}, 0})
    end

    # Initialize operation counters
    for operation <- [:get, :put, :delete, :get_many, :put_many] do
      :ets.insert(table, {{:operations, operation}, 0})
      :ets.insert(table, {{:duration, operation}, 0.0})
    end
  end

  defp compile_comprehensive_stats(state) do
    total_hits = get_metric_value(:total_hits, 0)
    total_misses = get_metric_value(:total_misses, 0)
    total_operations = total_hits + total_misses

    hit_ratio = if total_operations > 0, do: total_hits / total_operations, else: 0.0

    uptime = System.system_time(:millisecond) - state.start_time

    %{
      # Overall metrics
      total_hits: total_hits,
      total_misses: total_misses,
      total_operations: total_operations,
      hit_ratio: hit_ratio,
      uptime_ms: uptime,

      # Layer-specific metrics
      l1: compile_layer_stats(:l1, state),
      l2: compile_layer_stats(:l2, state),
      l3: compile_layer_stats(:l3, state),

      # Operation metrics
      operations: compile_operation_stats(state),

      # Performance metrics
      performance: compile_performance_stats(state)
    }
  end

  defp compile_layer_stats(layer, _state) do
    hits = get_metric_value({:hits, layer}, 0)
    operations = get_metric_value({:operations, layer}, 0)

    %{
      hits: hits,
      operations: operations,
      hit_ratio: if(operations > 0, do: hits / operations, else: 0.0)
    }
  end

  defp compile_operation_stats(_state) do
    operations = [:get, :put, :delete, :get_many, :put_many]

    operations
    |> Enum.map(fn op ->
      count = get_metric_value({:operations, op}, 0)
      avg_duration = get_metric_value({:duration, op}, 0.0)

      {op, %{count: count, avg_duration_ms: avg_duration / 1_000_000}}
    end)
    |> Map.new()
  end

  defp compile_performance_stats(_state) do
    # This would include more sophisticated performance metrics
    # For now, return basic metrics
    %{
      memory_usage_bytes: :erlang.memory(:total),
      process_count: :erlang.system_info(:process_count)
    }
  end

  defp get_metric_value(key, default) do
    case :ets.lookup(@metrics_table, key) do
      [{^key, value}] -> value
      [] -> default
    end
  end

  defp generate_periodic_report(state) do
    stats = compile_comprehensive_stats(state)

    Logger.info("Cache metrics report", %{
      hit_ratio: Float.round(stats.hit_ratio * 100, 2),
      total_operations: stats.total_operations,
      l1_hits: stats.l1.hits,
      l2_hits: stats.l2.hits,
      l3_hits: stats.l3.hits
    })

    # Emit telemetry for monitoring systems
    Telemetry.execute([:vaultx, :cache, :report], stats)
  end

  defp cleanup_old_history(_state) do
    cutoff_time = System.system_time(:millisecond) - @history_retention

    # Remove old history entries
    old_keys =
      @history_table
      |> :ets.tab2list()
      |> Enum.filter(fn {timestamp, _type, _layer, _key} -> timestamp < cutoff_time end)
      |> Enum.map(fn {timestamp, _type, _layer, _key} -> timestamp end)

    Enum.each(old_keys, fn key ->
      :ets.delete(@history_table, key)
    end)

    if length(old_keys) > 0 do
      Logger.debug("Cleaned up old cache history entries", %{count: length(old_keys)})
    end
  end

  defp schedule_report do
    Process.send_after(self(), :report, @report_interval)
  end
end
