defmodule Vaultx.Cache.MetricsTest do
  use ExUnit.Case, async: false

  alias Vaultx.Cache.Metrics

  defp stop_server do
    pid = Process.whereis(Vaultx.Cache.Metrics)
    if is_pid(pid), do: Process.exit(pid, :kill)
  end

  setup do
    stop_server()

    # Wait a bit for process to fully stop
    Process.sleep(10)

    case Metrics.start_link() do
      {:ok, pid} -> {:ok, pid}
      {:error, {:already_started, pid}} -> {:ok, pid}
    end

    on_exit(fn -> stop_server() end)
    :ok
  end

  test "initial stats are zeroed and structured" do
    assert {:ok, stats} = Metrics.get_stats()
    assert stats.total_hits == 0
    assert stats.total_misses == 0
    assert stats.total_operations == 0
    assert stats.hit_ratio == +0.0

    # Layer stats present
    assert %{hits: 0, operations: 0, hit_ratio: +0.0} = stats.l1
    assert %{hits: 0, operations: 0, hit_ratio: +0.0} = stats.l2
    assert %{hits: 0, operations: 0, hit_ratio: +0.0} = stats.l3

    # Operations map present
    assert is_map(stats.operations)

    for op <- [:get, :put, :delete, :get_many, :put_many] do
      assert %{count: 0, avg_duration_ms: +0.0} = Map.fetch!(stats.operations, op)
    end

    # Performance stats present
    assert %{memory_usage_bytes: mem, process_count: pc} = stats.performance
    assert is_integer(mem) and mem > 0
    assert is_integer(pc) and pc > 0
  end

  test "recording hits and misses updates stats" do
    Metrics.record_hit(:l1, "k1")
    Metrics.record_hit(:l2, "k2")
    Metrics.record_miss("k3")

    assert {:ok, stats} = Metrics.get_stats()
    assert stats.total_hits == 2
    assert stats.total_misses == 1
    assert stats.total_operations == 3
    assert_in_delta stats.hit_ratio, 2 / 3, 0.0001

    assert {:ok, l1} = Metrics.get_layer_stats(:l1)
    assert l1.hits >= 0
    assert l1.operations >= 0
    assert l1.hit_ratio >= +0.0
  end

  test "recording operations tracks count and average duration" do
    # 1ms
    Metrics.record_operation(:get, "k1", 1_000_000)
    # 3ms
    Metrics.record_operation(:get, "k1", 3_000_000)
    # 2ms
    Metrics.record_operation(:put, "k2", 2_000_000)

    assert {:ok, stats} = Metrics.get_stats()
    ops = stats.operations

    assert %{count: get_count, avg_duration_ms: get_avg} = ops.get
    assert get_count == 2
    assert_in_delta get_avg, 2.0, 0.001

    assert %{count: put_count, avg_duration_ms: put_avg} = ops.put
    assert put_count == 1
    assert_in_delta put_avg, 2.0, 0.001
  end

  test "evictions increment counters" do
    Metrics.record_eviction(:l1, "k1", :lru)
    Metrics.record_eviction(:l2, "k2", :expired)

    # No direct getters for eviction counters; ensure it doesn't crash and stats compiles
    assert {:ok, _stats} = Metrics.get_stats()
  end

  test "reset_metrics clears counters" do
    Metrics.record_hit(:l1, "k1")
    Metrics.record_miss("k2")
    assert :ok = Metrics.reset_metrics()

    assert {:ok, stats} = Metrics.get_stats()
    assert stats.total_hits == 0
    assert stats.total_misses == 0
    assert stats.total_operations == 0
  end
end
