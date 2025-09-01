defmodule Vaultx.Cache.Adapters.MemoryTest do
  use ExUnit.Case, async: true

  alias Vaultx.Cache.Adapters.Memory

  @table_name :vaultx_l2_memory_cache

  defp drop_named_table do
    case :ets.whereis(@table_name) do
      :undefined -> :ok
      tid when is_reference(tid) -> :ets.delete(tid)
    end
  end

  setup do
    # Ensure a clean ETS named table before each test
    drop_named_table()

    {:ok, state} = Memory.init(%{l2_max_size: 10})

    on_exit(fn -> drop_named_table() end)

    %{state: state}
  end

  test "init creates ETS table and sets max_size", %{state: state} do
    assert state.max_size == 10
    assert :ets.whereis(@table_name) |> is_reference()
    assert :ets.info(state.table, :name) == @table_name
  end

  test "put/get works for non-expired entries", %{state: state} do
    assert :ok == Memory.put("k1", 42, 100, state)
    assert {:ok, 42} = Memory.get("k1", state)
  end

  test "get returns not_found for missing key", %{state: state} do
    assert {:error, :not_found} = Memory.get("missing", state)
  end

  test "expired entries are not returned and are cleaned on access", %{state: state} do
    :ok = Memory.put("k2", :v, 10, state)
    :timer.sleep(20)
    assert {:error, :not_found} = Memory.get("k2", state)

    # Ensure it's actually removed from table
    assert [] == :ets.lookup(state.table, "k2")
  end

  test "delete removes the key", %{state: state} do
    :ok = Memory.put("k3", :v3, 1000, state)
    assert {:ok, :v3} = Memory.get("k3", state)
    assert :ok = Memory.delete("k3", state)
    assert {:error, :not_found} = Memory.get("k3", state)
  end

  test "clear :all removes all entries", %{state: state} do
    for i <- 1..3 do
      :ok = Memory.put("k#{i}", i, 1000, state)
    end

    assert :ok = Memory.clear(:all, state)
    assert 0 == :ets.info(state.table, :size)
  end

  test "clear pattern removes only matching keys", %{state: state} do
    :ok = Memory.put("user:1", 1, 1000, state)
    :ok = Memory.put("user:2", 2, 1000, state)
    :ok = Memory.put("order:1", 3, 1000, state)

    assert :ok = Memory.clear("user:*", state)

    # Only order:1 should remain
    keys = state.table |> :ets.tab2list() |> Enum.map(fn {k, _v, _e} -> k end) |> Enum.sort()
    assert keys == ["order:1"]
  end

  test "cleanup removes expired entries only", %{state: state} do
    :ok = Memory.put("e1", :expired, 10, state)
    :ok = Memory.put("ok1", :ok, 200, state)
    :timer.sleep(30)

    assert :ok = Memory.cleanup(state)

    remaining = state.table |> :ets.tab2list() |> Enum.map(fn {k, _v, _e} -> k end) |> Enum.sort()
    assert remaining == ["ok1"]
  end

  test "stats reports accurate size and utilization", %{state: state} do
    for i <- 1..3, do: Memory.put("s#{i}", i, 1000, state)

    assert {:ok, stats} = Memory.stats(state)
    assert stats.size == 3
    assert stats.max_size == 10
    assert is_integer(stats.memory_usage_bytes)
    assert_in_delta stats.utilization, 0.3, 0.0001
  end

  test "evicts when current size reaches max_size before insert", %{state: state} do
    # Fill to max_size with long TTL so none expire
    for i <- 1..10 do
      :ok = Memory.put("k#{i}", i, 5_000, state)
      # small sleep to ensure increasing expires_at ordering
      :timer.sleep(1)
    end

    # Size should be at max
    assert :ets.info(state.table, :size) == 10

    # Next put triggers maybe_evict_entries (evict 10% = 1), then inserts one -> size stays 10
    :ok = Memory.put("k_new", :new, 5_000, state)

    size = :ets.info(state.table, :size)
    assert size == 10

    keys = state.table |> :ets.tab2list() |> Enum.map(fn {k, _v, _e} -> k end)
    # At least one of the original keys should be gone
    refute Enum.all?(for i <- 1..10, do: "k#{i}" in keys)
    assert "k_new" in keys
  end
end
