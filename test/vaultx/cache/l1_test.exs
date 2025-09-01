defmodule Vaultx.Cache.L1Test do
  use ExUnit.Case, async: false

  alias Vaultx.Cache.L1

  @table_name :vaultx_l1_cache
  @access_table :vaultx_l1_access

  defp stop_server do
    pid = Process.whereis(Vaultx.Cache.L1)
    if is_pid(pid), do: Process.exit(pid, :kill)
  end

  setup do
    stop_server()
    {:ok, _pid} = L1.start_link(%{l1_max_size: 5, l1_cleanup_interval: 50})

    on_exit(fn ->
      stop_server()
      # ensure ETS tables are dropped
      case :ets.whereis(@table_name) do
        :undefined -> :ok
        tid -> :ets.delete(tid)
      end

      case :ets.whereis(@access_table) do
        :undefined -> :ok
        tid -> :ets.delete(tid)
      end
    end)

    :ok
  end

  test "put and get non-expired value" do
    assert :ok = L1.put("a", 1, ttl: 200)
    assert {:ok, 1} = L1.get("a")
  end

  test "put without ttl uses default config ttl" do
    assert :ok = L1.put("a_default", 123)
    assert {:ok, 123} = L1.get("a_default")
  end

  test "get missing returns not_found" do
    assert {:error, :not_found} = L1.get("missing")
  end

  test "expired value is removed and returns not_found" do
    :ok = L1.put("b", 2, ttl: 10)
    :timer.sleep(20)
    assert {:error, :not_found} = L1.get("b")
    # ensure access table also cleaned
    assert [] == :ets.lookup(@access_table, "b")
  end

  test "delete removes both tables" do
    :ok = L1.put("c", 3, ttl: 200)
    assert {:ok, 3} = L1.get("c")
    assert :ok = L1.delete("c")
    assert {:error, :not_found} = L1.get("c")
    assert [] == :ets.lookup(@access_table, "c")
  end

  test "clear :all empties tables and resets size" do
    for i <- 1..3, do: L1.put("k#{i}", i, ttl: 1000)
    assert :ok = L1.clear(:all)
    assert 0 == :ets.info(@table_name, :size)
    assert 0 == :ets.info(@access_table, :size)
  end

  test "clear pattern only removes matching keys" do
    L1.put("user:1", 1, ttl: 1000)
    L1.put("user:2", 2, ttl: 1000)
    L1.put("order:1", 3, ttl: 1000)

    assert :ok = L1.clear("user:*")

    keys = @table_name |> :ets.tab2list() |> Enum.map(fn {k, _v, _e} -> k end) |> Enum.sort()
    assert keys == ["order:1"]
    access_keys = @access_table |> :ets.tab2list() |> Enum.map(fn {k, _} -> k end) |> Enum.sort()
    assert access_keys == ["order:1"]
  end

  test "cleanup removes expired entries" do
    L1.put("e1", :expired, ttl: 10)
    L1.put("ok1", :ok, ttl: 200)
    :timer.sleep(30)

    # trigger cleanup via cast
    L1.cleanup()
    # give the server time to process
    :timer.sleep(20)

    keys = @table_name |> :ets.tab2list() |> Enum.map(fn {k, _v, _e} -> k end) |> Enum.sort()
    assert keys == ["ok1"]
  end

  test "scheduled cleanup via timer removes expired entries" do
    # Put a short-ttl entry and rely on scheduled cleanup (50ms)
    :ok = L1.put("e_timer", :expired, ttl: 10)
    :timer.sleep(120)
    keys = @table_name |> :ets.tab2list() |> Enum.map(fn {k, _v, _e} -> k end)
    refute "e_timer" in keys
  end

  test "stats returns expected fields" do
    for i <- 1..2, do: L1.put("s#{i}", i, ttl: 1000)
    stats = L1.stats()
    assert %{size: size, max_size: max_size, memory_usage: mem, hit_ratio: ratio} = stats
    assert size == 2
    assert max_size == 5
    assert is_integer(mem)
    assert is_float(ratio)
  end

  test "LRU eviction when reaching max size" do
    # Put keys with predictable access times
    L1.put("k1", 1, ttl: 1000)
    :timer.sleep(2)
    L1.put("k2", 2, ttl: 1000)
    :timer.sleep(2)
    L1.put("k3", 3, ttl: 1000)
    :timer.sleep(2)
    L1.put("k4", 4, ttl: 1000)
    :timer.sleep(2)
    L1.put("k5", 5, ttl: 1000)

    # Access k1 to make it most recently used
    assert {:ok, 1} = L1.get("k1")

    # Next insert should evict 10% (= max(0, 1)) least recently used: which should be k2 (oldest access)
    L1.put("k_new", :new, ttl: 1000)

    keys = @table_name |> :ets.tab2list() |> Enum.map(fn {k, _v, _e} -> k end)

    assert "k_new" in keys
    refute "k2" in keys
  end
end
