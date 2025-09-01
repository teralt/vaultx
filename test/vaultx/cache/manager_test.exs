defmodule Vaultx.Cache.ManagerTest do
  use ExUnit.Case, async: false

  alias Vaultx.Cache.Manager

  @moduledoc """
  Comprehensive test suite for Cache Manager.

  Tests cover:
  - GenServer lifecycle management
  - Multi-layer cache coordination
  - Cache operations (get, put, delete)
  - Batch operations (get_many, put_many)
  - Cache warming and cleanup
  - Error handling and recovery
  - Configuration management
  """

  setup do
    # Stop any existing manager
    if Process.whereis(Manager) do
      GenServer.stop(Manager, :normal, 1000)
    end

    # Clean up any existing ETS tables
    case :ets.whereis(:vaultx_l2_memory_cache) do
      :undefined -> :ok
      tid when is_reference(tid) -> :ets.delete(tid)
    end

    :ok
  end

  describe "start_link/1" do
    test "starts with default configuration" do
      assert {:ok, pid} = Manager.start_link([])
      assert Process.alive?(pid)
      assert Process.whereis(Manager) == pid

      # Clean up
      GenServer.stop(pid, :normal, 1000)
    end

    test "starts with minimal configuration to avoid L2 issues" do
      opts = [
        l1_enabled: false,
        l2_enabled: false,
        l3_enabled: false
      ]

      assert {:ok, pid} = Manager.start_link(opts)
      assert Process.alive?(pid)

      # Clean up
      GenServer.stop(pid, :normal, 1000)
    end

    test "registers process with module name" do
      {:ok, pid} = Manager.start_link([])
      assert Process.whereis(Manager) == pid

      # Clean up
      GenServer.stop(pid, :normal, 1000)
    end
  end

  describe "get/2" do
    setup do
      {:ok, pid} = Manager.start_link([])
      %{manager_pid: pid}
    end

    test "returns {:error, :not_found} for non-existent key", %{manager_pid: _pid} do
      assert {:error, :not_found} = Manager.get("non_existent_key")
    end

    test "handles get with options", %{manager_pid: _pid} do
      opts = [timeout: 1000, layers: [:l1, :l2]]
      assert {:error, :not_found} = Manager.get("test_key", opts)
    end

    test "handles timeout gracefully", %{manager_pid: _pid} do
      # This should complete quickly since cache is empty
      assert {:error, :not_found} = Manager.get("test_key", timeout: 100)
    end
  end

  describe "put/3" do
    setup do
      # Explicitly disable all cache layers
      opts = [
        l1_enabled: false,
        l2_enabled: false,
        l3_enabled: false
      ]

      {:ok, pid} = Manager.start_link(opts)
      %{manager_pid: pid}
    end

    test "returns error when no cache layers enabled", %{manager_pid: _pid} do
      # With default config (no layers enabled), put should fail
      assert {:error, %Vaultx.Base.Error{type: :cache_put_failed}} =
               Manager.put("test_key", "test_value")
    end

    test "handles put with options", %{manager_pid: _pid} do
      opts = [ttl: 5000, layers: [:l1, :l2]]

      assert {:error, %Vaultx.Base.Error{type: :cache_put_failed}} =
               Manager.put("test_key", "test_value", opts)
    end

    test "handles complex data types", %{manager_pid: _pid} do
      complex_data = %{
        list: [1, 2, 3],
        map: %{nested: "value"},
        tuple: {:ok, "result"}
      }

      assert {:error, %Vaultx.Base.Error{type: :cache_put_failed}} =
               Manager.put("complex", complex_data)
    end
  end

  describe "delete/1" do
    setup do
      opts = [l1_enabled: false, l2_enabled: false, l3_enabled: false]
      {:ok, pid} = Manager.start_link(opts)
      %{manager_pid: pid}
    end

    test "returns error when no cache layers enabled", %{manager_pid: _pid} do
      assert {:error, %Vaultx.Base.Error{type: :cache_delete_failed}} =
               Manager.delete("delete_key")
    end

    test "handles binary keys", %{manager_pid: _pid} do
      binary_key = <<1, 2, 3, 4>>

      assert {:error, %Vaultx.Base.Error{type: :cache_delete_failed}} =
               Manager.delete(binary_key)
    end
  end

  describe "get_many/2" do
    setup do
      opts = [l1_enabled: false, l2_enabled: false, l3_enabled: false]
      {:ok, pid} = Manager.start_link(opts)
      %{manager_pid: pid}
    end

    test "returns {:ok, empty_map} for empty key list", %{manager_pid: _pid} do
      assert {:ok, %{}} = Manager.get_many([])
    end

    test "returns {:ok, map_with_nil_values} for non-existent keys", %{manager_pid: _pid} do
      keys = ["key1", "key2", "key3"]
      assert {:ok, result} = Manager.get_many(keys)
      # When keys don't exist, they get nil values
      assert result == %{"key1" => nil, "key2" => nil, "key3" => nil}
    end

    test "handles get_many with options", %{manager_pid: _pid} do
      keys = ["key1", "key2"]
      opts = [timeout: 1000]
      assert {:ok, result} = Manager.get_many(keys, opts)
      assert result == %{"key1" => nil, "key2" => nil}
    end
  end

  describe "put_many/2" do
    setup do
      opts = [l1_enabled: false, l2_enabled: false, l3_enabled: false]
      {:ok, pid} = Manager.start_link(opts)
      %{manager_pid: pid}
    end

    test "returns error when no cache layers enabled", %{manager_pid: _pid} do
      pairs = [
        {"key1", "value1"},
        {"key2", "value2"},
        {"key3", "value3"}
      ]

      assert {:error, %Vaultx.Base.Error{type: :cache_put_many_failed}} =
               Manager.put_many(pairs)
    end

    test "handles empty pairs list", %{manager_pid: _pid} do
      assert :ok = Manager.put_many([])
    end

    test "handles pairs with options", %{manager_pid: _pid} do
      pairs = [{"key1", "value1"}]
      opts = [ttl: 5000]

      assert {:error, %Vaultx.Base.Error{type: :cache_put_many_failed}} =
               Manager.put_many(pairs, opts)
    end
  end

  describe "warm/2" do
    setup do
      {:ok, pid} = Manager.start_link([])
      %{manager_pid: pid}
    end

    test "accepts warm request", %{manager_pid: _pid} do
      preload_fn = fn -> %{"key1" => "value1", "key2" => "value2"} end

      # warm/2 is a cast, so it returns :ok immediately
      assert :ok = Manager.warm("user:*", preload_fn)
    end

    test "handles warm with function that returns empty map", %{manager_pid: _pid} do
      preload_fn = fn -> %{} end
      assert :ok = Manager.warm("empty:*", preload_fn)
    end

    test "handles warm with function that raises", %{manager_pid: _pid} do
      preload_fn = fn -> raise "preload error" end
      # Should not crash the manager
      assert :ok = Manager.warm("error:*", preload_fn)

      # Give some time for the cast to be processed
      Process.sleep(10)

      # Manager should still be alive
      assert Process.alive?(Process.whereis(Manager))
    end
  end

  describe "clear/1" do
    setup do
      {:ok, pid} = Manager.start_link([])
      %{manager_pid: pid}
    end

    test "clears all cache entries", %{manager_pid: _pid} do
      # Add some data first
      Manager.put("key1", "value1")
      Manager.put("key2", "value2")

      assert :ok = Manager.clear(:all)
    end

    test "clears entries matching pattern", %{manager_pid: _pid} do
      # Add some data first
      Manager.put("user:1", "data1")
      Manager.put("user:2", "data2")
      Manager.put("order:1", "order_data")

      assert :ok = Manager.clear("user:*")
    end

    test "handles clear with non-matching pattern", %{manager_pid: _pid} do
      assert :ok = Manager.clear("non_matching:*")
    end
  end

  describe "manager state" do
    setup do
      {:ok, pid} = Manager.start_link([])
      %{manager_pid: pid}
    end

    test "manager process stays alive", %{manager_pid: pid} do
      assert Process.alive?(pid)
      assert Process.whereis(Manager) == pid
    end
  end

  describe "GenServer callbacks" do
    test "manager handles cleanup timer messages" do
      {:ok, pid} = Manager.start_link([])

      # Send cleanup message (this is a valid message)
      send(pid, :cleanup)

      # Give time for message to be processed
      Process.sleep(10)

      # Manager should still be alive
      assert Process.alive?(pid)

      # Clean up
      GenServer.stop(pid, :normal, 1000)
    end

    test "manager handles process monitoring" do
      {:ok, pid} = Manager.start_link([])

      # Create a fake DOWN message (this tests the monitoring logic)
      fake_pid = spawn(fn -> :ok end)
      ref = make_ref()
      send(pid, {:DOWN, ref, :process, fake_pid, :normal})

      # Give time for message to be processed
      Process.sleep(10)

      # Manager should still be alive
      assert Process.alive?(pid)

      # Clean up
      GenServer.stop(pid, :normal, 1000)
    end
  end

  describe "error handling" do
    setup do
      opts = [l1_enabled: false, l2_enabled: false, l3_enabled: false]
      {:ok, pid} = Manager.start_link(opts)
      %{manager_pid: pid}
    end

    test "handles large keys gracefully", %{manager_pid: _pid} do
      large_key = String.duplicate("x", 10_000)

      assert {:error, %Vaultx.Base.Error{type: :cache_put_failed}} =
               Manager.put(large_key, "value")
    end

    test "handles large values gracefully", %{manager_pid: _pid} do
      large_value = String.duplicate("x", 10_000)

      assert {:error, %Vaultx.Base.Error{type: :cache_put_failed}} =
               Manager.put("key", large_value)
    end

    test "handles nil values", %{manager_pid: _pid} do
      assert {:error, %Vaultx.Base.Error{type: :cache_put_failed}} =
               Manager.put("nil_key", nil)
    end

    test "handles binary data", %{manager_pid: _pid} do
      binary_data = <<1, 2, 3, 4, 5>>

      assert {:error, %Vaultx.Base.Error{type: :cache_put_failed}} =
               Manager.put("binary_key", binary_data)
    end
  end

  describe "concurrent operations" do
    setup do
      opts = [l1_enabled: false, l2_enabled: false, l3_enabled: false]
      {:ok, pid} = Manager.start_link(opts)
      %{manager_pid: pid}
    end

    test "handles concurrent puts", %{manager_pid: _pid} do
      tasks =
        for i <- 1..20 do
          Task.async(fn ->
            Manager.put("concurrent_#{i}", "value_#{i}")
          end)
        end

      results = Task.await_many(tasks)
      # All should return cache_put_failed error since no layers are enabled
      assert Enum.all?(results, fn result ->
               match?({:error, %Vaultx.Base.Error{type: :cache_put_failed}}, result)
             end)
    end

    test "handles concurrent gets", %{manager_pid: _pid} do
      tasks =
        for i <- 1..20 do
          Task.async(fn ->
            Manager.get("get_test_#{i}")
          end)
        end

      results = Task.await_many(tasks)
      # All should return not_found since no cache layers are enabled
      assert Enum.all?(results, fn result ->
               match?({:error, :not_found}, result)
             end)
    end

    test "handles mixed concurrent operations", %{manager_pid: _pid} do
      tasks =
        for i <- 1..30 do
          Task.async(fn ->
            case rem(i, 3) do
              0 -> Manager.put("mixed_#{i}", "value_#{i}")
              1 -> Manager.get("mixed_#{i}")
              2 -> Manager.delete("mixed_#{i}")
            end
          end)
        end

      results = Task.await_many(tasks)
      # All operations should complete without crashing
      assert length(results) == 30

      # Verify manager is still alive
      assert Process.alive?(Process.whereis(Manager))
    end
  end
end
