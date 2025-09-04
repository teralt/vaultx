defmodule Vaultx.Cache.L2Test do
  use ExUnit.Case, async: false

  alias Vaultx.Cache.L2

  @moduledoc """
  Basic test suite for L2 cache layer.

  Tests cover:
  - GenServer lifecycle management
  - Basic cache operations
  - Error handling
  """

  setup do
    # Stop any existing L2 process
    if Process.whereis(L2) do
      GenServer.stop(L2, :normal, 1000)
    end

    # Clean up any existing ETS tables
    case :ets.whereis(:vaultx_l2_memory_cache) do
      :undefined -> :ok
      tid when is_reference(tid) -> :ets.delete(tid)
    end

    :ok
  end

  describe "start_link/1" do
    test "starts with memory adapter configuration" do
      config = %{
        l2_enabled: true,
        l2_adapter: Vaultx.Cache.Adapters.Memory,
        l2_max_size: 1000,
        l2_ttl_default: 300_000
      }

      assert {:ok, pid} = L2.start_link(config)
      assert Process.alive?(pid)
      assert Process.whereis(L2) == pid

      # Clean up
      GenServer.stop(pid, :normal, 1000)
    end

    test "fails to start with invalid adapter" do
      config = %{
        l2_enabled: true,
        l2_adapter: :invalid_adapter,
        l2_max_size: 1000
      }

      # This should crash during initialization
      Process.flag(:trap_exit, true)
      assert {:error, _reason} = L2.start_link(config)
    end
  end

  describe "basic operations with memory adapter" do
    setup do
      config = %{
        l2_enabled: true,
        l2_adapter: Vaultx.Cache.Adapters.Memory,
        l2_max_size: 100,
        l2_ttl_default: 300_000
      }

      {:ok, pid} = L2.start_link(config)
      %{l2_pid: pid}
    end

    test "put and get operations", %{l2_pid: _pid} do
      assert :ok = L2.put("test_key", "test_value", ttl: 5000)
      assert {:ok, "test_value"} = L2.get("test_key")
    end

    test "get non-existent key returns not_found", %{l2_pid: _pid} do
      assert {:error, :not_found} = L2.get("non_existent")
    end

    test "delete operation", %{l2_pid: _pid} do
      L2.put("delete_key", "delete_value", ttl: 5000)
      assert {:ok, "delete_value"} = L2.get("delete_key")

      assert :ok = L2.delete("delete_key")
      assert {:error, :not_found} = L2.get("delete_key")
    end

    test "clear all operation", %{l2_pid: _pid} do
      L2.put("key1", "value1", ttl: 5000)
      L2.put("key2", "value2", ttl: 5000)

      assert :ok = L2.clear(:all)

      assert {:error, :not_found} = L2.get("key1")
      assert {:error, :not_found} = L2.get("key2")
    end

    test "clear pattern operation", %{l2_pid: _pid} do
      L2.put("user:1", "data1", ttl: 5000)
      L2.put("user:2", "data2", ttl: 5000)
      L2.put("order:1", "order_data", ttl: 5000)

      assert :ok = L2.clear("user:*")

      assert {:error, :not_found} = L2.get("user:1")
      assert {:error, :not_found} = L2.get("user:2")
      assert {:ok, "order_data"} = L2.get("order:1")
    end

    test "cleanup operation", %{l2_pid: _pid} do
      # Put some data
      L2.put("cleanup_key", "cleanup_value", ttl: 5000)

      # Cleanup should not crash
      assert :ok = L2.cleanup()
    end

    test "stats operation", %{l2_pid: _pid} do
      # Add some data
      L2.put("stats_key", "stats_value", ttl: 5000)

      # L2.stats() returns a map directly, not {:ok, stats}
      stats = L2.stats()
      assert is_map(stats)
      assert Map.has_key?(stats, :size)
      assert Map.has_key?(stats, :max_size)
    end
  end

  describe "error handling" do
    setup do
      config = %{
        l2_enabled: true,
        l2_adapter: Vaultx.Cache.Adapters.Memory,
        l2_max_size: 100,
        l2_ttl_default: 300_000
      }

      {:ok, pid} = L2.start_link(config)
      %{l2_pid: pid}
    end

    test "handles large keys gracefully", %{l2_pid: _pid} do
      large_key = String.duplicate("x", 1000)
      assert :ok = L2.put(large_key, "value", ttl: 5000)
      assert {:ok, "value"} = L2.get(large_key)
    end

    test "handles large values gracefully", %{l2_pid: _pid} do
      large_value = String.duplicate("x", 1000)
      assert :ok = L2.put("key", large_value, ttl: 5000)
      assert {:ok, ^large_value} = L2.get("key")
    end

    test "handles binary data", %{l2_pid: _pid} do
      binary_key = <<1, 2, 3, 4>>
      binary_value = <<5, 6, 7, 8>>

      assert :ok = L2.put(binary_key, binary_value, ttl: 5000)
      assert {:ok, ^binary_value} = L2.get(binary_key)
    end

    test "handles nil values", %{l2_pid: _pid} do
      assert :ok = L2.put("nil_key", nil, ttl: 5000)
      assert {:ok, nil} = L2.get("nil_key")
    end
  end

  describe "concurrent operations" do
    setup do
      config = %{
        l2_enabled: true,
        l2_adapter: Vaultx.Cache.Adapters.Memory,
        l2_max_size: 1000,
        l2_ttl_default: 300_000
      }

      {:ok, pid} = L2.start_link(config)
      %{l2_pid: pid}
    end

    test "handles concurrent puts", %{l2_pid: _pid} do
      tasks =
        for i <- 1..20 do
          Task.async(fn ->
            L2.put("concurrent_#{i}", "value_#{i}", ttl: 5000)
          end)
        end

      results = Task.await_many(tasks)
      assert Enum.all?(results, &(&1 == :ok))
    end

    test "handles concurrent gets", %{l2_pid: _pid} do
      # First put some data
      for i <- 1..10 do
        L2.put("get_test_#{i}", "value_#{i}", ttl: 5000)
      end

      tasks =
        for i <- 1..20 do
          Task.async(fn ->
            L2.get("get_test_#{rem(i, 10) + 1}")
          end)
        end

      results = Task.await_many(tasks)
      # All should either succeed or return not_found
      assert Enum.all?(results, fn result ->
               match?({:ok, _}, result) or match?({:error, :not_found}, result)
             end)
    end

    test "handles mixed concurrent operations", %{l2_pid: _pid} do
      tasks =
        for i <- 1..30 do
          Task.async(fn ->
            case rem(i, 3) do
              0 -> L2.put("mixed_#{i}", "value_#{i}", ttl: 5000)
              1 -> L2.get("mixed_#{i}")
              2 -> L2.delete("mixed_#{i}")
            end
          end)
        end

      results = Task.await_many(tasks)
      # All operations should complete without crashing
      assert length(results) == 30

      # Verify L2 process is still alive
      assert Process.alive?(Process.whereis(L2))
    end
  end

  describe "TTL handling" do
    setup do
      config = %{
        l2_enabled: true,
        l2_adapter: Vaultx.Cache.Adapters.Memory,
        l2_max_size: 100,
        l2_ttl_default: 300_000
      }

      {:ok, pid} = L2.start_link(config)
      %{l2_pid: pid}
    end

    test "respects TTL values", %{l2_pid: _pid} do
      # Put with very short TTL
      assert :ok = L2.put("short_ttl", "value", ttl: 1)

      # Wait for expiration
      Process.sleep(10)

      # Should be expired
      assert {:error, :not_found} = L2.get("short_ttl")
    end

    test "uses default TTL when not specified", %{l2_pid: _pid} do
      # This test assumes the adapter supports default TTL
      # The exact behavior depends on the adapter implementation
      assert :ok = L2.put("default_ttl", "value")
      assert {:ok, "value"} = L2.get("default_ttl")
    end
  end
end
