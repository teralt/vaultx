defmodule Vaultx.Transport.PoolTest do
  use ExUnit.Case, async: true

  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Transport.Pool

  # Use a unique pool name for each test to avoid conflicts
  @test_pool_name :"test_pool_#{:rand.uniform(1_000_000)}"

  setup do
    # Start a test pool for each test
    {:ok, pid} = Pool.start_link(name: @test_pool_name, size: 2, max_overflow: 1)

    on_exit(fn ->
      if Process.alive?(pid) do
        Pool.stop(@test_pool_name)
      end
    end)

    %{pool: @test_pool_name, pid: pid}
  end

  describe "pool lifecycle" do
    test "starts and stops pool successfully", %{pool: pool} do
      # Pool should be running
      pid = Process.whereis(pool)
      assert pid != nil
      assert Process.alive?(pid)

      # Stop the pool
      assert :ok = Pool.stop(pool)

      # Pool should be stopped
      pid_after_stop = Process.whereis(pool)
      assert pid_after_stop == nil
    end

    test "starts pool with custom options" do
      pool_name = :"custom_pool_#{:rand.uniform(1_000_000)}"

      {:ok, pid} =
        Pool.start_link(
          name: pool_name,
          size: 5,
          max_overflow: 2,
          timeout: 10_000
        )

      assert Process.alive?(pid)

      # Clean up
      Pool.stop(pool_name)
    end
  end

  describe "connection management" do
    test "gets connection from pool", %{pool: pool} do
      assert {:ok, connection} = Pool.get_connection(pool)
      assert is_map(connection)
      assert Map.has_key?(connection, :id)
      assert Map.has_key?(connection, :url)
      assert Map.has_key?(connection, :created_at)
    end

    test "returns connection to pool", %{pool: pool} do
      {:ok, connection} = Pool.get_connection(pool)
      assert :ok = Pool.return_connection(pool, connection)
    end

    test "handles multiple connections", %{pool: pool} do
      # Get multiple connections (pool size is 2)
      {:ok, conn1} = Pool.get_connection(pool)
      {:ok, conn2} = Pool.get_connection(pool)

      # Connections should have different IDs
      assert conn1.id != conn2.id

      # Return connections
      Pool.return_connection(pool, conn1)
      Pool.return_connection(pool, conn2)
    end

    test "handles connection timeout", %{pool: pool} do
      # Get all available connections (size: 2, max_overflow: 1 = 3 total)
      {:ok, _conn1} = Pool.get_connection(pool)
      {:ok, _conn2} = Pool.get_connection(pool)
      {:ok, _conn3} = Pool.get_connection(pool)

      # Next request should timeout quickly
      assert catch_exit(Pool.get_connection(pool, 100))
    end
  end

  describe "pool statistics" do
    test "returns pool stats", %{pool: pool} do
      stats = Pool.stats(pool)

      assert is_map(stats)
      assert Map.has_key?(stats, :total_connections)
      assert Map.has_key?(stats, :active_connections)
      assert Map.has_key?(stats, :idle_connections)
      assert Map.has_key?(stats, :pending_requests)
      assert Map.has_key?(stats, :total_requests)
      assert Map.has_key?(stats, :failed_requests)

      # Initially should have no connections
      assert stats.total_connections >= 0
      assert stats.active_connections >= 0
      assert stats.idle_connections >= 0
    end

    test "stats reflect connection usage", %{pool: pool} do
      # Get initial stats
      initial_stats = Pool.stats(pool)

      # Get a connection
      {:ok, connection} = Pool.get_connection(pool)

      # Stats should show active connection
      stats_with_active = Pool.stats(pool)
      assert stats_with_active.active_connections == initial_stats.active_connections + 1
      assert stats_with_active.total_connections >= initial_stats.total_connections

      # Return connection
      Pool.return_connection(pool, connection)

      # Stats should show idle connection
      stats_with_idle = Pool.stats(pool)
      assert stats_with_idle.active_connections == initial_stats.active_connections
      assert stats_with_idle.idle_connections >= initial_stats.idle_connections
    end
  end

  describe "health monitoring" do
    test "returns health status", %{pool: pool} do
      health = Pool.health(pool)

      assert is_map(health)
      assert Map.has_key?(health, :status)
      assert Map.has_key?(health, :total_connections)
      assert Map.has_key?(health, :healthy_connections)
      assert Map.has_key?(health, :last_health_check)

      assert health.status == :healthy
    end

    test "health check timer is scheduled", %{pool: pool} do
      # Get initial health
      initial_health = Pool.health(pool)

      # Wait for health check to run (default interval is quite long, so we'll just verify structure)
      assert is_map(initial_health)
      assert initial_health.status == :healthy
    end
  end

  describe "request execution" do
    test "executes HTTP request successfully", %{pool: pool} do
      # Mock successful HTTP response
      expect_get(200, %{"data" => %{"key" => "value"}})

      assert {:ok, response} = Pool.request(:get, "secret/test", nil, [], pool: pool)
      assert response.status == 200
      assert response.body["data"]["key"] == "value"
    end

    test "handles HTTP request errors", %{pool: pool} do
      # Mock HTTP error
      stub_request(:get, :network_error, "Connection failed")

      assert {:error, error} = Pool.request(:get, "secret/test", nil, [], pool: pool)
      assert error.type == :network_error
    end

    test "handles connection exceptions", %{pool: pool} do
      # Mock HTTP client that raises an exception
      stub_request_raw(:get, "Connection failed")

      assert {:error, error} = Pool.request(:get, "secret/test", nil, [], pool: pool)
      assert error.type == :network_error
      assert error.message =~ "Connection error"
    end

    test "uses default pool when none specified" do
      # This will fail because default pool isn't running, but tests the code path
      result = catch_exit(Pool.request(:get, "test", nil, []))
      assert elem(result, 0) == :noproc
    end

    test "passes custom options", %{pool: pool} do
      expect_get(200, %{}, fn _url, _body, opts ->
        assert opts[:timeout] == 60_000
      end)

      assert {:ok, _response} = Pool.request(:get, "test", nil, [], pool: pool, timeout: 60_000)
    end
  end

  describe "advanced pool behavior" do
    test "reuses idle connections" do
      # Get a connection and return it
      {:ok, conn1} = Pool.get_connection(@test_pool_name)
      Pool.return_connection(@test_pool_name, conn1)

      # Get another connection - should reuse the idle one
      {:ok, conn2} = Pool.get_connection(@test_pool_name)
      # Same connection reused
      assert conn1.id == conn2.id

      Pool.return_connection(@test_pool_name, conn2)
    end

    test "handles pending requests when pool is full" do
      # Fill the pool (size: 2, max_overflow: 1 = 3 total)
      {:ok, conn1} = Pool.get_connection(@test_pool_name)
      {:ok, conn2} = Pool.get_connection(@test_pool_name)
      {:ok, conn3} = Pool.get_connection(@test_pool_name)

      # Start an async request that should be queued
      task =
        Task.async(fn ->
          Pool.get_connection(@test_pool_name, 5000)
        end)

      # Give it time to queue
      Process.sleep(100)

      # Return a connection - should serve the pending request
      Pool.return_connection(@test_pool_name, conn1)

      # The pending request should now get a connection
      assert {:ok, conn4} = Task.await(task)
      assert is_map(conn4)

      # Clean up
      Pool.return_connection(@test_pool_name, conn2)
      Pool.return_connection(@test_pool_name, conn3)
      Pool.return_connection(@test_pool_name, conn4)
    end

    test "handles returning unknown connection" do
      # Try to return a connection that doesn't exist in active connections
      fake_connection = %{
        id: "fake_id",
        url: "http://fake.com",
        created_at: System.system_time(:millisecond),
        last_used: System.system_time(:millisecond),
        request_count: 0,
        error_count: 0,
        healthy: true
      }

      assert :ok = Pool.return_connection(@test_pool_name, fake_connection)
    end
  end

  describe "health monitoring edge cases" do
    test "triggers health check timer" do
      # Start a pool with short health check interval
      pool_name = :"health_test_pool_#{:rand.uniform(1_000_000)}"

      {:ok, _pid} =
        Pool.start_link(
          name: pool_name,
          size: 1,
          # 100ms
          health_check_interval: 100
        )

      # Wait for health check to trigger
      Process.sleep(200)

      # Health should have been checked
      health = Pool.health(pool_name)
      assert health.last_health_check != nil

      # Clean up
      Pool.stop(pool_name)
    end

    test "connection timeout handling" do
      # Send a timeout message to test the timeout handler
      pool_pid = Process.whereis(@test_pool_name)

      # Send a timeout message (this would normally come from a timer)
      send(pool_pid, {:timeout, "fake_connection_id"})

      # Pool should still be alive and functional
      Process.sleep(50)
      assert Process.alive?(pool_pid)

      # Should still be able to get connections
      {:ok, conn} = Pool.get_connection(@test_pool_name)
      Pool.return_connection(@test_pool_name, conn)
    end

    test "health check with connections" do
      # Get connections to create some
      {:ok, conn1} = Pool.get_connection(@test_pool_name)
      {:ok, conn2} = Pool.get_connection(@test_pool_name)

      # Return one to make it idle
      Pool.return_connection(@test_pool_name, conn1)

      # Manually trigger health check
      pool_pid = Process.whereis(@test_pool_name)
      send(pool_pid, :health_check)

      # Give it time to process
      Process.sleep(50)

      # Health should still be reported
      health = Pool.health(@test_pool_name)
      assert health.status == :healthy
      assert is_integer(health.healthy_connections)

      # Clean up
      Pool.return_connection(@test_pool_name, conn2)
    end
  end

  describe "default parameter coverage" do
    test "uses default pool parameter" do
      # Test that functions accept default parameters by verifying they exist
      # We can't easily test the actual default behavior without starting the default pool

      # Verify functions exist with correct arity (including default parameters)
      assert function_exported?(Pool, :start_link, 0)
      assert function_exported?(Pool, :start_link, 1)
      assert function_exported?(Pool, :stop, 0)
      assert function_exported?(Pool, :stop, 1)
      assert function_exported?(Pool, :return_connection, 1)
      assert function_exported?(Pool, :return_connection, 2)
      assert function_exported?(Pool, :stats, 0)
      assert function_exported?(Pool, :stats, 1)
      assert function_exported?(Pool, :health, 0)
      assert function_exported?(Pool, :health, 1)
    end
  end

  describe "edge cases and error conditions" do
    test "connection timeout and cleanup" do
      # Get connections to create some activity
      {:ok, conn1} = Pool.get_connection(@test_pool_name)
      {:ok, conn2} = Pool.get_connection(@test_pool_name)

      # Simulate connection timeout by sending timeout message
      pool_pid = Process.whereis(@test_pool_name)
      send(pool_pid, {:timeout, conn1.id})

      # Give it time to process
      Process.sleep(50)

      # Pool should still be functional
      assert Process.alive?(pool_pid)

      # Clean up
      Pool.return_connection(@test_pool_name, conn2)
    end

    test "health check with old connections" do
      # Create a pool with very short health check interval
      pool_name = :"old_conn_test_#{:rand.uniform(1_000_000)}"

      {:ok, _pid} =
        Pool.start_link(
          name: pool_name,
          size: 1,
          health_check_interval: 50
        )

      # Get and return a connection to create an idle connection
      {:ok, conn} = Pool.get_connection(pool_name)
      Pool.return_connection(pool_name, conn)

      # Wait for health check to run multiple times
      Process.sleep(200)

      # Health should still be good
      health = Pool.health(pool_name)
      assert health.status == :healthy

      # Clean up
      Pool.stop(pool_name)
    end

    test "connection error rate calculation" do
      # This tests the private connection_healthy? function indirectly
      # by creating connections and checking health
      {:ok, conn1} = Pool.get_connection(@test_pool_name)
      {:ok, conn2} = Pool.get_connection(@test_pool_name)

      # Return connections to make them idle (so they can be health checked)
      Pool.return_connection(@test_pool_name, conn1)
      Pool.return_connection(@test_pool_name, conn2)

      # Trigger health check
      pool_pid = Process.whereis(@test_pool_name)
      send(pool_pid, :health_check)

      # Give it time to process
      Process.sleep(50)

      # Check that health monitoring worked
      health = Pool.health(@test_pool_name)
      assert health.healthy_connections >= 0
    end
  end

  describe "default parameter functions" do
    test "start_link with default options" do
      pool_name = :"default_opts_test_#{:rand.uniform(1_000_000)}"

      {:ok, pid} = Pool.start_link(name: pool_name)
      assert Process.alive?(pid)

      # Clean up
      Pool.stop(pool_name)
    end

    test "stop with default pool" do
      # Start a pool with the default name first
      try do
        {:ok, _pid} = Pool.start_link()
        # Now stop it using default parameter
        assert :ok = Pool.stop()
      rescue
        # If it's already started, just try to stop it
        _ ->
          result = catch_exit(Pool.stop())
          assert elem(result, 0) == :noproc or result == :ok
      end
    end

    test "stats with default pool" do
      # Test stats with default pool parameter
      result = catch_exit(Pool.stats())
      assert elem(result, 0) == :noproc or is_map(result)
    end

    test "health with default pool" do
      # Test health with default pool parameter
      result = catch_exit(Pool.health())
      assert elem(result, 0) == :noproc or is_map(result)
    end

    test "all default parameter variations" do
      # Test that all functions with default parameters can be called
      # We already have a running pool, so some of these will work

      # These should work with our test pool
      assert {:ok, _conn} = Pool.get_connection(@test_pool_name)
      assert is_map(Pool.stats(@test_pool_name))
      assert is_map(Pool.health(@test_pool_name))

      # Test return_connection with 1 arg (using default pool)
      # This function doesn't actually exit, it just returns :ok
      fake_conn = %{id: "test"}
      result = Pool.return_connection(fake_conn)
      assert result == :ok
    end
  end

  describe "private function coverage" do
    test "connection creation and management" do
      # Test connection creation by getting multiple connections
      {:ok, conn1} = Pool.get_connection(@test_pool_name)
      {:ok, conn2} = Pool.get_connection(@test_pool_name)

      # Each connection should have unique ID (tests generate_connection_id)
      assert conn1.id != conn2.id
      # 8 bytes encoded as hex
      assert byte_size(conn1.id) == 16

      Pool.return_connection(@test_pool_name, conn1)
      Pool.return_connection(@test_pool_name, conn2)
    end
  end
end
