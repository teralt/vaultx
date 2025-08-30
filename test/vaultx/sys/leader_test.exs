defmodule Vaultx.Sys.LeaderTest do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Sys.Leader
  alias Vaultx.Base.Error

  setup do
    # Ensure rate limiter is available if rate limiting is enabled
    # This prevents GenServer.call errors when rate limiting is configured
    config = Vaultx.Base.Config.get()

    if config.rate_limit_enabled and config.rate_limit_requests > 0 do
      unless Process.whereis(Vaultx.Base.RateLimiter) do
        {:ok, _pid} =
          Vaultx.Base.RateLimiter.start_link(
            rate: config.rate_limit_requests,
            burst: config.rate_limit_burst
          )
      end
    end

    :ok
  end

  # Sample leader status responses
  @leader_status %{
    "ha_enabled" => true,
    "is_self" => true,
    "leader_address" => "https://vault-1.example.com:8200",
    "leader_cluster_address" => "https://vault-1.example.com:8201",
    "active_time" => "2025-03-26T14:30:00Z",
    "performance_standby" => false,
    "last_wal" => 1000
  }

  @standby_status %{
    "ha_enabled" => true,
    "is_self" => false,
    "leader_address" => "https://vault-1.example.com:8200",
    "leader_cluster_address" => "https://vault-1.example.com:8201",
    "performance_standby" => true,
    "performance_standby_last_remote_wal" => 1050,
    "last_wal" => 1000
  }

  @no_ha_status %{
    "ha_enabled" => false,
    "is_self" => true,
    "leader_address" => "",
    "leader_cluster_address" => ""
  }

  @raft_status %{
    "ha_enabled" => true,
    "is_self" => true,
    "leader_address" => "https://vault-1.example.com:8200",
    "leader_cluster_address" => "https://vault-1.example.com:8201",
    "raft_committed_index" => 2000,
    "raft_applied_index" => 1999
  }

  describe "get_status/1" do
    test "gets leader status successfully" do
      expect_get(200, @leader_status, fn url, _body, _opts ->
        assert String.contains?(url, "sys/leader")
      end)

      assert {:ok, status} = Leader.get_status()
      assert status.ha_enabled == true
      assert status.is_self == true
      assert status.leader_address == "https://vault-1.example.com:8200"
      assert status.leader_cluster_address == "https://vault-1.example.com:8201"
      assert status.active_time == "2025-03-26T14:30:00Z"
      assert status.performance_standby == false
      assert status.last_wal == 1000
    end

    test "gets standby status with performance standby info" do
      expect_get(200, @standby_status, fn url, _body, _opts ->
        assert String.contains?(url, "sys/leader")
      end)

      assert {:ok, status} = Leader.get_status()
      assert status.ha_enabled == true
      assert status.is_self == false
      assert status.leader_address == "https://vault-1.example.com:8200"
      assert status.performance_standby == true
      assert status.performance_standby_last_remote_wal == 1050
      assert status.last_wal == 1000
    end

    test "gets status when HA is disabled" do
      expect_get(200, @no_ha_status, fn url, _body, _opts ->
        assert String.contains?(url, "sys/leader")
      end)

      assert {:ok, status} = Leader.get_status()
      assert status.ha_enabled == false
      assert status.is_self == true
      assert status.leader_address == ""
      assert status.leader_cluster_address == ""
      refute Map.has_key?(status, :active_time)
      refute Map.has_key?(status, :performance_standby)
    end

    test "gets status with Raft information" do
      expect_get(200, @raft_status, fn url, _body, _opts ->
        assert String.contains?(url, "sys/leader")
      end)

      assert {:ok, status} = Leader.get_status()
      assert status.ha_enabled == true
      assert status.raft_committed_index == 2000
      assert status.raft_applied_index == 1999
    end

    test "handles server errors" do
      expect_get(500, %{"errors" => ["internal server error"]})

      assert {:error, %Error{} = error} = Leader.get_status()
      assert error.type == :server_error
      assert String.contains?(error.message, "Failed to get leader status")
    end

    test "handles network errors" do
      stub_request_raw(:get, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{} = error} = Leader.get_status()
      assert error.type == :unknown_error
    end

    test "passes custom options" do
      expect_get(200, @leader_status, fn _url, _body, opts ->
        assert opts[:timeout] == 30_000
      end)

      assert {:ok, _status} = Leader.get_status(timeout: 30_000)
    end
  end

  describe "is_ha_enabled?/1" do
    test "returns true when HA is enabled" do
      expect_get(200, @leader_status)

      assert {:ok, true} = Leader.is_ha_enabled?()
    end

    test "returns false when HA is disabled" do
      expect_get(200, @no_ha_status)

      assert {:ok, false} = Leader.is_ha_enabled?()
    end

    test "handles errors" do
      expect_get(500, %{"errors" => ["server error"]})

      assert {:error, %Error{} = error} = Leader.is_ha_enabled?()
      assert error.type == :server_error
    end
  end

  describe "is_leader?/1" do
    test "returns true when current node is leader" do
      expect_get(200, @leader_status)

      assert {:ok, true} = Leader.is_leader?()
    end

    test "returns false when current node is standby" do
      expect_get(200, @standby_status)

      assert {:ok, false} = Leader.is_leader?()
    end

    test "handles errors" do
      expect_get(500, %{"errors" => ["server error"]})

      assert {:error, %Error{} = error} = Leader.is_leader?()
      assert error.type == :server_error
    end
  end

  describe "get_leader_address/1" do
    test "returns leader address" do
      expect_get(200, @leader_status)

      assert {:ok, address} = Leader.get_leader_address()
      assert address == "https://vault-1.example.com:8200"
    end

    test "returns empty string when HA disabled" do
      expect_get(200, @no_ha_status)

      assert {:ok, address} = Leader.get_leader_address()
      assert address == ""
    end

    test "handles errors" do
      expect_get(500, %{"errors" => ["server error"]})

      assert {:error, %Error{} = error} = Leader.get_leader_address()
      assert error.type == :server_error
    end
  end

  describe "get_performance_standby_info/1" do
    test "returns performance standby info when node is performance standby" do
      expect_get(200, @standby_status)

      assert {:ok, perf_info} = Leader.get_performance_standby_info()
      assert perf_info.is_performance_standby == true
      # 1050 - 1000
      assert perf_info.wal_lag == 50
    end

    test "returns non-performance standby info when node is leader" do
      expect_get(200, @leader_status)

      assert {:ok, perf_info} = Leader.get_performance_standby_info()
      assert perf_info.is_performance_standby == false
      assert perf_info.wal_lag == 0
    end

    test "handles missing performance standby fields" do
      minimal_status = %{
        "ha_enabled" => true,
        "is_self" => false,
        "leader_address" => "https://vault-1.example.com:8200",
        "leader_cluster_address" => "https://vault-1.example.com:8201"
      }

      expect_get(200, minimal_status)

      assert {:ok, perf_info} = Leader.get_performance_standby_info()
      assert perf_info.is_performance_standby == false
      assert perf_info.wal_lag == 0
    end

    test "calculates WAL lag correctly" do
      status_with_lag =
        @standby_status
        |> Map.put("performance_standby_last_remote_wal", 2000)
        |> Map.put("last_wal", 1800)

      expect_get(200, status_with_lag)

      assert {:ok, perf_info} = Leader.get_performance_standby_info()
      # 2000 - 1800
      assert perf_info.wal_lag == 200
    end

    test "handles negative WAL lag" do
      status_with_negative_lag =
        @standby_status
        |> Map.put("performance_standby_last_remote_wal", 1000)
        |> Map.put("last_wal", 1200)

      expect_get(200, status_with_negative_lag)

      assert {:ok, perf_info} = Leader.get_performance_standby_info()
      # max(0, 1000 - 1200)
      assert perf_info.wal_lag == 0
    end

    test "handles errors" do
      expect_get(500, %{"errors" => ["server error"]})

      assert {:error, %Error{} = error} = Leader.get_performance_standby_info()
      assert error.type == :server_error
    end
  end

  describe "get_raft_info/1" do
    test "returns Raft info when available" do
      expect_get(200, @raft_status)

      assert {:ok, raft_info} = Leader.get_raft_info()
      assert raft_info.has_raft_info == true
      assert raft_info.committed_index == 2000
      assert raft_info.applied_index == 1999
    end

    test "returns no Raft info when not using Raft" do
      expect_get(200, @leader_status)

      assert {:ok, raft_info} = Leader.get_raft_info()
      assert raft_info.has_raft_info == false
      assert raft_info.committed_index == 0
      assert raft_info.applied_index == 0
    end

    test "handles partial Raft info" do
      partial_raft_status = Map.put(@leader_status, "raft_committed_index", 1500)

      expect_get(200, partial_raft_status)

      assert {:ok, raft_info} = Leader.get_raft_info()
      # Both indices required
      assert raft_info.has_raft_info == false
      assert raft_info.committed_index == 1500
      assert raft_info.applied_index == 0
    end

    test "handles errors" do
      expect_get(500, %{"errors" => ["server error"]})

      assert {:error, %Error{} = error} = Leader.get_raft_info()
      assert error.type == :server_error
    end
  end

  describe "edge cases and error scenarios" do
    test "handles null values in response" do
      null_response = %{
        "ha_enabled" => true,
        "is_self" => true,
        "leader_address" => nil,
        "leader_cluster_address" => nil,
        "active_time" => nil,
        "performance_standby" => nil
      }

      expect_get(200, null_response)

      assert {:ok, status} = Leader.get_status()
      assert status.leader_address == ""
      assert status.leader_cluster_address == ""
      refute Map.has_key?(status, :active_time)
      refute Map.has_key?(status, :performance_standby)
    end

    test "handles missing optional fields" do
      minimal_response = %{
        "ha_enabled" => false,
        "is_self" => true,
        "leader_address" => "https://vault.example.com:8200",
        "leader_cluster_address" => "https://vault.example.com:8201"
      }

      expect_get(200, minimal_response)

      assert {:ok, status} = Leader.get_status()
      assert status.ha_enabled == false
      assert status.is_self == true
      refute Map.has_key?(status, :active_time)
      refute Map.has_key?(status, :performance_standby)
      refute Map.has_key?(status, :last_wal)
    end

    test "handles various HTTP error codes" do
      error_codes = [400, 401, 403, 404, 500, 502, 503]

      Enum.each(error_codes, fn code ->
        expect_get(code, %{"errors" => ["error #{code}"]})

        assert {:error, %Error{} = error} = Leader.get_status()
        assert error.type == :server_error
        assert String.contains?(error.message, "HTTP #{code}")
      end)
    end

    test "handles malformed JSON response" do
      expect_get(200, "invalid json")

      # With our current implementation, malformed JSON is handled gracefully
      # by returning default values rather than throwing an error
      assert {:ok, status} = Leader.get_status()
      assert status.ha_enabled == false
      assert status.is_self == false
      assert status.leader_address == ""
      assert status.leader_cluster_address == ""
    end
  end

  describe "integration scenarios" do
    test "leader monitoring workflow" do
      # Step 1: Check if HA is enabled
      expect_get(200, @leader_status)

      assert {:ok, true} = Leader.is_ha_enabled?()

      # Step 2: Check if this node is leader
      expect_get(200, @leader_status)

      assert {:ok, true} = Leader.is_leader?()

      # Step 3: Get detailed status
      expect_get(200, @leader_status)

      assert {:ok, status} = Leader.get_status()
      assert status.active_time == "2025-03-26T14:30:00Z"
    end

    test "standby monitoring workflow" do
      # Step 1: Check leader status
      expect_get(200, @standby_status)

      assert {:ok, false} = Leader.is_leader?()

      # Step 2: Get leader address
      expect_get(200, @standby_status)

      assert {:ok, leader_addr} = Leader.get_leader_address()
      assert leader_addr == "https://vault-1.example.com:8200"

      # Step 3: Check performance standby status
      expect_get(200, @standby_status)

      assert {:ok, perf_info} = Leader.get_performance_standby_info()
      assert perf_info.is_performance_standby == true
      assert perf_info.wal_lag == 50
    end

    test "Raft cluster monitoring workflow" do
      # Check Raft-specific metrics
      expect_get(200, @raft_status)

      assert {:ok, raft_info} = Leader.get_raft_info()
      assert raft_info.has_raft_info == true

      # Monitor consensus lag
      lag = raft_info.committed_index - raft_info.applied_index
      # 2000 - 1999
      assert lag == 1
    end

    test "non-HA deployment workflow" do
      # Step 1: Check HA status
      expect_get(200, @no_ha_status)

      assert {:ok, false} = Leader.is_ha_enabled?()

      # Step 2: Verify single-node behavior
      expect_get(200, @no_ha_status)

      assert {:ok, true} = Leader.is_leader?()

      # Step 3: Check addresses are empty
      expect_get(200, @no_ha_status)

      assert {:ok, address} = Leader.get_leader_address()
      assert address == ""
    end

    test "error handling across all functions" do
      # All functions should handle errors consistently
      expect_get(500, %{"errors" => ["server error"]})
      assert {:error, %Error{type: :server_error}} = Leader.get_status()

      expect_get(500, %{"errors" => ["server error"]})
      assert {:error, %Error{type: :server_error}} = Leader.is_ha_enabled?()

      expect_get(500, %{"errors" => ["server error"]})
      assert {:error, %Error{type: :server_error}} = Leader.is_leader?()

      expect_get(500, %{"errors" => ["server error"]})
      assert {:error, %Error{type: :server_error}} = Leader.get_leader_address()

      expect_get(500, %{"errors" => ["server error"]})
      assert {:error, %Error{type: :server_error}} = Leader.get_performance_standby_info()

      expect_get(500, %{"errors" => ["server error"]})
      assert {:error, %Error{type: :server_error}} = Leader.get_raft_info()
    end

    test "custom options passed through all functions" do
      custom_opts = [timeout: 45_000]

      expect_get(200, @leader_status, fn _url, _body, opts ->
        assert opts[:timeout] == 45_000
      end)

      assert {:ok, _} = Leader.get_status(custom_opts)

      expect_get(200, @leader_status, fn _url, _body, opts ->
        assert opts[:timeout] == 45_000
      end)

      assert {:ok, _} = Leader.is_ha_enabled?(custom_opts)

      expect_get(200, @leader_status, fn _url, _body, opts ->
        assert opts[:timeout] == 45_000
      end)

      assert {:ok, _} = Leader.is_leader?(custom_opts)
    end
  end
end
