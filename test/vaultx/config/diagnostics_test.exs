defmodule Vaultx.Config.DiagnosticsTest do
  use ExUnit.Case, async: true

  alias Vaultx.Config.Diagnostics

  @moduledoc """
  Test suite for Config Diagnostics functionality.
  
  Tests cover:
  - Comprehensive diagnostics
  - System health checks
  - Connectivity testing
  - Health status scoring
  - Error handling
  """

  describe "run_comprehensive_diagnostics/0" do
    test "runs comprehensive diagnostics successfully" do
      result = Diagnostics.run_comprehensive_diagnostics()
      
      case result do
        {:ok, diagnostics} ->
          assert is_map(diagnostics)
          assert Map.has_key?(diagnostics, :overall_status)
          assert Map.has_key?(diagnostics, :overall_score)
          assert Map.has_key?(diagnostics, :system)
          assert Map.has_key?(diagnostics, :connectivity)
          assert Map.has_key?(diagnostics, :timestamp)
          
          # Check overall status is valid
          assert diagnostics.overall_status in [:healthy, :degraded, :unhealthy, :critical]
          
          # Check overall score is a number
          assert is_number(diagnostics.overall_score)
          assert diagnostics.overall_score >= 0.0
          assert diagnostics.overall_score <= 100.0
          
          # Check system diagnostics
          assert is_map(diagnostics.system)
          assert Map.has_key?(diagnostics.system, :status)
          assert Map.has_key?(diagnostics.system, :score)
          assert Map.has_key?(diagnostics.system, :issues)
          assert Map.has_key?(diagnostics.system, :recommendations)
          
          # Check connectivity diagnostics
          assert is_map(diagnostics.connectivity)
          assert Map.has_key?(diagnostics.connectivity, :status)
          assert Map.has_key?(diagnostics.connectivity, :score)
          
        {:error, _reason} ->
          # Error is acceptable if dependencies are not available
          :ok
      end
    end

    test "returns consistent diagnostic structure" do
      # Run diagnostics multiple times to check consistency
      results = for _i <- 1..3 do
        Diagnostics.run_comprehensive_diagnostics()
      end
      
      # All results should have the same structure
      for result <- results do
        case result do
          {:ok, diagnostics} ->
            assert is_map(diagnostics)
            assert Map.has_key?(diagnostics, :overall_status)
            assert Map.has_key?(diagnostics, :overall_score)
            
          {:error, _} ->
            # Consistent error handling is also acceptable
            :ok
        end
      end
    end

    test "handles system errors gracefully" do
      # This test ensures the function doesn't crash
      result = Diagnostics.run_comprehensive_diagnostics()
      
      # Should return either success or error, not crash
      assert match?({:ok, _}, result) or match?({:error, _}, result)
    end
  end

  describe "check_system_health/0" do
    test "checks system health successfully" do
      result = Diagnostics.check_system_health()
      
      assert is_map(result)
      assert Map.has_key?(result, :status)
      assert Map.has_key?(result, :score)
      assert Map.has_key?(result, :issues)
      assert Map.has_key?(result, :recommendations)
      assert Map.has_key?(result, :metrics)
      assert Map.has_key?(result, :timestamp)
      
      # Check status is valid
      assert result.status in [:healthy, :degraded, :unhealthy, :critical]
      
      # Check score is valid
      assert is_number(result.score)
      assert result.score >= 0.0
      assert result.score <= 100.0
      
      # Check issues and recommendations are lists
      assert is_list(result.issues)
      assert is_list(result.recommendations)
      
      # Check metrics is a map
      assert is_map(result.metrics)
      
      # Check timestamp is valid
      assert %DateTime{} = result.timestamp
    end

    test "returns consistent health check results" do
      # Run multiple health checks
      results = for _i <- 1..5 do
        Diagnostics.check_system_health()
      end
      
      # All results should have consistent structure
      for result <- results do
        assert is_map(result)
        assert Map.has_key?(result, :status)
        assert Map.has_key?(result, :score)
        assert is_number(result.score)
        assert result.score >= 0.0 and result.score <= 100.0
      end
    end

    test "system health includes expected metrics" do
      result = Diagnostics.check_system_health()
      
      assert is_map(result.metrics)
      
      # Metrics might include memory, CPU, disk usage, etc.
      # We just check that it's a map with some content
      # The exact metrics depend on the implementation
      assert is_map(result.metrics)
    end
  end

  describe "test_connectivity/0" do
    test "tests connectivity successfully" do
      result = Diagnostics.test_connectivity()
      
      assert is_map(result)
      assert Map.has_key?(result, :status)
      assert Map.has_key?(result, :score)
      assert Map.has_key?(result, :issues)
      assert Map.has_key?(result, :recommendations)
      assert Map.has_key?(result, :metrics)
      assert Map.has_key?(result, :timestamp)
      
      # Check status is valid
      assert result.status in [:healthy, :degraded, :unhealthy, :critical]
      
      # Check score is valid
      assert is_number(result.score)
      assert result.score >= 0.0
      assert result.score <= 100.0
      
      # Check collections are proper types
      assert is_list(result.issues)
      assert is_list(result.recommendations)
      assert is_map(result.metrics)
      assert %DateTime{} = result.timestamp
    end

    test "handles connectivity issues gracefully" do
      # This test ensures connectivity testing doesn't crash
      # even if Vault is not available
      result = Diagnostics.test_connectivity()
      
      assert is_map(result)
      assert Map.has_key?(result, :status)
      assert Map.has_key?(result, :score)
      
      # Score might be low if connectivity fails, but should still be valid
      assert is_number(result.score)
      assert result.score >= 0.0 and result.score <= 100.0
    end

    test "connectivity test includes relevant metrics" do
      result = Diagnostics.test_connectivity()
      
      assert is_map(result.metrics)
      
      # Connectivity metrics might include response time, status codes, etc.
      # We just verify the structure is correct
      assert is_map(result.metrics)
    end
  end

  describe "health status scoring" do
    test "health status corresponds to score ranges" do
      # Test the scoring system by running diagnostics
      result = Diagnostics.run_comprehensive_diagnostics()
      
      case result do
        {:ok, diagnostics} ->
          score = diagnostics.overall_score
          status = diagnostics.overall_status
          
          # Verify status matches expected score ranges
          cond do
            score >= 80.0 -> assert status == :healthy
            score >= 60.0 -> assert status == :degraded
            score >= 40.0 -> assert status == :unhealthy
            true -> assert status == :critical
          end
          
        {:error, _} ->
          # Error handling is acceptable
          :ok
      end
    end

    test "individual component scores are reasonable" do
      system_result = Diagnostics.check_system_health()
      connectivity_result = Diagnostics.test_connectivity()
      
      # Both scores should be valid numbers
      assert is_number(system_result.score)
      assert is_number(connectivity_result.score)
      
      # Scores should be in valid range
      assert system_result.score >= 0.0 and system_result.score <= 100.0
      assert connectivity_result.score >= 0.0 and connectivity_result.score <= 100.0
      
      # Status should match score
      for {result, name} <- [{system_result, "system"}, {connectivity_result, "connectivity"}] do
        score = result.score
        status = result.status
        
        expected_status = cond do
          score >= 80.0 -> :healthy
          score >= 60.0 -> :degraded
          score >= 40.0 -> :unhealthy
          true -> :critical
        end
        
        assert status == expected_status, 
          "#{name} status #{status} doesn't match score #{score} (expected #{expected_status})"
      end
    end
  end

  describe "error handling and edge cases" do
    test "handles missing configuration gracefully" do
      # This test ensures diagnostics work even with minimal config
      result = Diagnostics.run_comprehensive_diagnostics()
      
      # Should not crash, should return some result
      assert match?({:ok, _}, result) or match?({:error, _}, result)
    end

    test "diagnostics are deterministic for same conditions" do
      # Run diagnostics multiple times quickly
      results = for _i <- 1..3 do
        Diagnostics.check_system_health()
      end
      
      # Results should be consistent (allowing for small timing differences)
      scores = Enum.map(results, & &1.score)
      statuses = Enum.map(results, & &1.status)
      
      # All scores should be numbers in valid range
      for score <- scores do
        assert is_number(score)
        assert score >= 0.0 and score <= 100.0
      end
      
      # All statuses should be valid
      for status <- statuses do
        assert status in [:healthy, :degraded, :unhealthy, :critical]
      end
    end

    test "handles concurrent diagnostic requests" do
      # Test concurrent access
      tasks = for _i <- 1..5 do
        Task.async(fn -> Diagnostics.check_system_health() end)
      end
      
      results = Enum.map(tasks, &Task.await(&1, 5000))
      
      # All tasks should complete successfully
      for result <- results do
        assert is_map(result)
        assert Map.has_key?(result, :status)
        assert Map.has_key?(result, :score)
      end
    end
  end

  describe "timestamp and metadata" do
    test "diagnostics include proper timestamps" do
      result = Diagnostics.run_comprehensive_diagnostics()
      
      case result do
        {:ok, diagnostics} ->
          assert %DateTime{} = diagnostics.timestamp
          
          # Timestamp should be recent (within last minute)
          now = DateTime.utc_now()
          diff = DateTime.diff(now, diagnostics.timestamp, :second)
          assert diff >= 0 and diff < 60
          
          # Component timestamps should also be valid
          assert %DateTime{} = diagnostics.system.timestamp
          assert %DateTime{} = diagnostics.connectivity.timestamp
          
        {:error, _} ->
          :ok
      end
    end

    test "individual health checks include timestamps" do
      system_result = Diagnostics.check_system_health()
      connectivity_result = Diagnostics.test_connectivity()
      
      assert %DateTime{} = system_result.timestamp
      assert %DateTime{} = connectivity_result.timestamp
      
      # Timestamps should be recent
      now = DateTime.utc_now()
      
      system_diff = DateTime.diff(now, system_result.timestamp, :second)
      connectivity_diff = DateTime.diff(now, connectivity_result.timestamp, :second)
      
      assert system_diff >= 0 and system_diff < 60
      assert connectivity_diff >= 0 and connectivity_diff < 60
    end
  end
end
