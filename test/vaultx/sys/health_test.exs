defmodule Vaultx.Sys.HealthTest do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Sys.Health
  alias Vaultx.Base.Error

  # Sample health response from Vault
  @health_response %{
    "initialized" => true,
    "sealed" => false,
    "standby" => false,
    "performance_standby" => false,
    "server_time_utc" => 1_640_995_200,
    "version" => "1.20.0",
    "cluster_name" => "vault-cluster-1",
    "cluster_id" => "cluster-123",
    "replication_performance_mode" => "disabled",
    "replication_dr_mode" => "disabled",
    "replication_primary_canary_age_ms" => 0,
    "ha_connection_healthy" => true,
    "last_request_forwarding_heartbeat_ms" => 0,
    "removed_from_cluster" => false,
    "clock_skew_ms" => 0,
    "echo_duration_ms" => 1,
    "enterprise" => false,
    "license" => nil,
    "last_wal" => nil
  }

  describe "check/1" do
    test "returns health status successfully" do
      expect_get(200, @health_response, fn url, _body, _opts ->
        assert String.contains?(url, "sys/health")
        refute String.contains?(url, "?")
      end)

      assert {:ok, health} = Health.check()
      assert health.initialized == true
      assert health.sealed == false
      assert health.standby == false
      assert health.performance_standby == false
      assert health.server_time_utc == 1_640_995_200
      assert health.version == "1.20.0"
      assert health.cluster_name == "vault-cluster-1"
      assert health.cluster_id == "cluster-123"
      assert health.enterprise == false
    end

    test "returns health status with query parameters" do
      expect_get(200, @health_response, fn url, _body, _opts ->
        assert String.contains?(url, "sys/health?")
        assert String.contains?(url, "standbyok=true")
        assert String.contains?(url, "perfstandbyok=true")
        assert String.contains?(url, "activecode=200")
        assert String.contains?(url, "standbycode=200")
      end)

      opts = [
        standbyok: true,
        perfstandbyok: true,
        activecode: 200,
        standbycode: 200
      ]

      assert {:ok, health} = Health.check(opts)
      assert health.initialized == true
    end

    test "handles different status codes correctly" do
      for status <- [200, 429, 472, 473, 474, 501, 503, 530] do
        expect_get(status, @health_response)
        assert {:ok, _health} = Health.check()
      end
    end

    test "returns error for unexpected status codes" do
      expect_get(400, %{"errors" => ["bad request"]})

      assert {:error, %Error{type: :unexpected_response}} = Health.check()
    end

    test "wraps network errors" do
      stub_request_raw(:get, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{type: :unknown_error}} = Health.check()
    end

    test "handles all custom status code options" do
      expect_get(200, @health_response, fn url, _body, _opts ->
        assert String.contains?(url, "drsecondarycode=472")
        assert String.contains?(url, "haunhealthycode=474")
        assert String.contains?(url, "performancestandbycode=473")
        assert String.contains?(url, "removedcode=530")
        assert String.contains?(url, "sealedcode=503")
        assert String.contains?(url, "uninitcode=501")
      end)

      opts = [
        drsecondarycode: 472,
        haunhealthycode: 474,
        performancestandbycode: 473,
        removedcode: 530,
        sealedcode: 503,
        uninitcode: 501
      ]

      assert {:ok, _health} = Health.check(opts)
    end

    test "ignores invalid status code options" do
      expect_get(200, @health_response, fn url, _body, _opts ->
        assert String.contains?(url, "sys/health")
        # Should not contain invalid parameters
        refute String.contains?(url, "activecode=invalid")
        refute String.contains?(url, "standbycode=bad")
      end)

      opts = [
        # non-integer value should be ignored
        activecode: "invalid",
        # non-integer value should be ignored
        standbycode: :bad
      ]

      assert {:ok, _health} = Health.check(opts)
    end
  end

  describe "private helper functions" do
    test "parse_health_response/1 handles missing fields gracefully" do
      minimal_response = %{
        "initialized" => true,
        "sealed" => false
      }

      expect_get(200, minimal_response)

      assert {:ok, health} = Health.check()
      assert health.initialized == true
      assert health.sealed == false
      # default value
      assert health.standby == false
      # default value
      assert health.version == "unknown"
      # default value
      assert health.cluster_name == ""
    end
  end

  describe "edge cases and error handling" do
    test "handles empty response body" do
      expect_get(200, %{})

      assert {:ok, health} = Health.check()
      # default value
      assert health.initialized == false
      # default value
      assert health.sealed == true
    end

    test "handles nil values in response" do
      response_with_nils =
        Map.merge(@health_response, %{
          "license" => nil,
          "last_wal" => nil,
          "performance_standby_last_remote_wal" => nil
        })

      expect_get(200, response_with_nils)

      assert {:ok, health} = Health.check()
      assert health.license == nil
      assert health.last_wal == nil
    end

    test "handles boolean conversion correctly" do
      response_with_strings = %{
        "initialized" => "true",
        "sealed" => "false",
        "standby" => true,
        "performance_standby" => false
      }

      expect_get(200, response_with_strings)

      assert {:ok, health} = Health.check()
      # String values should be preserved as-is since we don't do type conversion
      assert health.initialized == "true"
      assert health.sealed == "false"
      assert health.standby == true
      assert health.performance_standby == false
    end
  end
end
