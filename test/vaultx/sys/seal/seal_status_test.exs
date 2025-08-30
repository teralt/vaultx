defmodule Vaultx.Sys.SealStatusTest do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Sys.SealStatus
  alias Vaultx.Base.Error

  # Sample seal status responses
  @sealed_status %{
    "sealed" => true,
    "t" => 3,
    "n" => 5,
    "progress" => 1,
    "version" => "1.15.0",
    "build_date" => "2025-03-26T14:28:14Z",
    "storage_type" => "consul",
    "type" => "shamir",
    "initialized" => true,
    "migration" => false,
    "recovery_seal" => false,
    "removed_from_cluster" => false,
    "nonce" => "abc123"
  }

  @unsealed_status %{
    "sealed" => false,
    "t" => 3,
    "n" => 5,
    "progress" => 3,
    "version" => "1.15.0",
    "build_date" => "2025-03-26T14:28:14Z",
    "storage_type" => "consul",
    "type" => "shamir",
    "initialized" => true,
    "migration" => false,
    "recovery_seal" => false,
    "removed_from_cluster" => false,
    "nonce" => "def456",
    "cluster_name" => "vault-cluster",
    "cluster_id" => "12345678-1234-1234-1234-123456789012"
  }

  @minimal_status %{
    "sealed" => true,
    "t" => 3,
    "n" => 5,
    "progress" => 0,
    "version" => "1.15.0"
  }

  describe "get/1" do
    test "gets sealed status successfully" do
      expect_get(200, @sealed_status, fn url, _body, _opts ->
        assert String.contains?(url, "sys/seal-status")
      end)

      assert {:ok, status} = SealStatus.get()
      assert status.sealed == true
      assert status.t == 3
      assert status.n == 5
      assert status.progress == 1
      assert status.version == "1.15.0"
      assert status.build_date == "2025-03-26T14:28:14Z"
      assert status.storage_type == "consul"
      assert status.type == "shamir"
      assert status.initialized == true
      assert status.migration == false
      assert status.recovery_seal == false
      assert status.removed_from_cluster == false
      assert status.nonce == "abc123"
      refute Map.has_key?(status, :cluster_name)
      refute Map.has_key?(status, :cluster_id)
    end

    test "gets unsealed status with cluster information" do
      expect_get(200, @unsealed_status, fn url, _body, _opts ->
        assert String.contains?(url, "sys/seal-status")
      end)

      assert {:ok, status} = SealStatus.get()
      assert status.sealed == false
      assert status.progress == 3
      assert status.cluster_name == "vault-cluster"
      assert status.cluster_id == "12345678-1234-1234-1234-123456789012"
    end

    test "handles minimal status response" do
      expect_get(200, @minimal_status, fn url, _body, _opts ->
        assert String.contains?(url, "sys/seal-status")
      end)

      assert {:ok, status} = SealStatus.get()
      assert status.sealed == true
      assert status.version == "1.15.0"
      assert status.build_date == ""
      assert status.storage_type == ""
      assert status.type == ""
      assert status.initialized == false
      assert status.migration == false
      assert status.recovery_seal == false
      assert status.removed_from_cluster == false
      assert status.nonce == ""
    end

    test "handles server errors" do
      expect_get(500, %{"errors" => ["internal server error"]})

      assert {:error, %Error{} = error} = SealStatus.get()
      assert error.type == :server_error
      assert String.contains?(error.message, "Failed to get seal status")
    end

    test "handles network errors" do
      stub_request_raw(:get, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{} = error} = SealStatus.get()
      assert error.type == :unknown_error
    end

    test "passes custom options" do
      expect_get(200, @sealed_status, fn _url, _body, opts ->
        assert opts[:timeout] == 30_000
      end)

      assert {:ok, _status} = SealStatus.get(timeout: 30_000)
    end
  end

  describe "is_sealed?/1" do
    test "returns true when vault is sealed" do
      expect_get(200, @sealed_status)

      assert {:ok, true} = SealStatus.is_sealed?()
    end

    test "returns false when vault is unsealed" do
      expect_get(200, @unsealed_status)

      assert {:ok, false} = SealStatus.is_sealed?()
    end

    test "handles errors" do
      expect_get(500, %{"errors" => ["server error"]})

      assert {:error, %Error{} = error} = SealStatus.is_sealed?()
      assert error.type == :server_error
    end
  end

  describe "is_unsealed?/1" do
    test "returns false when vault is sealed" do
      expect_get(200, @sealed_status)

      assert {:ok, false} = SealStatus.is_unsealed?()
    end

    test "returns true when vault is unsealed" do
      expect_get(200, @unsealed_status)

      assert {:ok, true} = SealStatus.is_unsealed?()
    end

    test "handles errors" do
      expect_get(500, %{"errors" => ["server error"]})

      assert {:error, %Error{} = error} = SealStatus.is_unsealed?()
      assert error.type == :server_error
    end
  end

  describe "wait_for_unseal/1" do
    test "returns immediately when already unsealed" do
      expect_get(200, @unsealed_status)

      assert {:ok, status} = SealStatus.wait_for_unseal()
      assert status.sealed == false
    end

    test "waits and returns when vault becomes unsealed" do
      # First call - sealed
      expect_get(200, @sealed_status)

      # Second call - unsealed
      expect_get(200, @unsealed_status)

      assert {:ok, status} = SealStatus.wait_for_unseal(timeout: 5_000, interval: 100)
      assert status.sealed == false
    end

    test "times out when vault remains sealed" do
      # Use stub instead of expect to allow multiple calls
      stub_ok(:get, 200, @sealed_status)

      assert {:error, %Error{} = error} = SealStatus.wait_for_unseal(timeout: 200, interval: 50)
      assert error.type == :timeout
      assert String.contains?(error.message, "Timeout waiting for Vault to unseal")
    end

    test "handles errors during wait" do
      expect_get(500, %{"errors" => ["server error"]})

      assert {:error, %Error{} = error} = SealStatus.wait_for_unseal(timeout: 1_000)
      assert error.type == :server_error
    end

    test "uses custom timeout and interval" do
      expect_get(200, @unsealed_status)

      start_time = System.monotonic_time(:millisecond)
      assert {:ok, _status} = SealStatus.wait_for_unseal(timeout: 10_000, interval: 2_000)
      end_time = System.monotonic_time(:millisecond)

      # Should return quickly since already unsealed
      assert end_time - start_time < 1_000
    end
  end

  describe "get_unseal_progress/1" do
    test "returns progress information for sealed vault" do
      expect_get(200, @sealed_status)

      assert {:ok, progress} = SealStatus.get_unseal_progress()
      assert progress.current == 1
      assert progress.required == 3
      assert progress.remaining == 2
    end

    test "returns progress information for unsealed vault" do
      expect_get(200, @unsealed_status)

      assert {:ok, progress} = SealStatus.get_unseal_progress()
      assert progress.current == 3
      assert progress.required == 3
      assert progress.remaining == 0
    end

    test "handles zero progress" do
      zero_progress_status = %{@sealed_status | "progress" => 0}
      expect_get(200, zero_progress_status)

      assert {:ok, progress} = SealStatus.get_unseal_progress()
      assert progress.current == 0
      assert progress.required == 3
      assert progress.remaining == 3
    end

    test "handles errors" do
      expect_get(500, %{"errors" => ["server error"]})

      assert {:error, %Error{} = error} = SealStatus.get_unseal_progress()
      assert error.type == :server_error
    end
  end

  describe "edge cases and error scenarios" do
    test "handles null values in response" do
      null_response = %{
        "sealed" => true,
        "t" => 3,
        "n" => 5,
        "progress" => 1,
        "version" => "1.15.0",
        "build_date" => nil,
        "storage_type" => nil,
        "type" => nil,
        "cluster_name" => nil,
        "cluster_id" => nil
      }

      expect_get(200, null_response)

      assert {:ok, status} = SealStatus.get()
      assert status.build_date == ""
      assert status.storage_type == ""
      assert status.type == ""
      refute Map.has_key?(status, :cluster_name)
      refute Map.has_key?(status, :cluster_id)
    end

    test "handles missing optional fields" do
      minimal_response = %{
        "sealed" => false,
        "t" => 3,
        "n" => 5,
        "progress" => 3,
        "version" => "1.15.0"
      }

      expect_get(200, minimal_response)

      assert {:ok, status} = SealStatus.get()
      assert status.sealed == false
      assert status.initialized == false
      assert status.migration == false
      assert status.recovery_seal == false
      assert status.removed_from_cluster == false
      assert status.nonce == ""
    end

    test "handles various HTTP error codes" do
      error_codes = [400, 401, 403, 404, 500, 502, 503]

      Enum.each(error_codes, fn code ->
        expect_get(code, %{"errors" => ["error #{code}"]})

        assert {:error, %Error{} = error} = SealStatus.get()
        assert error.type == :server_error
        assert String.contains?(error.message, "HTTP #{code}")
      end)
    end

    test "handles malformed JSON response" do
      expect_get(200, "invalid json")

      # Now returns a valid response with default values instead of error
      assert {:ok, status} = SealStatus.get()
      assert status.sealed == true
      assert status.version == ""
    end

    test "handles auto-seal configuration" do
      auto_seal_status = %{
        @sealed_status
        | "type" => "awskms",
          "recovery_seal" => true
      }

      expect_get(200, auto_seal_status)

      assert {:ok, status} = SealStatus.get()
      assert status.type == "awskms"
      assert status.recovery_seal == true
    end

    test "handles migration in progress" do
      migration_status = %{
        @sealed_status
        | "migration" => true
      }

      expect_get(200, migration_status)

      assert {:ok, status} = SealStatus.get()
      assert status.migration == true
    end

    test "handles cluster removal status" do
      removed_status = %{
        @sealed_status
        | "removed_from_cluster" => true
      }

      expect_get(200, removed_status)

      assert {:ok, status} = SealStatus.get()
      assert status.removed_from_cluster == true
    end
  end

  describe "integration scenarios" do
    test "monitoring workflow" do
      # Step 1: Check initial status (sealed)
      expect_get(200, @sealed_status)

      assert {:ok, initial_status} = SealStatus.get()
      assert initial_status.sealed == true
      assert initial_status.progress == 1

      # Step 2: Check if sealed
      expect_get(200, @sealed_status)

      assert {:ok, true} = SealStatus.is_sealed?()

      # Step 3: Get progress
      expect_get(200, @sealed_status)

      assert {:ok, progress} = SealStatus.get_unseal_progress()
      assert progress.remaining == 2
    end

    test "unseal monitoring workflow" do
      # Step 1: Start waiting (vault is sealed)
      expect_get(200, @sealed_status)

      # Step 2: Still sealed after interval
      expect_get(200, %{@sealed_status | "progress" => 2})

      # Step 3: Finally unsealed
      expect_get(200, @unsealed_status)

      assert {:ok, final_status} = SealStatus.wait_for_unseal(timeout: 5_000, interval: 100)
      assert final_status.sealed == false
      assert final_status.cluster_name == "vault-cluster"
    end

    test "health check workflow" do
      # Check if unsealed for health check
      expect_get(200, @unsealed_status)

      assert {:ok, true} = SealStatus.is_unsealed?()

      # Get detailed status for monitoring
      expect_get(200, @unsealed_status)

      assert {:ok, status} = SealStatus.get()
      assert status.version == "1.15.0"
      assert status.storage_type == "consul"
      assert status.cluster_name == "vault-cluster"
    end

    test "custom timeout scenarios" do
      # Very short timeout should fail quickly
      stub_ok(:get, 200, @sealed_status)

      start_time = System.monotonic_time(:millisecond)
      assert {:error, %Error{}} = SealStatus.wait_for_unseal(timeout: 50, interval: 10)
      end_time = System.monotonic_time(:millisecond)

      # Should timeout within reasonable time
      assert end_time - start_time < 200
    end
  end
end
