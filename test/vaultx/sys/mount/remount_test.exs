defmodule Vaultx.Sys.RemountTest do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Sys.Remount
  alias Vaultx.Base.Error

  # Sample migration response
  @migration_response %{
    "migration_id" => "ef3ba21c-8be8-4e5f-8d00-cb46a532c665"
  }

  # Sample migration status response
  @migration_status_response %{
    "migration_id" => "ef3ba21c-8be8-4e5f-8d00-cb46a532c665",
    "migration_info" => %{
      "source_mount" => "secret",
      "target_mount" => "new-secret",
      "status" => "success"
    }
  }

  # In-progress migration status
  @migration_in_progress_response %{
    "migration_id" => "ef3ba21c-8be8-4e5f-8d00-cb46a532c665",
    "migration_info" => %{
      "source_mount" => "secret",
      "target_mount" => "new-secret",
      "status" => "in-progress"
    }
  }

  # Failed migration status
  @migration_failed_response %{
    "migration_id" => "ef3ba21c-8be8-4e5f-8d00-cb46a532c665",
    "migration_info" => %{
      "source_mount" => "secret",
      "target_mount" => "new-secret",
      "status" => "failure"
    }
  }

  describe "move/3" do
    test "moves mount successfully within namespace" do
      expect_post(200, @migration_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/remount")
        assert body["from"] == "secret"
        assert body["to"] == "new-secret"
      end)

      assert {:ok, response} = Remount.move("secret", "new-secret")
      assert response.migration_id == "ef3ba21c-8be8-4e5f-8d00-cb46a532c665"
    end

    test "moves auth method successfully" do
      expect_post(204, @migration_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/remount")
        assert body["from"] == "auth/approle"
        assert body["to"] == "auth/new-approle"
      end)

      assert {:ok, response} = Remount.move("auth/approle", "auth/new-approle")
      assert response.migration_id == "ef3ba21c-8be8-4e5f-8d00-cb46a532c665"
    end

    test "moves mount across namespaces" do
      expect_post(200, @migration_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/remount")
        assert body["from"] == "ns1/ns2/secret"
        assert body["to"] == "ns1/ns3/new-secret"
      end)

      assert {:ok, response} = Remount.move("ns1/ns2/secret", "ns1/ns3/new-secret")
      assert response.migration_id == "ef3ba21c-8be8-4e5f-8d00-cb46a532c665"
    end

    test "handles move errors" do
      expect_post(400, %{"errors" => ["source mount does not exist"]})

      assert {:error, %Error{} = error} = Remount.move("nonexistent", "new-path")
      assert error.type == :server_error
      assert String.contains?(error.message, "Failed to initiate mount migration")
    end

    test "handles network errors during move" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{} = error} = Remount.move("secret", "new-secret")
      assert error.type == :unknown_error
    end

    test "handles invalid response format" do
      expect_post(200, %{"invalid" => "response"})

      assert {:error, %Error{} = error} = Remount.move("secret", "new-secret")
      assert error.type == :server_error
    end
  end

  describe "status/2" do
    test "retrieves successful migration status" do
      migration_id = "ef3ba21c-8be8-4e5f-8d00-cb46a532c665"

      expect_get(200, @migration_status_response, fn url, _body, _opts ->
        assert String.contains?(url, "sys/remount/status/#{migration_id}")
      end)

      assert {:ok, status} = Remount.status(migration_id)
      assert status.migration_id == migration_id
      assert status.migration_info.source_mount == "secret"
      assert status.migration_info.target_mount == "new-secret"
      assert status.migration_info.status == "success"
    end

    test "retrieves in-progress migration status" do
      migration_id = "ef3ba21c-8be8-4e5f-8d00-cb46a532c665"

      expect_get(200, @migration_in_progress_response, fn url, _body, _opts ->
        assert String.contains?(url, "sys/remount/status/#{migration_id}")
      end)

      assert {:ok, status} = Remount.status(migration_id)
      assert status.migration_id == migration_id
      assert status.migration_info.status == "in-progress"
    end

    test "retrieves failed migration status" do
      migration_id = "ef3ba21c-8be8-4e5f-8d00-cb46a532c665"

      expect_get(200, @migration_failed_response, fn url, _body, _opts ->
        assert String.contains?(url, "sys/remount/status/#{migration_id}")
      end)

      assert {:ok, status} = Remount.status(migration_id)
      assert status.migration_id == migration_id
      assert status.migration_info.status == "failure"
    end

    test "handles status check errors" do
      migration_id = "nonexistent-id"
      expect_get(404, %{"errors" => ["migration not found"]})

      assert {:error, %Error{} = error} = Remount.status(migration_id)
      assert error.type == :server_error
      assert String.contains?(error.message, "Failed to get migration status")
    end

    test "handles network errors during status check" do
      migration_id = "ef3ba21c-8be8-4e5f-8d00-cb46a532c665"
      stub_request_raw(:get, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{} = error} = Remount.status(migration_id)
      assert error.type == :unknown_error
    end

    test "handles cross-namespace migration status" do
      migration_id = "cross-ns-migration-id"

      cross_ns_response = %{
        "migration_id" => migration_id,
        "migration_info" => %{
          "source_mount" => "ns1/ns2/secret",
          "target_mount" => "ns1/ns3/new-secret",
          "status" => "success"
        }
      }

      expect_get(200, cross_ns_response)

      assert {:ok, status} = Remount.status(migration_id)
      assert status.migration_id == migration_id
      assert status.migration_info.source_mount == "ns1/ns2/secret"
      assert status.migration_info.target_mount == "ns1/ns3/new-secret"
      assert status.migration_info.status == "success"
    end

    test "handles auth method migration status" do
      migration_id = "auth-migration-id"

      auth_response = %{
        "migration_id" => migration_id,
        "migration_info" => %{
          "source_mount" => "auth/approle",
          "target_mount" => "auth/new-approle",
          "status" => "success"
        }
      }

      expect_get(200, auth_response)

      assert {:ok, status} = Remount.status(migration_id)
      assert status.migration_id == migration_id
      assert status.migration_info.source_mount == "auth/approle"
      assert status.migration_info.target_mount == "auth/new-approle"
      assert status.migration_info.status == "success"
    end
  end

  describe "edge cases" do
    test "handles empty migration ID" do
      expect_get(404, %{"errors" => ["migration not found"]})

      assert {:error, %Error{} = error} = Remount.status("")
      assert error.type == :server_error
    end

    test "handles special characters in mount paths" do
      expect_post(200, @migration_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/remount")
        assert body["from"] == "my-app/v1.0"
        assert body["to"] == "my-app/v2.0"
      end)

      assert {:ok, response} = Remount.move("my-app/v1.0", "my-app/v2.0")
      assert response.migration_id == "ef3ba21c-8be8-4e5f-8d00-cb46a532c665"
    end

    test "handles long migration IDs" do
      long_id = String.duplicate("a", 100)

      long_response = %{
        "migration_id" => long_id,
        "migration_info" => %{
          "source_mount" => "secret",
          "target_mount" => "new-secret",
          "status" => "success"
        }
      }

      expect_get(200, long_response)

      assert {:ok, status} = Remount.status(long_id)
      assert status.migration_id == long_id
    end

    test "handles unicode characters in mount paths" do
      expect_post(200, @migration_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/remount")
        assert body["from"] == "测试/secret"
        assert body["to"] == "测试/new-secret"
      end)

      assert {:ok, response} = Remount.move("测试/secret", "测试/new-secret")
      assert response.migration_id == "ef3ba21c-8be8-4e5f-8d00-cb46a532c665"
    end
  end

  describe "integration scenarios" do
    test "complete migration workflow" do
      # Step 1: Initiate migration
      expect_post(200, @migration_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/remount")
        assert body["from"] == "old-mount"
        assert body["to"] == "new-mount"
      end)

      assert {:ok, response} = Remount.move("old-mount", "new-mount")
      migration_id = response.migration_id

      # Step 2: Check in-progress status
      expect_get(200, @migration_in_progress_response)
      assert {:ok, status} = Remount.status(migration_id)
      assert status.migration_info.status == "in-progress"

      # Step 3: Check final success status
      expect_get(200, @migration_status_response)
      assert {:ok, final_status} = Remount.status(migration_id)
      assert final_status.migration_info.status == "success"
    end

    test "migration failure workflow" do
      # Step 1: Initiate migration
      expect_post(200, @migration_response)
      assert {:ok, response} = Remount.move("problematic-mount", "new-mount")
      migration_id = response.migration_id

      # Step 2: Check failure status
      expect_get(200, @migration_failed_response)
      assert {:ok, status} = Remount.status(migration_id)
      assert status.migration_info.status == "failure"
    end
  end
end
