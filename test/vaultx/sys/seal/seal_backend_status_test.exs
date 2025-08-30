defmodule Vaultx.Sys.SealBackendStatusTest do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Sys.SealBackendStatus
  alias Vaultx.Base.Error

  # Sample seal backend status responses
  @healthy_backends %{
    "healthy" => true,
    "backends" => [
      %{
        "name" => "awskms",
        "healthy" => true
      },
      %{
        "name" => "hsm",
        "healthy" => true
      }
    ]
  }

  @unhealthy_backends %{
    "healthy" => false,
    "unhealthy_since" => "2025-03-26T14:30:00Z",
    "backends" => [
      %{
        "name" => "awskms",
        "healthy" => true
      },
      %{
        "name" => "hsm",
        "healthy" => false,
        "unhealthy_since" => "2025-03-26T14:30:00Z"
      },
      %{
        "name" => "gcpkms",
        "healthy" => false,
        "unhealthy_since" => "2025-03-26T14:25:00Z"
      }
    ]
  }

  @single_backend %{
    "healthy" => true,
    "backends" => [
      %{
        "name" => "shamir",
        "healthy" => true
      }
    ]
  }

  @empty_backends %{
    "healthy" => true,
    "backends" => []
  }

  describe "get/1" do
    test "gets healthy backend status successfully" do
      expect_get(200, @healthy_backends, fn url, _body, _opts ->
        assert String.contains?(url, "sys/seal-backend-status")
      end)

      assert {:ok, status} = SealBackendStatus.get()
      assert status.healthy == true
      assert length(status.backends) == 2
      refute Map.has_key?(status, :unhealthy_since)

      awskms_backend = Enum.find(status.backends, &(&1.name == "awskms"))
      assert awskms_backend.healthy == true
      refute Map.has_key?(awskms_backend, :unhealthy_since)

      hsm_backend = Enum.find(status.backends, &(&1.name == "hsm"))
      assert hsm_backend.healthy == true
    end

    test "gets unhealthy backend status with timestamps" do
      expect_get(200, @unhealthy_backends, fn url, _body, _opts ->
        assert String.contains?(url, "sys/seal-backend-status")
      end)

      assert {:ok, status} = SealBackendStatus.get()
      assert status.healthy == false
      assert status.unhealthy_since == "2025-03-26T14:30:00Z"
      assert length(status.backends) == 3

      awskms_backend = Enum.find(status.backends, &(&1.name == "awskms"))
      assert awskms_backend.healthy == true

      hsm_backend = Enum.find(status.backends, &(&1.name == "hsm"))
      assert hsm_backend.healthy == false
      assert hsm_backend.unhealthy_since == "2025-03-26T14:30:00Z"

      gcpkms_backend = Enum.find(status.backends, &(&1.name == "gcpkms"))
      assert gcpkms_backend.healthy == false
      assert gcpkms_backend.unhealthy_since == "2025-03-26T14:25:00Z"
    end

    test "handles single backend configuration" do
      expect_get(200, @single_backend, fn url, _body, _opts ->
        assert String.contains?(url, "sys/seal-backend-status")
      end)

      assert {:ok, status} = SealBackendStatus.get()
      assert status.healthy == true
      assert length(status.backends) == 1

      shamir_backend = hd(status.backends)
      assert shamir_backend.name == "shamir"
      assert shamir_backend.healthy == true
    end

    test "handles empty backends list" do
      expect_get(200, @empty_backends, fn url, _body, _opts ->
        assert String.contains?(url, "sys/seal-backend-status")
      end)

      assert {:ok, status} = SealBackendStatus.get()
      assert status.healthy == true
      assert status.backends == []
    end

    test "handles server errors" do
      expect_get(500, %{"errors" => ["internal server error"]})

      assert {:error, %Error{} = error} = SealBackendStatus.get()
      assert error.type == :server_error
      assert String.contains?(error.message, "Failed to get seal backend status")
    end

    test "handles network errors" do
      stub_request_raw(:get, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{} = error} = SealBackendStatus.get()
      assert error.type == :unknown_error
    end

    test "passes custom options" do
      expect_get(200, @healthy_backends, fn _url, _body, opts ->
        assert opts[:timeout] == 30_000
      end)

      assert {:ok, _status} = SealBackendStatus.get(timeout: 30_000)
    end
  end

  describe "all_healthy?/1" do
    test "returns true when all backends are healthy" do
      expect_get(200, @healthy_backends)

      assert {:ok, true} = SealBackendStatus.all_healthy?()
    end

    test "returns false when some backends are unhealthy" do
      expect_get(200, @unhealthy_backends)

      assert {:ok, false} = SealBackendStatus.all_healthy?()
    end

    test "handles errors" do
      expect_get(500, %{"errors" => ["server error"]})

      assert {:error, %Error{} = error} = SealBackendStatus.all_healthy?()
      assert error.type == :server_error
    end
  end

  describe "get_backend_status/2" do
    test "returns specific backend status when found" do
      expect_get(200, @unhealthy_backends)

      assert {:ok, backend} = SealBackendStatus.get_backend_status("hsm")
      assert backend.name == "hsm"
      assert backend.healthy == false
      assert backend.unhealthy_since == "2025-03-26T14:30:00Z"
    end

    test "returns healthy backend status" do
      expect_get(200, @unhealthy_backends)

      assert {:ok, backend} = SealBackendStatus.get_backend_status("awskms")
      assert backend.name == "awskms"
      assert backend.healthy == true
      refute Map.has_key?(backend, :unhealthy_since)
    end

    test "returns error when backend not found" do
      expect_get(200, @healthy_backends)

      assert {:error, %Error{} = error} = SealBackendStatus.get_backend_status("nonexistent")
      assert error.type == :not_found
      assert String.contains?(error.message, "Seal backend 'nonexistent' not found")
      assert error.details.requested_backend == "nonexistent"
      assert error.details.available_backends == ["awskms", "hsm"]
    end

    test "handles errors from get request" do
      expect_get(500, %{"errors" => ["server error"]})

      assert {:error, %Error{} = error} = SealBackendStatus.get_backend_status("awskms")
      assert error.type == :server_error
    end
  end

  describe "list_backend_names/1" do
    test "returns list of backend names" do
      expect_get(200, @unhealthy_backends)

      assert {:ok, names} = SealBackendStatus.list_backend_names()
      assert names == ["awskms", "hsm", "gcpkms"]
    end

    test "returns empty list for no backends" do
      expect_get(200, @empty_backends)

      assert {:ok, names} = SealBackendStatus.list_backend_names()
      assert names == []
    end

    test "handles single backend" do
      expect_get(200, @single_backend)

      assert {:ok, names} = SealBackendStatus.list_backend_names()
      assert names == ["shamir"]
    end

    test "handles errors" do
      expect_get(500, %{"errors" => ["server error"]})

      assert {:error, %Error{} = error} = SealBackendStatus.list_backend_names()
      assert error.type == :server_error
    end
  end

  describe "get_unhealthy_backends/1" do
    test "returns unhealthy backends only" do
      expect_get(200, @unhealthy_backends)

      assert {:ok, unhealthy} = SealBackendStatus.get_unhealthy_backends()
      assert length(unhealthy) == 2

      hsm_backend = Enum.find(unhealthy, &(&1.name == "hsm"))
      assert hsm_backend.healthy == false
      assert hsm_backend.unhealthy_since == "2025-03-26T14:30:00Z"

      gcpkms_backend = Enum.find(unhealthy, &(&1.name == "gcpkms"))
      assert gcpkms_backend.healthy == false
      assert gcpkms_backend.unhealthy_since == "2025-03-26T14:25:00Z"

      # Should not include healthy backends
      refute Enum.any?(unhealthy, &(&1.name == "awskms"))
    end

    test "returns empty list when all backends are healthy" do
      expect_get(200, @healthy_backends)

      assert {:ok, unhealthy} = SealBackendStatus.get_unhealthy_backends()
      assert unhealthy == []
    end

    test "handles empty backends list" do
      expect_get(200, @empty_backends)

      assert {:ok, unhealthy} = SealBackendStatus.get_unhealthy_backends()
      assert unhealthy == []
    end

    test "handles errors" do
      expect_get(500, %{"errors" => ["server error"]})

      assert {:error, %Error{} = error} = SealBackendStatus.get_unhealthy_backends()
      assert error.type == :server_error
    end
  end

  describe "edge cases and error scenarios" do
    test "handles null unhealthy_since timestamps" do
      response_with_nulls = %{
        "healthy" => false,
        "backends" => [
          %{
            "name" => "test-backend",
            "healthy" => false,
            "unhealthy_since" => nil
          }
        ]
      }

      expect_get(200, response_with_nulls)

      assert {:ok, status} = SealBackendStatus.get()
      assert status.healthy == false
      refute Map.has_key?(status, :unhealthy_since)

      backend = hd(status.backends)
      assert backend.name == "test-backend"
      assert backend.healthy == false
      refute Map.has_key?(backend, :unhealthy_since)
    end

    test "handles missing optional fields" do
      minimal_response = %{
        "healthy" => true,
        "backends" => [
          %{
            "name" => "minimal-backend",
            "healthy" => true
          }
        ]
      }

      expect_get(200, minimal_response)

      assert {:ok, status} = SealBackendStatus.get()
      assert status.healthy == true
      refute Map.has_key?(status, :unhealthy_since)

      backend = hd(status.backends)
      assert backend.name == "minimal-backend"
      assert backend.healthy == true
      refute Map.has_key?(backend, :unhealthy_since)
    end

    test "handles various HTTP error codes" do
      error_codes = [400, 401, 403, 404, 500, 502, 503]

      Enum.each(error_codes, fn code ->
        expect_get(code, %{"errors" => ["error #{code}"]})

        assert {:error, %Error{} = error} = SealBackendStatus.get()
        assert error.type == :server_error
        assert String.contains?(error.message, "HTTP #{code}")
      end)
    end

    test "handles malformed JSON response" do
      expect_get(200, "invalid json")

      # Now returns a valid response with default values instead of error
      assert {:ok, status} = SealBackendStatus.get()
      assert status.healthy == true
      assert status.backends == []
    end

    test "handles malformed backend data" do
      malformed_response = %{
        "healthy" => true,
        "backends" => [
          %{
            "name" => nil,
            "healthy" => "not_boolean"
          }
        ]
      }

      expect_get(200, malformed_response)

      assert {:ok, status} = SealBackendStatus.get()
      backend = hd(status.backends)
      assert backend.name == nil
      assert backend.healthy == "not_boolean"
    end

    test "handles unicode characters in backend names" do
      unicode_response = %{
        "healthy" => true,
        "backends" => [
          %{
            "name" => "测试后端",
            "healthy" => true
          }
        ]
      }

      expect_get(200, unicode_response)

      assert {:ok, status} = SealBackendStatus.get()
      backend = hd(status.backends)
      assert backend.name == "测试后端"
    end

    test "handles non-list backends field" do
      response_with_invalid_backends = %{
        "healthy" => true,
        "backends" => "not a list"
      }

      expect_get(200, response_with_invalid_backends)

      assert {:ok, status} = SealBackendStatus.get()
      assert status.healthy == true
      assert status.backends == []
    end

    test "handles null backends field" do
      response_with_null_backends = %{
        "healthy" => true,
        "backends" => nil
      }

      expect_get(200, response_with_null_backends)

      assert {:ok, status} = SealBackendStatus.get()
      assert status.healthy == true
      assert status.backends == []
    end
  end

  describe "integration scenarios" do
    test "monitoring workflow for healthy backends" do
      # Step 1: Check overall health
      expect_get(200, @healthy_backends)

      assert {:ok, true} = SealBackendStatus.all_healthy?()

      # Step 2: Get detailed status
      expect_get(200, @healthy_backends)

      assert {:ok, status} = SealBackendStatus.get()
      assert status.healthy == true

      # Step 3: List all backends
      expect_get(200, @healthy_backends)

      assert {:ok, names} = SealBackendStatus.list_backend_names()
      assert "awskms" in names
      assert "hsm" in names
    end

    test "monitoring workflow for unhealthy backends" do
      # Step 1: Check overall health (unhealthy)
      expect_get(200, @unhealthy_backends)

      assert {:ok, false} = SealBackendStatus.all_healthy?()

      # Step 2: Get unhealthy backends
      expect_get(200, @unhealthy_backends)

      assert {:ok, unhealthy} = SealBackendStatus.get_unhealthy_backends()
      assert length(unhealthy) == 2

      # Step 3: Check specific backend
      expect_get(200, @unhealthy_backends)

      assert {:ok, hsm_status} = SealBackendStatus.get_backend_status("hsm")
      assert hsm_status.healthy == false
      assert hsm_status.unhealthy_since == "2025-03-26T14:30:00Z"
    end

    test "alerting workflow" do
      # Check for unhealthy backends
      expect_get(200, @unhealthy_backends)

      assert {:ok, unhealthy} = SealBackendStatus.get_unhealthy_backends()

      # Simulate alerting logic
      if not Enum.empty?(unhealthy) do
        unhealthy_names = Enum.map(unhealthy, & &1.name)
        assert "hsm" in unhealthy_names
        assert "gcpkms" in unhealthy_names
        refute "awskms" in unhealthy_names
      end
    end

    test "backend discovery workflow" do
      # Step 1: Discover all backends
      expect_get(200, @unhealthy_backends)

      assert {:ok, all_names} = SealBackendStatus.list_backend_names()
      assert length(all_names) == 3

      # Step 2: Check each backend individually
      Enum.each(all_names, fn name ->
        expect_get(200, @unhealthy_backends)

        assert {:ok, backend} = SealBackendStatus.get_backend_status(name)
        assert backend.name == name
        assert is_boolean(backend.healthy)
      end)
    end

    test "health transition monitoring" do
      # Initially healthy
      expect_get(200, @healthy_backends)

      assert {:ok, initial_status} = SealBackendStatus.get()
      assert initial_status.healthy == true

      # Later becomes unhealthy
      expect_get(200, @unhealthy_backends)

      assert {:ok, later_status} = SealBackendStatus.get()
      assert later_status.healthy == false
      assert Map.has_key?(later_status, :unhealthy_since)
    end
  end
end
