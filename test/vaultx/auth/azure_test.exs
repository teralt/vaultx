defmodule Vaultx.Auth.AzureTest do
  use ExUnit.Case, async: true

  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Auth.Azure

  @valid_jwt "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.EkN-DOsnsuRjRO6BxXemmJDm3HbxrbRzXglbN2S4sOkopdU4IsDxTI8jO19W_A4K8ZPJijNLis4EZsHeY559a4DFOd50_OqgHs3PheWJoyhgZ6PW6WbTK_ZHcYWbqJOjxS6JxYhROdsBuwi0_v5ZmemhHHizhrk1qJOF2KaLJZvYG5OcYvlWjtoee1fYHRFD3bBOB-oQSu1eS-rNzQx_LU1k1G_Aw6L0jtgJQd6wub3Bqb0EPtmHY559a4DFOd50_OqgHs3PheWJoyhgZ6PW6WbTK_ZHcYWbqJOjxS6JxYhROdsBuwi0_v5ZmemhHHizhrk1qJOF2KaLJZvYG5OcYvlWjtoee1fYHRFD3bBOB-oQSu1eS-rNzQx_LU1k1G_Aw6L0jtgJQd6wub3Bqb0EPtmHY559a4DFOd50_OqgHs3PheWJoyhgZ6PW6WbTK_ZHcYWbqJOjxS6JxYhROdsBuwi0_v5ZmemhHHizhrk1qJOF2KaLJZvYG5OcYvlWjtoee1fYHRFD3bBOB-oQSu1eS-rNzQx_LU1k1G_Aw6L0jtgJQd6wub3Bqb0EPtmH"

  describe "authenticate/2" do
    test "authenticates successfully with VM credentials" do
      credentials = %{
        role: "my-vm-role",
        jwt: @valid_jwt,
        subscription_id: "12345678-1234-1234-1234-123456789012",
        resource_group_name: "my-resource-group",
        vm_name: "my-vm"
      }

      auth_response = %{
        "client_token" => "hvs.CAESTEST_TOKEN_FOR_AZURE_AUTH_TESTING_ONLY_NOT_REAL_SECRET_DATA",
        "accessor" => "test-accessor-uuid-for-azure-auth-testing-only",
        "policies" => ["default", "my-policy"],
        "token_policies" => ["default", "my-policy"],
        "lease_duration" => 3600,
        "renewable" => true,
        "entity_id" => "81d2e2c8-be83-88d2-1c25-b13c5093d51d",
        "token_type" => "service",
        "metadata" => %{
          "role" => "my-vm-role",
          "subscription_id" => "12345678-1234-1234-1234-123456789012",
          "resource_group_name" => "my-resource-group",
          "vm_name" => "my-vm"
        }
      }

      expect_post(200, %{"auth" => auth_response}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/azure/login")
        assert body["role"] == "my-vm-role"
        assert body["jwt"] == @valid_jwt
        assert body["subscription_id"] == "12345678-1234-1234-1234-123456789012"
        assert body["resource_group_name"] == "my-resource-group"
        assert body["vm_name"] == "my-vm"
      end)

      assert {:ok, auth} = Azure.authenticate(credentials)

      assert auth.client_token ==
               "hvs.CAESTEST_TOKEN_FOR_AZURE_AUTH_TESTING_ONLY_NOT_REAL_SECRET_DATA"

      assert auth.accessor == "test-accessor-uuid-for-azure-auth-testing-only"
      assert auth.policies == ["default", "my-policy"]
      assert auth.token_policies == ["default", "my-policy"]
      assert auth.lease_duration == 3600
      assert auth.renewable == true
      assert auth.entity_id == "81d2e2c8-be83-88d2-1c25-b13c5093d51d"
      assert auth.token_type == "service"
      assert auth.metadata["role"] == "my-vm-role"
    end

    test "authenticates successfully with VMSS credentials" do
      credentials = %{
        role: "my-vmss-role",
        jwt: @valid_jwt,
        subscription_id: "12345678-1234-1234-1234-123456789012",
        resource_group_name: "my-resource-group",
        vmss_name: "my-vmss"
      }

      auth_response = %{
        "client_token" => "hvs.CAESTEST_TOKEN_FOR_AZURE_AUTH_TESTING_ONLY_NOT_REAL_SECRET_DATA",
        "accessor" => "test-accessor-uuid-for-azure-auth-testing-only",
        "policies" => ["default", "vmss-policy"],
        "lease_duration" => 7200,
        "renewable" => true,
        "entity_id" => "91d2e2c8-be83-88d2-1c25-b13c5093d51d",
        "token_type" => "service"
      }

      expect_post(200, %{"auth" => auth_response}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/azure/login")
        assert body["role"] == "my-vmss-role"
        assert body["jwt"] == @valid_jwt
        assert body["subscription_id"] == "12345678-1234-1234-1234-123456789012"
        assert body["resource_group_name"] == "my-resource-group"
        assert body["vmss_name"] == "my-vmss"
      end)

      assert {:ok, auth} = Azure.authenticate(credentials)

      assert auth.client_token ==
               "hvs.CAESTEST_TOKEN_FOR_AZURE_AUTH_TESTING_ONLY_NOT_REAL_SECRET_DATA"

      assert auth.policies == ["default", "vmss-policy"]
      assert auth.lease_duration == 7200
      assert auth.entity_id == "91d2e2c8-be83-88d2-1c25-b13c5093d51d"
    end

    test "authenticates successfully with resource ID" do
      credentials = %{
        role: "my-resource-role",
        jwt: @valid_jwt,
        subscription_id: "12345678-1234-1234-1234-123456789012",
        resource_group_name: "my-resource-group",
        resource_id:
          "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/my-rg/providers/Microsoft.Compute/virtualMachines/my-vm"
      }

      auth_response = %{
        "client_token" => "hvs.CAESTEST_TOKEN_FOR_AZURE_AUTH_TESTING_ONLY_NOT_REAL_SECRET_DATA",
        "accessor" => "test-accessor-uuid-for-azure-auth-testing-only",
        "policies" => ["default", "resource-policy"],
        "lease_duration" => 1800,
        "renewable" => true
      }

      expect_post(200, %{"auth" => auth_response}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/azure/login")
        assert body["role"] == "my-resource-role"
        assert body["jwt"] == @valid_jwt

        assert body["resource_id"] ==
                 "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/my-rg/providers/Microsoft.Compute/virtualMachines/my-vm"
      end)

      assert {:ok, auth} = Azure.authenticate(credentials)
      assert auth.policies == ["default", "resource-policy"]
      assert auth.lease_duration == 1800
    end

    test "handles authentication failure" do
      credentials = %{
        role: "invalid-role",
        jwt: @valid_jwt,
        subscription_id: "12345678-1234-1234-1234-123456789012",
        resource_group_name: "my-resource-group",
        vm_name: "my-vm"
      }

      expect_post(403, %{
        "errors" => ["permission denied"]
      })

      assert {:error, error} = Azure.authenticate(credentials)
      assert error.type == :authorization_denied
    end

    test "handles invalid JWT token" do
      credentials = %{
        role: "my-role",
        jwt: @valid_jwt,
        subscription_id: "12345678-1234-1234-1234-123456789012",
        resource_group_name: "my-resource-group",
        vm_name: "my-vm"
      }

      expect_post(400, %{
        "errors" => ["invalid JWT token"]
      })

      assert {:error, error} = Azure.authenticate(credentials)
      assert error.type == :invalid_request
    end

    test "handles role not found" do
      credentials = %{
        role: "nonexistent-role",
        jwt: @valid_jwt,
        subscription_id: "12345678-1234-1234-1234-123456789012",
        resource_group_name: "my-resource-group",
        vm_name: "my-vm"
      }

      expect_post(404, %{
        "errors" => ["role 'nonexistent-role' not found"]
      })

      assert {:error, error} = Azure.authenticate(credentials)
      assert error.type == :not_found
    end

    test "handles HTTP errors" do
      credentials = %{
        role: "my-role",
        jwt: @valid_jwt,
        subscription_id: "12345678-1234-1234-1234-123456789012",
        resource_group_name: "my-resource-group",
        vm_name: "my-vm"
      }

      stub_request_raw(:post, :timeout)

      assert {:error, error} = Azure.authenticate(credentials)
      assert error.type == :http_error
    end

    test "uses custom mount path" do
      credentials = %{
        role: "my-role",
        jwt: @valid_jwt,
        subscription_id: "12345678-1234-1234-1234-123456789012",
        resource_group_name: "my-resource-group",
        vm_name: "my-vm"
      }

      auth_response = %{
        "client_token" => "hvs.test-token",
        "accessor" => "test-accessor",
        "policies" => ["default"],
        "lease_duration" => 3600,
        "renewable" => true
      }

      expect_post(200, %{"auth" => auth_response}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/custom-azure/login")
      end)

      assert {:ok, _auth} = Azure.authenticate(credentials, mount_path: "custom-azure")
    end
  end

  describe "validate_credentials/1" do
    test "validates VM credentials successfully" do
      credentials = %{
        role: "my-role",
        jwt: @valid_jwt,
        subscription_id: "12345678-1234-1234-1234-123456789012",
        resource_group_name: "my-resource-group",
        vm_name: "my-vm"
      }

      assert :ok = Azure.validate_credentials(credentials)
    end

    test "validates VMSS credentials successfully" do
      credentials = %{
        role: "my-role",
        jwt: @valid_jwt,
        subscription_id: "12345678-1234-1234-1234-123456789012",
        resource_group_name: "my-resource-group",
        vmss_name: "my-vmss"
      }

      assert :ok = Azure.validate_credentials(credentials)
    end

    test "validates resource ID credentials successfully" do
      credentials = %{
        role: "my-role",
        jwt: @valid_jwt,
        resource_id:
          "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/my-rg/providers/Microsoft.Compute/virtualMachines/my-vm"
      }

      assert :ok = Azure.validate_credentials(credentials)
    end

    test "rejects credentials missing role" do
      credentials = %{
        jwt: @valid_jwt,
        subscription_id: "12345678-1234-1234-1234-123456789012",
        resource_group_name: "my-resource-group",
        vm_name: "my-vm"
      }

      assert {:error, error} = Azure.validate_credentials(credentials)
      assert error.type == :invalid_credentials
      assert String.contains?(error.message, "Missing required fields")
    end

    test "rejects credentials missing JWT" do
      credentials = %{
        role: "my-role",
        subscription_id: "12345678-1234-1234-1234-123456789012",
        resource_group_name: "my-resource-group",
        vm_name: "my-vm"
      }

      assert {:error, error} = Azure.validate_credentials(credentials)
      assert error.type == :invalid_credentials
      assert String.contains?(error.message, "Missing required fields")
    end

    test "rejects credentials missing resource identification" do
      credentials = %{
        role: "my-role",
        jwt: @valid_jwt
      }

      assert {:error, error} = Azure.validate_credentials(credentials)
      assert error.type == :invalid_credentials
      assert String.contains?(error.message, "Must provide either")
    end

    test "rejects invalid JWT format" do
      credentials = %{
        role: "my-role",
        jwt: "invalid-jwt-without-dots",
        subscription_id: "12345678-1234-1234-1234-123456789012",
        resource_group_name: "my-resource-group",
        vm_name: "my-vm"
      }

      assert {:error, error} = Azure.validate_credentials(credentials)
      assert error.type == :invalid_credentials
      assert String.contains?(error.message, "JWT must be a valid JWT token string")
    end

    test "rejects non-map credentials" do
      assert {:error, error} = Azure.validate_credentials("invalid")
      assert error.type == :invalid_credentials
      assert String.contains?(error.message, "Credentials must be a map")
    end
  end

  describe "metadata/0" do
    test "returns correct metadata" do
      metadata = Azure.metadata()

      assert metadata.name == "azure"

      assert metadata.description ==
               "Azure Managed Service Identity and Service Principal authentication"

      assert metadata.required_fields == [:role, :jwt]
      assert :subscription_id in metadata.optional_fields
      assert :resource_group_name in metadata.optional_fields
      assert :vm_name in metadata.optional_fields
      assert :vmss_name in metadata.optional_fields
      assert :resource_id in metadata.optional_fields
      assert metadata.supports_refresh == false
      assert metadata.supports_revocation == false
    end
  end

  describe "authenticate/2 with validation failures" do
    test "handles credential validation failure during authentication" do
      # Test with invalid credentials that will fail validation
      credentials = %{
        role: "my-role"
        # Missing JWT and resource identification
      }

      assert {:error, error} = Azure.authenticate(credentials)
      assert error.type == :invalid_credentials
      assert String.contains?(error.message, "Missing required fields")
    end
  end

  # Edge cases and comprehensive testing
  describe "edge cases and error scenarios" do
    test "handles malformed auth response gracefully" do
      credentials = %{
        role: "my-role",
        jwt: @valid_jwt,
        subscription_id: "12345678-1234-1234-1234-123456789012",
        resource_group_name: "my-resource-group",
        vm_name: "my-vm"
      }

      # Response missing auth field
      expect_post(200, %{"data" => "invalid"})

      assert {:error, error} = Azure.authenticate(credentials)
      assert error.type == :unknown_error
    end

    test "handles concurrent authentication requests" do
      credentials = %{
        role: "my-role",
        jwt: @valid_jwt,
        subscription_id: "12345678-1234-1234-1234-123456789012",
        resource_group_name: "my-resource-group",
        vm_name: "my-vm"
      }

      auth_response = %{
        "client_token" => "hvs.test-token",
        "accessor" => "test-accessor",
        "policies" => ["default"],
        "lease_duration" => 3600,
        "renewable" => true
      }

      # Mock multiple successful responses
      for _i <- 1..5 do
        expect_post(200, %{"auth" => auth_response})
      end

      tasks =
        1..5
        |> Enum.map(fn _i ->
          Task.async(fn ->
            Azure.authenticate(credentials)
          end)
        end)

      results = Task.await_many(tasks, 5000)

      # All operations should succeed
      assert Enum.all?(results, fn
               {:ok, _auth} -> true
               _ -> false
             end)
    end
  end
end
