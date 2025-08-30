defmodule Vaultx.Auth.AppRoleTest do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Auth.AppRole
  alias Vaultx.Base.Error

  # Sample auth response from Vault
  @auth_response %{
    "auth" => %{
      "client_token" => "hvs.CAESIJ1234567890",
      "accessor" => "hmac-sha256:accessor123",
      "policies" => ["default", "my-policy"],
      "lease_duration" => 3600,
      "renewable" => true,
      "entity_id" => "entity-123",
      "token_type" => "service",
      "metadata" => %{"role_name" => "my-role"}
    }
  }

  describe "authenticate/2" do
    test "authenticates with role_id and secret_id successfully" do
      expect_post(200, @auth_response, fn url, body, _opts ->
        assert String.contains?(url, "auth/approle/login")
        assert body["role_id"] == "59d6d1ca-47bb-4e7e-a40b-8be3bc5a0ba8"
        assert body["secret_id"] == "84896a0c-1347-aa90-a4f6-aca8b7558780"
      end)

      credentials = %{
        role_id: "59d6d1ca-47bb-4e7e-a40b-8be3bc5a0ba8",
        secret_id: "84896a0c-1347-aa90-a4f6-aca8b7558780"
      }

      assert {:ok, auth_response} = AppRole.authenticate(credentials)

      assert auth_response.client_token == "hvs.CAESIJ1234567890"
      assert auth_response.accessor == "hmac-sha256:accessor123"
      assert auth_response.policies == ["default", "my-policy"]
      assert auth_response.lease_duration == 3600
      assert auth_response.renewable == true
      assert auth_response.entity_id == "entity-123"
      assert auth_response.token_type == "service"

      assert auth_response.metadata == %{
               auth_method: "approle",
               role_id: "59d6d1ca-47bb-4e7e-a40b-8be3bc5a0ba8"
             }
    end

    test "authenticates with only role_id (no secret_id required)" do
      expect_post(200, @auth_response, fn url, body, _opts ->
        assert String.contains?(url, "auth/approle/login")
        assert body["role_id"] == "59d6d1ca-47bb-4e7e-a40b-8be3bc5a0ba8"
        refute Map.has_key?(body, "secret_id")
      end)

      credentials = %{role_id: "59d6d1ca-47bb-4e7e-a40b-8be3bc5a0ba8"}
      assert {:ok, auth_response} = AppRole.authenticate(credentials)

      assert auth_response.client_token == "hvs.CAESIJ1234567890"

      assert auth_response.metadata == %{
               auth_method: "approle",
               role_id: "59d6d1ca-47bb-4e7e-a40b-8be3bc5a0ba8"
             }
    end

    test "authenticates with custom mount path" do
      expect_post(200, @auth_response, fn url, body, _opts ->
        assert String.contains?(url, "auth/custom-approle/login")
        assert body["role_id"] == "59d6d1ca-47bb-4e7e-a40b-8be3bc5a0ba8"
      end)

      credentials = %{role_id: "59d6d1ca-47bb-4e7e-a40b-8be3bc5a0ba8"}
      opts = [mount_path: "custom-approle"]
      assert {:ok, _auth_response} = AppRole.authenticate(credentials, opts)
    end

    test "handles authentication failure with invalid credentials" do
      expect_post(400, %{"errors" => ["invalid role ID or secret ID"]})

      credentials = %{
        role_id: "invalid-role-id",
        secret_id: "invalid-secret-id"
      }

      assert {:error, %Error{} = error} = AppRole.authenticate(credentials)
      assert error.type == :authentication_failed
    end

    test "handles network errors" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      credentials = %{role_id: "59d6d1ca-47bb-4e7e-a40b-8be3bc5a0ba8"}
      assert {:error, %Error{} = error} = AppRole.authenticate(credentials)
      assert error.type == :unknown_error
    end

    test "handles server errors" do
      expect_post(500, %{"errors" => ["internal server error"]})

      credentials = %{role_id: "59d6d1ca-47bb-4e7e-a40b-8be3bc5a0ba8"}
      assert {:error, %Error{} = error} = AppRole.authenticate(credentials)
      assert error.type == :authentication_failed
    end

    test "handles AppRole server unavailable" do
      expect_post(503, %{"errors" => ["AppRole server unavailable"]})

      credentials = %{role_id: "59d6d1ca-47bb-4e7e-a40b-8be3bc5a0ba8"}
      assert {:error, %Error{} = error} = AppRole.authenticate(credentials)
      assert error.type == :authentication_failed
    end
  end

  describe "refresh_token/2" do
    test "returns unsupported operation error" do
      assert {:error, %Error{} = error} = AppRole.refresh_token("token", [])
      assert error.type == :unsupported_operation
      assert String.contains?(error.message, "does not support token refresh")
    end
  end

  describe "revoke_token/2" do
    test "returns unsupported operation error" do
      assert {:error, %Error{} = error} = AppRole.revoke_token("token", [])
      assert error.type == :unsupported_operation
      assert String.contains?(error.message, "does not support token revocation")
    end
  end

  describe "validate_credentials/1" do
    test "accepts valid credentials with role_id and secret_id" do
      credentials = %{
        role_id: "59d6d1ca-47bb-4e7e-a40b-8be3bc5a0ba8",
        secret_id: "84896a0c-1347-aa90-a4f6-aca8b7558780"
      }

      assert :ok = AppRole.validate_credentials(credentials)
    end

    test "accepts valid credentials with only role_id" do
      credentials = %{role_id: "59d6d1ca-47bb-4e7e-a40b-8be3bc5a0ba8"}
      assert :ok = AppRole.validate_credentials(credentials)
    end

    test "rejects missing role_id" do
      credentials = %{secret_id: "84896a0c-1347-aa90-a4f6-aca8b7558780"}
      assert {:error, %Error{} = error} = AppRole.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Missing required fields: role_id")
    end

    test "rejects empty role_id" do
      credentials = %{role_id: "", secret_id: "84896a0c-1347-aa90-a4f6-aca8b7558780"}
      assert {:error, %Error{} = error} = AppRole.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Role ID cannot be empty")
    end

    test "rejects empty secret_id" do
      credentials = %{role_id: "59d6d1ca-47bb-4e7e-a40b-8be3bc5a0ba8", secret_id: ""}
      assert {:error, %Error{} = error} = AppRole.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Secret ID cannot be empty")
    end

    test "rejects non-string role_id" do
      credentials = %{role_id: 123, secret_id: "84896a0c-1347-aa90-a4f6-aca8b7558780"}
      assert {:error, %Error{} = error} = AppRole.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Field 'role_id' must be a string")
    end

    test "rejects non-string secret_id" do
      credentials = %{role_id: "59d6d1ca-47bb-4e7e-a40b-8be3bc5a0ba8", secret_id: 123}
      assert {:error, %Error{} = error} = AppRole.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Field 'secret_id' must be a string")
    end

    test "rejects role_id that is too long" do
      long_role_id = String.duplicate("a", 4097)
      credentials = %{role_id: long_role_id}
      assert {:error, %Error{} = error} = AppRole.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Role ID too long")
    end

    test "rejects secret_id that is too long" do
      long_secret_id = String.duplicate("a", 4097)
      credentials = %{role_id: "59d6d1ca-47bb-4e7e-a40b-8be3bc5a0ba8", secret_id: long_secret_id}
      assert {:error, %Error{} = error} = AppRole.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Secret ID too long")
    end

    test "rejects role_id with invalid UTF-8" do
      invalid_role_id = <<0xFF, 0xFE>>
      credentials = %{role_id: invalid_role_id}
      assert {:error, %Error{} = error} = AppRole.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Role ID contains invalid UTF-8")
    end

    test "rejects secret_id with invalid UTF-8" do
      invalid_secret_id = <<0xFF, 0xFE>>

      credentials = %{
        role_id: "59d6d1ca-47bb-4e7e-a40b-8be3bc5a0ba8",
        secret_id: invalid_secret_id
      }

      assert {:error, %Error{} = error} = AppRole.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Secret ID contains invalid UTF-8")
    end

    test "accepts maximum length role_id" do
      max_role_id = String.duplicate("a", 4096)
      credentials = %{role_id: max_role_id}
      assert :ok = AppRole.validate_credentials(credentials)
    end

    test "accepts maximum length secret_id" do
      max_secret_id = String.duplicate("a", 4096)
      credentials = %{role_id: "59d6d1ca-47bb-4e7e-a40b-8be3bc5a0ba8", secret_id: max_secret_id}
      assert :ok = AppRole.validate_credentials(credentials)
    end

    test "accepts unicode characters in role_id" do
      unicode_role_id = "RoleID-123"
      credentials = %{role_id: unicode_role_id}
      assert :ok = AppRole.validate_credentials(credentials)
    end

    test "accepts unicode characters in secret_id" do
      unicode_secret_id = "SecretID-456"

      credentials = %{
        role_id: "59d6d1ca-47bb-4e7e-a40b-8be3bc5a0ba8",
        secret_id: unicode_secret_id
      }

      assert :ok = AppRole.validate_credentials(credentials)
    end

    test "accepts UUID format role_id" do
      uuid_role_id = "59d6d1ca-47bb-4e7e-a40b-8be3bc5a0ba8"
      credentials = %{role_id: uuid_role_id}
      assert :ok = AppRole.validate_credentials(credentials)
    end

    test "accepts UUID format secret_id" do
      uuid_secret_id = "84896a0c-1347-aa90-a4f6-aca8b7558780"
      credentials = %{role_id: "59d6d1ca-47bb-4e7e-a40b-8be3bc5a0ba8", secret_id: uuid_secret_id}
      assert :ok = AppRole.validate_credentials(credentials)
    end
  end

  describe "metadata/0" do
    test "returns correct metadata" do
      metadata = AppRole.metadata()

      assert metadata.name == "approle"
      assert metadata.supports_refresh == false
      assert metadata.supports_revocation == false
      assert metadata.required_fields == [:role_id]
      assert metadata.optional_fields == [:secret_id]
      assert is_binary(metadata.description)
      assert String.contains?(metadata.description, "Machine-to-machine authentication")
    end
  end
end
