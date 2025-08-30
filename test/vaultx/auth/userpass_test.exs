defmodule Vaultx.Auth.UserPassTest do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Auth.UserPass
  alias Vaultx.Base.Error

  # Sample auth response from Vault
  @auth_response %{
    "auth" => %{
      "client_token" => "hvs.CAESIJ1234567890",
      "accessor" => "hmac-sha256:accessor123",
      "policies" => ["default", "myapp"],
      "lease_duration" => 3600,
      "renewable" => true,
      "entity_id" => "entity-123",
      "token_type" => "service",
      "metadata" => %{"username" => "testuser"}
    }
  }

  describe "authenticate/2" do
    test "authenticates with valid credentials successfully" do
      expect_post(200, @auth_response, fn url, body, _opts ->
        assert String.contains?(url, "auth/userpass/login/testuser")
        assert body["password"] == "testpass"
      end)

      credentials = %{username: "testuser", password: "testpass"}
      assert {:ok, auth_response} = UserPass.authenticate(credentials)

      assert auth_response.client_token == "hvs.CAESIJ1234567890"
      assert auth_response.accessor == "hmac-sha256:accessor123"
      assert auth_response.policies == ["default", "myapp"]
      assert auth_response.lease_duration == 3600
      assert auth_response.renewable == true
      assert auth_response.entity_id == "entity-123"
      assert auth_response.token_type == "service"
      assert auth_response.metadata == %{auth_method: "userpass", username: "testuser"}
    end

    test "authenticates with custom mount path" do
      expect_post(200, @auth_response, fn url, body, _opts ->
        assert String.contains?(url, "auth/custom-userpass/login/testuser")
        assert body["password"] == "testpass"
      end)

      credentials = %{username: "testuser", password: "testpass"}
      opts = [mount_path: "custom-userpass"]
      assert {:ok, _auth_response} = UserPass.authenticate(credentials, opts)
    end

    test "handles authentication failure" do
      error_response = %{
        "errors" => ["invalid username or password"],
        "status" => 400
      }

      expect_post(400, error_response)

      credentials = %{username: "testuser", password: "wrongpass"}
      assert {:error, %Error{} = error} = UserPass.authenticate(credentials)
      assert error.type == :invalid_request
    end

    test "handles network errors" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      credentials = %{username: "testuser", password: "testpass"}
      assert {:error, %Error{} = error} = UserPass.authenticate(credentials)
      assert error.type == :unknown_error
    end

    test "handles server errors" do
      error_response = %{
        "errors" => ["internal server error"],
        "status" => 500
      }

      expect_post(500, error_response)

      credentials = %{username: "testuser", password: "testpass"}
      assert {:error, %Error{} = error} = UserPass.authenticate(credentials)
      assert error.type == :server_error
    end
  end

  describe "validate_credentials/1" do
    test "validates correct credentials" do
      credentials = %{username: "testuser", password: "testpass"}
      assert :ok = UserPass.validate_credentials(credentials)
    end

    test "rejects missing username" do
      credentials = %{password: "testpass"}
      assert {:error, %Error{} = error} = UserPass.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Missing required fields: username")
    end

    test "rejects missing password" do
      credentials = %{username: "testuser"}
      assert {:error, %Error{} = error} = UserPass.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Missing required fields: password")
    end

    test "rejects missing both username and password" do
      credentials = %{}
      assert {:error, %Error{} = error} = UserPass.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Missing required fields: username, password")
    end

    test "rejects non-string username" do
      credentials = %{username: 123, password: "testpass"}
      assert {:error, %Error{} = error} = UserPass.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Username must be a string")
    end

    test "rejects non-string password" do
      credentials = %{username: "testuser", password: 123}
      assert {:error, %Error{} = error} = UserPass.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Password must be a string")
    end

    test "rejects empty username" do
      credentials = %{username: "", password: "testpass"}
      assert {:error, %Error{} = error} = UserPass.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Username cannot be empty")
    end

    test "rejects empty password" do
      credentials = %{username: "testuser", password: ""}
      assert {:error, %Error{} = error} = UserPass.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Password cannot be empty")
    end

    test "rejects username that is too long" do
      long_username = String.duplicate("a", 257)
      credentials = %{username: long_username, password: "testpass"}
      assert {:error, %Error{} = error} = UserPass.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Username too long")
    end

    test "rejects password that is too long" do
      long_password = String.duplicate("a", 4097)
      credentials = %{username: "testuser", password: long_password}
      assert {:error, %Error{} = error} = UserPass.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Password too long")
    end

    test "rejects invalid UTF-8 username" do
      invalid_username = <<0xFF, 0xFE>>
      credentials = %{username: invalid_username, password: "testpass"}
      assert {:error, %Error{} = error} = UserPass.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Username must be valid UTF-8")
    end

    test "rejects invalid UTF-8 password" do
      invalid_password = <<0xFF, 0xFE>>
      credentials = %{username: "testuser", password: invalid_password}
      assert {:error, %Error{} = error} = UserPass.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Password must be valid UTF-8")
    end

    test "rejects non-map credentials" do
      assert {:error, %Error{} = error} = UserPass.validate_credentials("invalid")
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Credentials must be a map")
    end

    test "accepts maximum length username and password" do
      max_username = String.duplicate("a", 256)
      max_password = String.duplicate("a", 4096)
      credentials = %{username: max_username, password: max_password}
      assert :ok = UserPass.validate_credentials(credentials)
    end

    test "handles credentials with nil username gracefully" do
      credentials = %{username: nil, password: "testpass"}
      assert {:error, %Error{} = error} = UserPass.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Username cannot be empty")
    end

    test "handles credentials with nil password gracefully" do
      credentials = %{username: "testuser", password: nil}
      assert {:error, %Error{} = error} = UserPass.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Password cannot be empty")
    end
  end

  describe "refresh_token/2" do
    test "returns not supported error" do
      assert {:error, %Error{} = error} = UserPass.refresh_token("token", [])
      assert error.type == :not_supported
      assert String.contains?(error.message, "does not support token refresh")
    end
  end

  describe "revoke_token/2" do
    test "returns not supported error" do
      assert {:error, %Error{} = error} = UserPass.revoke_token("token", [])
      assert error.type == :not_supported
      assert String.contains?(error.message, "does not support token revocation")
    end
  end

  describe "metadata/0" do
    test "returns correct metadata" do
      metadata = UserPass.metadata()

      assert metadata.name == "Username & Password"
      assert metadata.supports_refresh == false
      assert metadata.supports_revocation == false
      assert metadata.required_fields == [:username, :password]
      assert metadata.optional_fields == []
      assert String.contains?(metadata.description, "username and password")
    end
  end
end
