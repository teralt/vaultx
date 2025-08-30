defmodule Vaultx.Auth.LDAPTest do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Auth.LDAP
  alias Vaultx.Base.Error

  # Sample auth response from Vault
  @auth_response %{
    "auth" => %{
      "client_token" => "hvs.CAESIJ1234567890",
      "accessor" => "hmac-sha256:accessor123",
      "policies" => ["default", "developers"],
      "lease_duration" => 3600,
      "renewable" => true,
      "entity_id" => "entity-123",
      "token_type" => "service",
      "metadata" => %{"username" => "Fleey.dev"}
    }
  }

  describe "authenticate/2" do
    test "authenticates with valid credentials successfully" do
      expect_post(200, @auth_response, fn url, body, _opts ->
        assert String.contains?(url, "auth/ldap/login/Fleey.dev")
        assert body["password"] == "mypassword"
      end)

      credentials = %{username: "Fleey.dev", password: "mypassword"}
      assert {:ok, auth_response} = LDAP.authenticate(credentials)

      assert auth_response.client_token == "hvs.CAESIJ1234567890"
      assert auth_response.accessor == "hmac-sha256:accessor123"
      assert auth_response.policies == ["default", "developers"]
      assert auth_response.lease_duration == 3600
      assert auth_response.renewable == true
      assert auth_response.entity_id == "entity-123"
      assert auth_response.token_type == "service"
      assert auth_response.metadata == %{auth_method: "ldap", username: "Fleey.dev"}
    end

    test "authenticates with custom mount path" do
      expect_post(200, @auth_response, fn url, body, _opts ->
        assert String.contains?(url, "auth/custom-ldap/login/Fleey.dev")
        assert body["password"] == "mypassword"
      end)

      credentials = %{username: "Fleey.dev", password: "mypassword"}
      opts = [mount_path: "custom-ldap"]
      assert {:ok, _auth_response} = LDAP.authenticate(credentials, opts)
    end

    test "handles authentication failure with invalid credentials" do
      expect_post(400, %{"errors" => ["invalid username or password"]})

      credentials = %{username: "Fleey.dev", password: "wrongpass"}
      assert {:error, %Error{} = error} = LDAP.authenticate(credentials)
      assert error.type == :authentication_failed
    end

    test "handles network errors" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      credentials = %{username: "Fleey.dev", password: "mypassword"}
      assert {:error, %Error{} = error} = LDAP.authenticate(credentials)
      assert error.type == :unknown_error
    end

    test "handles server errors" do
      expect_post(500, %{"errors" => ["internal server error"]})

      credentials = %{username: "Fleey.dev", password: "mypassword"}
      assert {:error, %Error{} = error} = LDAP.authenticate(credentials)
      assert error.type == :authentication_failed
    end

    test "handles LDAP server unavailable" do
      expect_post(503, %{"errors" => ["LDAP server unavailable"]})

      credentials = %{username: "Fleey.dev", password: "mypassword"}
      assert {:error, %Error{} = error} = LDAP.authenticate(credentials)
      assert error.type == :authentication_failed
    end
  end

  describe "refresh_token/2" do
    test "returns unsupported operation error" do
      assert {:error, %Error{} = error} = LDAP.refresh_token("token", [])
      assert error.type == :unsupported_operation
      assert String.contains?(error.message, "does not support token refresh")
    end
  end

  describe "revoke_token/2" do
    test "returns unsupported operation error" do
      assert {:error, %Error{} = error} = LDAP.revoke_token("token", [])
      assert error.type == :unsupported_operation
      assert String.contains?(error.message, "does not support token revocation")
    end
  end

  describe "validate_credentials/1" do
    test "accepts valid credentials" do
      credentials = %{username: "Fleey.dev", password: "mypassword"}
      assert :ok = LDAP.validate_credentials(credentials)
    end

    test "rejects missing username" do
      credentials = %{password: "mypassword"}
      assert {:error, %Error{} = error} = LDAP.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Missing required fields: username")
    end

    test "rejects missing password" do
      credentials = %{username: "Fleey.dev"}
      assert {:error, %Error{} = error} = LDAP.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Missing required fields: password")
    end

    test "rejects empty username" do
      credentials = %{username: "", password: "mypassword"}
      assert {:error, %Error{} = error} = LDAP.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Username cannot be empty")
    end

    test "rejects empty password" do
      credentials = %{username: "Fleey.dev", password: ""}
      assert {:error, %Error{} = error} = LDAP.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Password cannot be empty")
    end

    test "rejects non-string username" do
      credentials = %{username: 123, password: "mypassword"}
      assert {:error, %Error{} = error} = LDAP.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Field 'username' must be a string")
    end

    test "rejects non-string password" do
      credentials = %{username: "Fleey.dev", password: 123}
      assert {:error, %Error{} = error} = LDAP.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Field 'password' must be a string")
    end

    test "rejects username that is too long" do
      long_username = String.duplicate("a", 257)
      credentials = %{username: long_username, password: "mypassword"}
      assert {:error, %Error{} = error} = LDAP.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Username too long")
    end

    test "rejects password that is too long" do
      long_password = String.duplicate("a", 4097)
      credentials = %{username: "Fleey.dev", password: long_password}
      assert {:error, %Error{} = error} = LDAP.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Password too long")
    end

    test "rejects username with invalid UTF-8" do
      invalid_username = <<0xFF, 0xFE>>
      credentials = %{username: invalid_username, password: "mypassword"}
      assert {:error, %Error{} = error} = LDAP.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Username contains invalid UTF-8")
    end

    test "rejects password with invalid UTF-8" do
      invalid_password = <<0xFF, 0xFE>>
      credentials = %{username: "Fleey.dev", password: invalid_password}
      assert {:error, %Error{} = error} = LDAP.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Password contains invalid UTF-8")
    end

    test "accepts maximum length username" do
      max_username = String.duplicate("a", 256)
      credentials = %{username: max_username, password: "mypassword"}
      assert :ok = LDAP.validate_credentials(credentials)
    end

    test "accepts maximum length password" do
      max_password = String.duplicate("a", 4096)
      credentials = %{username: "Fleey.dev", password: max_password}
      assert :ok = LDAP.validate_credentials(credentials)
    end

    test "accepts unicode characters in username" do
      unicode_username = "用户名"
      credentials = %{username: unicode_username, password: "mypassword"}
      assert :ok = LDAP.validate_credentials(credentials)
    end

    test "accepts unicode characters in password" do
      unicode_password = "密码123"
      credentials = %{username: "Fleey.dev", password: unicode_password}
      assert :ok = LDAP.validate_credentials(credentials)
    end

    test "accepts special characters in username" do
      special_username = "Fleey.dev@company.com"
      credentials = %{username: special_username, password: "mypassword"}
      assert :ok = LDAP.validate_credentials(credentials)
    end

    test "accepts special characters in password" do
      special_password = "P@ssw0rd!#$%"
      credentials = %{username: "Fleey.dev", password: special_password}
      assert :ok = LDAP.validate_credentials(credentials)
    end
  end

  describe "metadata/0" do
    test "returns correct metadata" do
      metadata = LDAP.metadata()

      assert metadata.name == "ldap"
      assert metadata.supports_refresh == false
      assert metadata.supports_revocation == false
      assert metadata.required_fields == [:username, :password]
      assert metadata.optional_fields == []
      assert is_binary(metadata.description)
      assert String.contains?(metadata.description, "LDAP directory authentication")
    end
  end

  # Test edge cases and error conditions
  describe "edge cases" do
    test "handles malformed auth response" do
      malformed_response = %{"data" => %{"some" => "data"}}
      expect_post(200, malformed_response)

      credentials = %{username: "Fleey.dev", password: "mypassword"}
      assert {:error, %Error{}} = LDAP.authenticate(credentials)
    end

    test "handles missing auth field in response" do
      missing_auth_response = %{"lease_id" => "", "renewable" => false}
      expect_post(200, missing_auth_response)

      credentials = %{username: "Fleey.dev", password: "mypassword"}
      assert {:error, %Error{}} = LDAP.authenticate(credentials)
    end

    test "handles auth response with minimal fields" do
      minimal_auth_response = %{
        "auth" => %{
          "client_token" => "hvs.MINIMAL123"
        }
      }

      expect_post(200, minimal_auth_response, fn url, body, _opts ->
        assert String.contains?(url, "auth/ldap/login/Fleey.dev")
        assert body["password"] == "mypassword"
      end)

      credentials = %{username: "Fleey.dev", password: "mypassword"}
      assert {:ok, auth_response} = LDAP.authenticate(credentials)

      assert auth_response.client_token == "hvs.MINIMAL123"
      assert auth_response.policies == []
      assert auth_response.lease_duration == 0
      assert auth_response.renewable == false
      assert auth_response.metadata == %{auth_method: "ldap", username: "Fleey.dev"}
    end

    test "handles auth response with null values" do
      null_auth_response = %{
        "auth" => %{
          "client_token" => "hvs.NULL123",
          "policies" => nil,
          "metadata" => nil,
          "entity_id" => nil
        }
      }

      expect_post(200, null_auth_response, fn url, body, _opts ->
        assert String.contains?(url, "auth/ldap/login/Fleey.dev")
        assert body["password"] == "mypassword"
      end)

      credentials = %{username: "Fleey.dev", password: "mypassword"}
      assert {:ok, auth_response} = LDAP.authenticate(credentials)

      assert auth_response.client_token == "hvs.NULL123"
      assert auth_response.policies == []
      assert auth_response.metadata == %{auth_method: "ldap", username: "Fleey.dev"}
      assert is_nil(auth_response.entity_id)
    end
  end
end
