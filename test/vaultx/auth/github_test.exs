defmodule Vaultx.Auth.GitHubTest do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Auth.GitHub
  alias Vaultx.Base.Error

  # Sample auth response from Vault
  @auth_response %{
    "auth" => %{
      "client_token" => "hvs.CAESIJ1234567890",
      "accessor" => "hmac-sha256:accessor123",
      "policies" => ["default", "dev-team"],
      "lease_duration" => 7200,
      "renewable" => true,
      "entity_id" => "entity-456",
      "token_type" => "service",
      "metadata" => %{
        "username" => "john-doe",
        "org" => "my-org"
      }
    }
  }

  describe "authenticate/2" do
    test "authenticates with valid GitHub token successfully" do
      expect_post(200, @auth_response, fn url, body, _opts ->
        assert String.contains?(url, "auth/github/login")
        assert body["token"] == "ghp_1234567890abcdef1234567890abcdef12345678"
      end)

      credentials = %{token: "ghp_1234567890abcdef1234567890abcdef12345678"}
      assert {:ok, auth_response} = GitHub.authenticate(credentials)

      assert auth_response.client_token == "hvs.CAESIJ1234567890"
      assert auth_response.accessor == "hmac-sha256:accessor123"
      assert auth_response.policies == ["default", "dev-team"]
      assert auth_response.lease_duration == 7200
      assert auth_response.renewable == true
      assert auth_response.entity_id == "entity-456"
      assert auth_response.token_type == "service"
      assert auth_response.metadata == %{"username" => "john-doe", "org" => "my-org"}
    end

    test "authenticates with custom mount path" do
      expect_post(200, @auth_response, fn url, body, _opts ->
        assert String.contains?(url, "auth/custom-github/login")
        assert body["token"] == "ghp_1234567890abcdef1234567890abcdef12345678"
      end)

      credentials = %{token: "ghp_1234567890abcdef1234567890abcdef12345678"}
      opts = [mount_path: "custom-github"]
      assert {:ok, _auth_response} = GitHub.authenticate(credentials, opts)
    end

    test "authenticates with fine-grained personal access token" do
      fine_grained_token =
        "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

      expect_post(200, @auth_response, fn url, body, _opts ->
        assert String.contains?(url, "auth/github/login")
        assert body["token"] == fine_grained_token
      end)

      credentials = %{token: fine_grained_token}
      assert {:ok, _auth_response} = GitHub.authenticate(credentials)
    end

    test "handles authentication failure" do
      error_response = %{
        "errors" => ["permission denied"],
        "status" => 403
      }

      expect_post(403, error_response)

      # Use a valid token format that will pass validation but fail authentication
      credentials = %{token: "ghp_1234567890abcdef1234567890abcdef12345678"}
      assert {:error, %Error{} = error} = GitHub.authenticate(credentials)
      assert error.type == :authorization_denied
    end

    test "handles network errors" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      credentials = %{token: "ghp_1234567890abcdef1234567890abcdef12345678"}
      assert {:error, %Error{} = error} = GitHub.authenticate(credentials)
      assert error.type == :unknown_error
    end

    test "handles server errors" do
      error_response = %{
        "errors" => ["internal server error"],
        "status" => 500
      }

      expect_post(500, error_response)

      credentials = %{token: "ghp_1234567890abcdef1234567890abcdef12345678"}
      assert {:error, %Error{} = error} = GitHub.authenticate(credentials)
      assert error.type == :server_error
    end

    test "passes custom options to HTTP request" do
      expect_post(200, @auth_response, fn _url, _body, opts ->
        assert opts[:timeout] == 30_000
        assert opts[:retry_attempts] == 3
      end)

      credentials = %{token: "ghp_1234567890abcdef1234567890abcdef12345678"}
      opts = [timeout: 30_000, retry_attempts: 3]
      assert {:ok, _auth_response} = GitHub.authenticate(credentials, opts)
    end
  end

  describe "validate_credentials/1" do
    test "validates classic personal access token" do
      credentials = %{token: "ghp_1234567890abcdef1234567890abcdef12345678"}
      assert :ok = GitHub.validate_credentials(credentials)
    end

    test "validates fine-grained personal access token" do
      credentials = %{
        token:
          "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
      }

      assert :ok = GitHub.validate_credentials(credentials)
    end

    test "validates OAuth token" do
      credentials = %{token: "gho_1234567890abcdef1234567890abcdef"}
      assert :ok = GitHub.validate_credentials(credentials)
    end

    test "validates installation token" do
      credentials = %{token: "ghs_1234567890abcdef1234567890abcdef"}
      assert :ok = GitHub.validate_credentials(credentials)
    end

    test "validates refresh token" do
      credentials = %{token: "ghr_1234567890abcdef1234567890abcdef"}
      assert :ok = GitHub.validate_credentials(credentials)
    end

    test "validates generic long token (for GitHub Enterprise)" do
      credentials = %{token: "custom_token_1234567890abcdef"}
      assert :ok = GitHub.validate_credentials(credentials)
    end

    test "rejects missing token" do
      credentials = %{}
      assert {:error, %Error{} = error} = GitHub.validate_credentials(credentials)
      assert error.type == :invalid_credentials
      assert String.contains?(error.message, "GitHub token is required")
    end

    test "rejects nil token" do
      credentials = %{token: nil}
      assert {:error, %Error{} = error} = GitHub.validate_credentials(credentials)
      assert error.type == :invalid_credentials
      assert String.contains?(error.message, "GitHub token is required")
    end

    test "rejects empty token" do
      credentials = %{token: ""}
      assert {:error, %Error{} = error} = GitHub.validate_credentials(credentials)
      assert error.type == :invalid_credentials
      assert String.contains?(error.message, "GitHub token must be a non-empty string")
    end

    test "rejects non-string token" do
      credentials = %{token: 12345}
      assert {:error, %Error{} = error} = GitHub.validate_credentials(credentials)
      assert error.type == :invalid_credentials
      assert String.contains?(error.message, "GitHub token must be a non-empty string")
    end

    test "rejects invalid token format" do
      credentials = %{token: "invalid_token"}
      assert {:error, %Error{} = error} = GitHub.validate_credentials(credentials)
      assert error.type == :invalid_credentials
      assert String.contains?(error.message, "Invalid GitHub token format")
    end

    test "rejects non-map credentials" do
      assert {:error, %Error{} = error} = GitHub.validate_credentials("invalid")
      assert error.type == :invalid_credentials
      assert String.contains?(error.message, "Credentials must be a map")
    end
  end

  describe "refresh_token/2" do
    test "returns not supported error" do
      assert {:error, %Error{} = error} = GitHub.refresh_token("token", [])
      assert error.type == :not_supported
      assert String.contains?(error.message, "does not support token refresh")
    end
  end

  describe "revoke_token/2" do
    test "returns not supported error" do
      assert {:error, %Error{} = error} = GitHub.revoke_token("token", [])
      assert error.type == :not_supported
      assert String.contains?(error.message, "does not support token revocation")
    end
  end

  describe "metadata/0" do
    test "returns correct metadata" do
      metadata = GitHub.metadata()

      assert metadata.name == "GitHub Authentication"
      assert metadata.supports_refresh == false
      assert metadata.supports_revocation == false
      assert metadata.required_fields == [:token]
      assert metadata.optional_fields == []
      assert metadata.description == "Authenticate using GitHub personal access tokens"
    end
  end

  describe "token format validation" do
    test "validates various GitHub token formats" do
      valid_tokens = [
        # Classic personal access token (new format - 40 chars total)
        "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",
        # Classic personal access token (legacy format - 44 chars total)
        "ghp_1234567890abcdef1234567890abcdef12345678",
        # Fine-grained personal access token
        "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        # OAuth token
        "gho_1234567890abcdef1234567890abcdef",
        # Installation token
        "ghs_1234567890abcdef1234567890abcdef",
        # Refresh token
        "ghr_1234567890abcdef1234567890abcdef",
        # Generic long token (for GitHub Enterprise)
        "enterprise_token_1234567890abcdef1234567890"
      ]

      Enum.each(valid_tokens, fn token ->
        credentials = %{token: token}
        assert :ok = GitHub.validate_credentials(credentials), "Token should be valid: #{token}"
      end)
    end

    test "rejects invalid GitHub token formats" do
      invalid_tokens = [
        # Too short
        "ghp_short",
        # Wrong length for ghp_ (neither 40 nor 44 chars)
        # 39 chars
        "ghp_12345678901234567890123456789012345",
        # 46 chars
        "ghp_123456789012345678901234567890123456789012",
        # Empty
        "",
        # Very short
        "abc",
        # Short generic token
        "short_token"
      ]

      Enum.each(invalid_tokens, fn token ->
        credentials = %{token: token}

        assert {:error, %Error{}} = GitHub.validate_credentials(credentials),
               "Token should be invalid: #{token}"
      end)
    end
  end

  describe "integration scenarios" do
    test "complete authentication workflow" do
      # Step 1: Validate credentials
      credentials = %{token: "ghp_1234567890abcdef1234567890abcdef12345678"}
      assert :ok = GitHub.validate_credentials(credentials)

      # Step 2: Authenticate
      expect_post(200, @auth_response, fn url, body, _opts ->
        assert String.contains?(url, "auth/github/login")
        assert body["token"] == "ghp_1234567890abcdef1234567890abcdef12345678"
      end)

      assert {:ok, auth_response} = GitHub.authenticate(credentials)

      # Step 3: Verify response structure
      assert is_binary(auth_response.client_token)
      assert is_binary(auth_response.accessor)
      assert is_list(auth_response.policies)
      assert is_integer(auth_response.lease_duration)
      assert is_boolean(auth_response.renewable)
      assert is_map(auth_response.metadata)
    end

    test "error handling workflow" do
      # Invalid credentials
      invalid_credentials = %{token: "invalid"}

      assert {:error, %Error{type: :invalid_credentials}} =
               GitHub.validate_credentials(invalid_credentials)

      # Valid credentials but auth failure
      valid_credentials = %{token: "ghp_1234567890abcdef1234567890abcdef12345678"}
      assert :ok = GitHub.validate_credentials(valid_credentials)

      expect_post(401, %{"errors" => ["unauthorized"], "status" => 401})

      assert {:error, %Error{type: :authentication_failed}} =
               GitHub.authenticate(valid_credentials)
    end

    test "custom mount path workflow" do
      credentials = %{token: "ghp_1234567890abcdef1234567890abcdef12345678"}
      custom_mount = "company-github"

      expect_post(200, @auth_response, fn url, _body, _opts ->
        assert String.contains?(url, "auth/#{custom_mount}/login")
      end)

      assert {:ok, _auth_response} = GitHub.authenticate(credentials, mount_path: custom_mount)
    end
  end
end
