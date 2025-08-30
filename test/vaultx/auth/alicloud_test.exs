defmodule Vaultx.Auth.AliCloudTest do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Auth.AliCloud
  alias Vaultx.Base.{Error, JSON}

  # Sample auth response from Vault
  @auth_response %{
    "auth" => %{
      "client_token" => "hvs.CAESIJ1234567890",
      "accessor" => "hmac-sha256:accessor123",
      "policies" => ["default", "dev"],
      "lease_duration" => 7200,
      "renewable" => true,
      "entity_id" => "entity-456",
      "token_type" => "service",
      "metadata" => %{
        "account_id" => "5138828231865461",
        "user_id" => "216959339000654321",
        "role_id" => "4657-abcd",
        "arn" => "acs:ram::5138828231865461:assumed-role/dev-role/vm-ram-i-rj978rorvlg76urhqh7q",
        "identity_type" => "assumed-role",
        "principal_id" => "vm-ram-i-rj978rorvlg76urhqh7q",
        "request_id" => "D6E46F10-F26C-4AA0-BB69-FE2743D9AE62",
        "role_name" => "dev-role"
      }
    }
  }

  # Valid base64 encoded test data
  @valid_identity_url Base.encode64(
                        "https://sts.cn-hangzhou.aliyuncs.com/?Action=GetCallerIdentity&Version=2015-04-01"
                      )
  @valid_identity_headers Base.encode64(
                            JSON.encode!(%{
                              "Authorization" => "acs AK123:signature123",
                              "Content-Type" => "application/x-www-form-urlencoded",
                              "Host" => "sts.cn-hangzhou.aliyuncs.com",
                              "Date" => "Wed, 26 Sep 2023 14:30:00 GMT"
                            })
                          )

  describe "authenticate/2" do
    test "authenticates with valid AliCloud credentials successfully" do
      expect_post(200, @auth_response, fn url, body, _opts ->
        assert String.contains?(url, "auth/alicloud/login")
        assert body["role"] == "dev-role"
        assert body["identity_request_url"] == @valid_identity_url
        assert body["identity_request_headers"] == @valid_identity_headers
      end)

      credentials = %{
        role: "dev-role",
        identity_request_url: @valid_identity_url,
        identity_request_headers: @valid_identity_headers
      }

      assert {:ok, auth_response} = AliCloud.authenticate(credentials)

      assert auth_response.client_token == "hvs.CAESIJ1234567890"
      assert auth_response.accessor == "hmac-sha256:accessor123"
      assert auth_response.policies == ["default", "dev"]
      assert auth_response.lease_duration == 7200
      assert auth_response.renewable == true
      assert auth_response.entity_id == "entity-456"
      assert auth_response.token_type == "service"
      assert auth_response.metadata["account_id"] == "5138828231865461"

      assert auth_response.metadata["arn"] ==
               "acs:ram::5138828231865461:assumed-role/dev-role/vm-ram-i-rj978rorvlg76urhqh7q"
    end

    test "authenticates with custom mount path" do
      expect_post(200, @auth_response, fn url, body, _opts ->
        assert String.contains?(url, "auth/custom-alicloud/login")
        assert body["role"] == "prod-role"
      end)

      credentials = %{
        role: "prod-role",
        identity_request_url: @valid_identity_url,
        identity_request_headers: @valid_identity_headers
      }

      opts = [mount_path: "custom-alicloud"]
      assert {:ok, _auth_response} = AliCloud.authenticate(credentials, opts)
    end

    test "handles authentication failure" do
      error_response = %{
        "errors" => ["permission denied"],
        "status" => 403
      }

      expect_post(403, error_response)

      credentials = %{
        role: "invalid-role",
        identity_request_url: @valid_identity_url,
        identity_request_headers: @valid_identity_headers
      }

      assert {:error, %Error{} = error} = AliCloud.authenticate(credentials)
      assert error.type == :authorization_denied
    end

    test "handles network errors" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      credentials = %{
        role: "dev-role",
        identity_request_url: @valid_identity_url,
        identity_request_headers: @valid_identity_headers
      }

      assert {:error, %Error{} = error} = AliCloud.authenticate(credentials)
      assert error.type == :unknown_error
    end

    test "handles server errors" do
      error_response = %{
        "errors" => ["internal server error"],
        "status" => 500
      }

      expect_post(500, error_response)

      credentials = %{
        role: "dev-role",
        identity_request_url: @valid_identity_url,
        identity_request_headers: @valid_identity_headers
      }

      assert {:error, %Error{} = error} = AliCloud.authenticate(credentials)
      assert error.type == :server_error
    end

    test "passes custom options to HTTP request" do
      expect_post(200, @auth_response, fn _url, _body, opts ->
        assert opts[:timeout] == 30_000
        assert opts[:retry_attempts] == 3
      end)

      credentials = %{
        role: "dev-role",
        identity_request_url: @valid_identity_url,
        identity_request_headers: @valid_identity_headers
      }

      opts = [timeout: 30_000, retry_attempts: 3]
      assert {:ok, _auth_response} = AliCloud.authenticate(credentials, opts)
    end
  end

  describe "validate_credentials/1" do
    test "validates complete valid credentials" do
      credentials = %{
        role: "dev-role",
        identity_request_url: @valid_identity_url,
        identity_request_headers: @valid_identity_headers
      }

      assert :ok = AliCloud.validate_credentials(credentials)
    end

    test "rejects missing role" do
      credentials = %{
        identity_request_url: @valid_identity_url,
        identity_request_headers: @valid_identity_headers
      }

      assert {:error, %Error{} = error} = AliCloud.validate_credentials(credentials)
      assert error.type == :invalid_credentials
      assert String.contains?(error.message, "Role is required")
    end

    test "rejects empty role" do
      credentials = %{
        role: "",
        identity_request_url: @valid_identity_url,
        identity_request_headers: @valid_identity_headers
      }

      assert {:error, %Error{} = error} = AliCloud.validate_credentials(credentials)
      assert error.type == :invalid_credentials
      assert String.contains?(error.message, "Role is required")
    end

    test "rejects missing identity_request_url" do
      credentials = %{
        role: "dev-role",
        identity_request_headers: @valid_identity_headers
      }

      assert {:error, %Error{} = error} = AliCloud.validate_credentials(credentials)
      assert error.type == :invalid_credentials
      assert String.contains?(error.message, "Identity request URL is required")
    end

    test "rejects empty identity_request_url" do
      credentials = %{
        role: "dev-role",
        identity_request_url: "",
        identity_request_headers: @valid_identity_headers
      }

      assert {:error, %Error{} = error} = AliCloud.validate_credentials(credentials)
      assert error.type == :invalid_credentials
      assert String.contains?(error.message, "Identity request URL is required")
    end

    test "rejects missing identity_request_headers" do
      credentials = %{
        role: "dev-role",
        identity_request_url: @valid_identity_url
      }

      assert {:error, %Error{} = error} = AliCloud.validate_credentials(credentials)
      assert error.type == :invalid_credentials
      assert String.contains?(error.message, "Identity request headers are required")
    end

    test "rejects empty identity_request_headers" do
      credentials = %{
        role: "dev-role",
        identity_request_url: @valid_identity_url,
        identity_request_headers: ""
      }

      assert {:error, %Error{} = error} = AliCloud.validate_credentials(credentials)
      assert error.type == :invalid_credentials
      assert String.contains?(error.message, "Identity request headers are required")
    end

    test "rejects invalid base64 identity_request_url" do
      credentials = %{
        role: "dev-role",
        identity_request_url: "invalid-base64!",
        identity_request_headers: @valid_identity_headers
      }

      assert {:error, %Error{} = error} = AliCloud.validate_credentials(credentials)
      assert error.type == :invalid_credentials
      assert String.contains?(error.message, "Identity request URL must be valid base64")
    end

    test "rejects invalid base64 identity_request_headers" do
      credentials = %{
        role: "dev-role",
        identity_request_url: @valid_identity_url,
        identity_request_headers: "invalid-base64!"
      }

      assert {:error, %Error{} = error} = AliCloud.validate_credentials(credentials)
      assert error.type == :invalid_credentials
      assert String.contains?(error.message, "Identity request headers must be valid base64")
    end

    test "rejects non-map credentials" do
      assert {:error, %Error{} = error} = AliCloud.validate_credentials("invalid")
      assert error.type == :invalid_credentials
      assert String.contains?(error.message, "Credentials must be a map")
    end

    test "rejects non-string field values" do
      credentials = %{
        role: 123,
        identity_request_url: @valid_identity_url,
        identity_request_headers: @valid_identity_headers
      }

      assert {:error, %Error{} = error} = AliCloud.validate_credentials(credentials)
      assert error.type == :invalid_credentials
      assert String.contains?(error.message, "Role is required")
    end
  end

  describe "refresh_token/2" do
    test "returns not supported error" do
      assert {:error, %Error{} = error} = AliCloud.refresh_token("token", [])
      assert error.type == :not_supported
      assert String.contains?(error.message, "does not support token refresh")
    end
  end

  describe "revoke_token/2" do
    test "returns not supported error" do
      assert {:error, %Error{} = error} = AliCloud.revoke_token("token", [])
      assert error.type == :not_supported
      assert String.contains?(error.message, "does not support token revocation")
    end
  end

  describe "metadata/0" do
    test "returns correct metadata" do
      metadata = AliCloud.metadata()

      assert metadata.name == "AliCloud Authentication"
      assert metadata.supports_refresh == false
      assert metadata.supports_revocation == false
      assert metadata.required_fields == [:role, :identity_request_url, :identity_request_headers]
      assert metadata.optional_fields == []

      assert metadata.description ==
               "Authenticate using Alibaba Cloud RAM roles and STS GetCallerIdentity requests"
    end
  end

  describe "base64 validation" do
    test "validates various base64 encoded data" do
      valid_base64_values = [
        Base.encode64("simple string"),
        Base.encode64("https://example.com/path?param=value"),
        Base.encode64(JSON.encode!(%{"key" => "value", "nested" => %{"data" => 123}})),
        Base.encode64("multi\nline\nstring"),
        Base.encode64("special chars: !@#$%^&*()")
        # Note: empty string base64 would be "", which fails required field validation
      ]

      Enum.each(valid_base64_values, fn base64_value ->
        credentials = %{
          role: "test-role",
          identity_request_url: base64_value,
          identity_request_headers: base64_value
        }

        assert :ok = AliCloud.validate_credentials(credentials),
               "Should accept valid base64: #{String.slice(base64_value, 0, 20)}..."
      end)
    end

    test "rejects invalid base64 data" do
      invalid_base64_values = [
        "not base64 at all!",
        "invalid==base64",
        "spaces in base64",
        "123!@#",
        "almost_base64_but_not_quite"
      ]

      Enum.each(invalid_base64_values, fn invalid_value ->
        credentials = %{
          role: "test-role",
          identity_request_url: invalid_value,
          identity_request_headers: @valid_identity_headers
        }

        assert {:error, %Error{}} = AliCloud.validate_credentials(credentials),
               "Should reject invalid base64: #{invalid_value}"
      end)
    end
  end

  describe "integration scenarios" do
    test "complete authentication workflow" do
      # Step 1: Validate credentials
      credentials = %{
        role: "integration-role",
        identity_request_url: @valid_identity_url,
        identity_request_headers: @valid_identity_headers
      }

      assert :ok = AliCloud.validate_credentials(credentials)

      # Step 2: Authenticate
      expect_post(200, @auth_response, fn url, body, _opts ->
        assert String.contains?(url, "auth/alicloud/login")
        assert body["role"] == "integration-role"
        assert body["identity_request_url"] == @valid_identity_url
        assert body["identity_request_headers"] == @valid_identity_headers
      end)

      assert {:ok, auth_response} = AliCloud.authenticate(credentials)

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
      invalid_credentials = %{
        role: "test",
        identity_request_url: "invalid",
        identity_request_headers: "invalid"
      }

      assert {:error, %Error{type: :invalid_credentials}} =
               AliCloud.validate_credentials(invalid_credentials)

      # Valid credentials but auth failure
      valid_credentials = %{
        role: "test-role",
        identity_request_url: @valid_identity_url,
        identity_request_headers: @valid_identity_headers
      }

      assert :ok = AliCloud.validate_credentials(valid_credentials)

      expect_post(401, %{"errors" => ["unauthorized"], "status" => 401})

      assert {:error, %Error{type: :authentication_failed}} =
               AliCloud.authenticate(valid_credentials)
    end

    test "custom mount path workflow" do
      credentials = %{
        role: "custom-role",
        identity_request_url: @valid_identity_url,
        identity_request_headers: @valid_identity_headers
      }

      custom_mount = "company-alicloud"

      expect_post(200, @auth_response, fn url, _body, _opts ->
        assert String.contains?(url, "auth/#{custom_mount}/login")
      end)

      assert {:ok, _auth_response} = AliCloud.authenticate(credentials, mount_path: custom_mount)
    end
  end
end
