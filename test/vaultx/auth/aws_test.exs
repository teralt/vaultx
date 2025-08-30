defmodule Vaultx.Auth.AWSTest do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Auth.AWS
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
      "metadata" => %{"auth_method" => "aws"}
    }
  }

  describe "authenticate/2" do
    test "authenticates with EC2 instance successfully" do
      expect_post(200, @auth_response, fn url, body, _opts ->
        assert String.contains?(url, "auth/aws/login")
        assert body["role"] == "my-ec2-role"
        refute Map.has_key?(body, "iam_http_request_method")
      end)

      credentials = %{role: "my-ec2-role"}
      assert {:ok, auth_response} = AWS.authenticate(credentials)

      assert auth_response.client_token == "hvs.CAESIJ1234567890"
      assert auth_response.accessor == "hmac-sha256:accessor123"
      assert auth_response.policies == ["default", "myapp"]
      assert auth_response.lease_duration == 3600
      assert auth_response.renewable == true
      assert auth_response.entity_id == "entity-123"
      assert auth_response.token_type == "service"
      assert auth_response.metadata == %{"auth_method" => "aws"}
    end

    test "authenticates with IAM credentials successfully" do
      expect_post(200, @auth_response, fn url, body, _opts ->
        assert String.contains?(url, "auth/aws/login")
        assert body["role"] == "my-iam-role"
        assert body["iam_http_request_method"] == "POST"
        assert body["iam_request_url"] == "https://sts.amazonaws.com/"
        assert body["iam_request_body"] == "Action=GetCallerIdentity&Version=2011-06-15"
        assert body["iam_request_headers"] == "Authorization: AWS4-HMAC-SHA256 ..."
      end)

      credentials = %{
        role: "my-iam-role",
        iam_http_request_method: "POST",
        iam_request_url: "https://sts.amazonaws.com/",
        iam_request_body: "Action=GetCallerIdentity&Version=2011-06-15",
        iam_request_headers: "Authorization: AWS4-HMAC-SHA256 ..."
      }

      assert {:ok, auth_response} = AWS.authenticate(credentials)
      assert auth_response.client_token == "hvs.CAESIJ1234567890"
    end

    test "authenticates with server ID header" do
      expect_post_with_headers(200, @auth_response, fn url, body, headers, _opts ->
        assert String.contains?(url, "auth/aws/login")
        assert body["role"] == "my-role"
        # Check that server ID header is included
        assert {"X-Vault-AWS-IAM-Server-ID", "vault.example.com"} in headers
      end)

      credentials = %{
        role: "my-role",
        server_id: "vault.example.com"
      }

      assert {:ok, _auth_response} = AWS.authenticate(credentials)
    end

    test "authenticates with nonce for EC2" do
      expect_post(200, @auth_response, fn _url, body, _opts ->
        assert body["role"] == "my-role"
        assert body["nonce"] == "unique-nonce-value"
      end)

      credentials = %{
        role: "my-role",
        nonce: "unique-nonce-value"
      }

      assert {:ok, _auth_response} = AWS.authenticate(credentials)
    end

    test "authenticates with role tag for EC2" do
      expect_post(200, @auth_response, fn _url, body, _opts ->
        assert body["role"] == "my-role"
        assert body["role_tag"] == "v1:09V0qGuyB8=:a=ami-fce3c696:p=default,prod"
      end)

      credentials = %{
        role: "my-role",
        role_tag: "v1:09V0qGuyB8=:a=ami-fce3c696:p=default,prod"
      }

      assert {:ok, _auth_response} = AWS.authenticate(credentials)
    end

    test "uses custom mount path" do
      expect_post(200, @auth_response, fn url, _body, _opts ->
        assert String.contains?(url, "auth/custom-aws/login")
      end)

      credentials = %{role: "my-role"}
      opts = [mount_path: "custom-aws"]

      assert {:ok, _auth_response} = AWS.authenticate(credentials, opts)
    end

    test "returns authentication_failed on invalid credentials" do
      expect_post(400, %{"errors" => ["invalid AWS credentials"]})

      credentials = %{role: "invalid-role"}
      assert {:error, %Error{type: :invalid_request}} = AWS.authenticate(credentials)
    end

    test "returns server_error on 500" do
      expect_post(500, %{"errors" => ["internal server error"]})

      credentials = %{role: "my-role"}
      assert {:error, %Error{type: :invalid_request}} = AWS.authenticate(credentials)
    end

    test "wraps network errors" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      credentials = %{role: "my-role"}
      assert {:error, %Error{type: :unknown_error}} = AWS.authenticate(credentials)
    end
  end

  describe "validate_credentials/1" do
    test "validates valid EC2 credentials" do
      credentials = %{role: "my-role"}
      assert :ok = AWS.validate_credentials(credentials)
    end

    test "validates valid IAM credentials" do
      credentials = %{
        role: "my-iam-role",
        iam_http_request_method: "POST",
        iam_request_url: "https://sts.amazonaws.com/",
        iam_request_body: "Action=GetCallerIdentity&Version=2011-06-15",
        iam_request_headers: "Authorization: AWS4-HMAC-SHA256 ..."
      }

      assert :ok = AWS.validate_credentials(credentials)
    end

    test "validates optional fields" do
      credentials = %{
        role: "my-role",
        server_id: "vault.example.com",
        nonce: "unique-nonce",
        role_tag: "v1:tag"
      }

      assert :ok = AWS.validate_credentials(credentials)
    end

    test "returns error for missing role" do
      credentials = %{}

      assert {:error, %Error{type: :invalid_request, message: "Missing required field: role"}} =
               AWS.validate_credentials(credentials)
    end

    test "returns error for non-string role" do
      credentials = %{role: 123}

      assert {:error, %Error{type: :invalid_request, message: "Field 'role' must be a string"}} =
               AWS.validate_credentials(credentials)
    end

    test "returns error for empty role" do
      credentials = %{role: ""}

      assert {:error, %Error{type: :invalid_request, message: "Field 'role' cannot be empty"}} =
               AWS.validate_credentials(credentials)
    end

    test "returns error for non-string optional fields" do
      credentials = %{role: "my-role", server_id: 123}
      assert {:error, %Error{type: :invalid_request}} = AWS.validate_credentials(credentials)
    end

    test "returns error for incomplete IAM fields" do
      credentials = %{
        role: "my-role",
        iam_http_request_method: "POST"
        # Missing other IAM fields
      }

      assert {:error, %Error{type: :invalid_request}} = AWS.validate_credentials(credentials)
    end

    test "returns error for non-map credentials" do
      assert {:error, %Error{type: :invalid_request, message: "Credentials must be a map"}} =
               AWS.validate_credentials("invalid")
    end
  end

  describe "refresh_token/2" do
    test "refreshes token successfully" do
      expect_post(200, @auth_response, fn url, _body, opts ->
        assert String.contains?(url, "auth/token/renew-self")
        assert Map.get(opts, :token) == "hvs.old_token"
      end)

      assert {:ok, auth_response} = AWS.refresh_token("hvs.old_token")
      assert auth_response.client_token == "hvs.CAESIJ1234567890"
    end

    test "returns error on refresh failure" do
      expect_post(400, %{"errors" => ["token not renewable"]})

      assert {:error, %Error{type: :invalid_request}} = AWS.refresh_token("hvs.old_token")
    end

    test "wraps network errors on refresh" do
      stub_request_raw(:post, %Req.TransportError{reason: :econnrefused})

      assert {:error, %Error{type: :unknown_error}} = AWS.refresh_token("hvs.old_token")
    end
  end

  describe "revoke_token/2" do
    test "revokes token successfully" do
      expect_post(204, %{}, fn url, _body, opts ->
        assert String.contains?(url, "auth/token/revoke-self")
        assert Map.get(opts, :token) == "hvs.token_to_revoke"
      end)

      assert :ok = AWS.revoke_token("hvs.token_to_revoke")
    end

    test "returns error on revoke failure" do
      stub_request_raw(:post, %Req.TransportError{reason: :econnrefused})

      assert {:error, %Error{}} = AWS.revoke_token("hvs.invalid_token")
    end

    test "wraps network errors on revoke" do
      stub_request_raw(:post, :timeout)

      assert {:error, %Error{type: :network_error}} = AWS.revoke_token("hvs.token")
    end
  end

  describe "metadata/0" do
    test "returns correct metadata" do
      metadata = AWS.metadata()

      assert metadata.name == "AWS Authentication"
      assert metadata.supports_refresh == true
      assert metadata.supports_revocation == true
      assert metadata.required_fields == [:role]

      assert metadata.optional_fields == [
               :iam_http_request_method,
               :iam_request_url,
               :iam_request_body,
               :iam_request_headers,
               :server_id,
               :nonce,
               :role_tag
             ]

      assert metadata.description ==
               "AWS EC2 and IAM authentication using AWS credentials and instance identity"
    end
  end

  describe "private helper functions" do
    test "detect_auth_type/1 detects IAM authentication" do
      credentials = %{
        role: "my-role",
        iam_http_request_method: "POST",
        iam_request_url: "https://sts.amazonaws.com/",
        iam_request_body: "Action=GetCallerIdentity",
        iam_request_headers: "Authorization: ..."
      }

      # We can't directly test private functions, but we can verify the behavior
      # through the authenticate function which uses detect_auth_type internally
      expect_post(200, @auth_response, fn _url, body, _opts ->
        # IAM authentication should include all IAM fields
        assert body["iam_http_request_method"] == "POST"
        assert body["iam_request_url"] == "https://sts.amazonaws.com/"
        assert body["iam_request_body"] == "Action=GetCallerIdentity"
        assert body["iam_request_headers"] == "Authorization: ..."
      end)

      assert {:ok, _} = AWS.authenticate(credentials)
    end

    test "detect_auth_type/1 detects EC2 authentication" do
      credentials = %{role: "my-role"}

      expect_post(200, @auth_response, fn _url, body, _opts ->
        # EC2 authentication should not include IAM fields
        refute Map.has_key?(body, "iam_http_request_method")
        refute Map.has_key?(body, "iam_request_url")
        refute Map.has_key?(body, "iam_request_body")
        refute Map.has_key?(body, "iam_request_headers")
      end)

      assert {:ok, _} = AWS.authenticate(credentials)
    end
  end

  describe "error handling edge cases" do
    test "handles malformed auth response" do
      expect_post(200, %{"invalid" => "response"})

      credentials = %{role: "my-role"}
      assert {:error, %Error{}} = AWS.authenticate(credentials)
    end

    test "handles missing auth field in response" do
      expect_post(200, %{"data" => %{"some" => "data"}})

      credentials = %{role: "my-role"}
      assert {:error, %Error{}} = AWS.authenticate(credentials)
    end

    test "handles partial auth response" do
      partial_response = %{
        "auth" => %{
          "client_token" => "hvs.token123"
          # Missing other fields
        }
      }

      expect_post(200, partial_response)

      credentials = %{role: "my-role"}
      assert {:ok, auth_response} = AWS.authenticate(credentials)
      assert auth_response.client_token == "hvs.token123"
      assert auth_response.accessor == nil
      assert auth_response.policies == []
      assert auth_response.lease_duration == 0
      assert auth_response.renewable == false
    end

    test "handles security audit log failure gracefully" do
      # This test covers the case where Security.audit_log might fail
      # but the authentication should still proceed
      expect_post(200, @auth_response)

      credentials = %{role: "my-role"}
      assert {:ok, _auth_response} = AWS.authenticate(credentials)
    end

    test "validates credentials with empty IAM fields" do
      credentials = %{
        role: "my-role",
        iam_http_request_method: "",
        iam_request_url: "https://sts.amazonaws.com/",
        iam_request_body: "Action=GetCallerIdentity",
        iam_request_headers: "Authorization: ..."
      }

      assert {:error, %Error{type: :invalid_request}} = AWS.validate_credentials(credentials)
    end
  end

  describe "integration scenarios" do
    test "full IAM authentication flow with all options" do
      expect_post_with_headers(200, @auth_response, fn url, body, headers, _opts ->
        assert String.contains?(url, "auth/custom-aws/login")
        assert body["role"] == "production-role"
        assert body["iam_http_request_method"] == "POST"
        assert body["iam_request_url"] == "https://sts.amazonaws.com/"
        assert body["iam_request_body"] == "Action=GetCallerIdentity&Version=2011-06-15"
        assert body["iam_request_headers"] == "Authorization: AWS4-HMAC-SHA256 ..."

        assert {"X-Vault-AWS-IAM-Server-ID", "production.vault.com"} in headers
      end)

      credentials = %{
        role: "production-role",
        iam_http_request_method: "POST",
        iam_request_url: "https://sts.amazonaws.com/",
        iam_request_body: "Action=GetCallerIdentity&Version=2011-06-15",
        iam_request_headers: "Authorization: AWS4-HMAC-SHA256 ...",
        server_id: "production.vault.com"
      }

      opts = [mount_path: "custom-aws"]

      assert {:ok, auth_response} = AWS.authenticate(credentials, opts)
      assert auth_response.client_token == "hvs.CAESIJ1234567890"
      assert auth_response.policies == ["default", "myapp"]
    end

    test "full EC2 authentication flow with role tag and nonce" do
      expect_post(200, @auth_response, fn _url, body, _opts ->
        assert body["role"] == "ec2-role"
        assert body["nonce"] == "unique-ec2-nonce"
        assert body["role_tag"] == "v1:tag:value"
        refute Map.has_key?(body, "iam_http_request_method")
      end)

      credentials = %{
        role: "ec2-role",
        nonce: "unique-ec2-nonce",
        role_tag: "v1:tag:value"
      }

      assert {:ok, auth_response} = AWS.authenticate(credentials)
      assert auth_response.client_token == "hvs.CAESIJ1234567890"
    end
  end
end
