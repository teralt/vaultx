defmodule Vaultx.Auth.TokenTest do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Auth.Token
  alias Vaultx.Base.Error

  # Sample token info response from Vault
  @token_info_response %{
    "data" => %{
      "accessor" => "hmac-sha256:accessor123",
      "creation_time" => 1_640_995_200,
      "creation_ttl" => 3600,
      "display_name" => "token",
      "entity_id" => "entity-123",
      "expire_time" => "2025-01-01T12:00:00Z",
      "explicit_max_ttl" => 0,
      "id" => "hvs.CAESIJ1234567890",
      "identity_policies" => ["identity-policy"],
      "issue_time" => "2025-01-01T11:00:00Z",
      "meta" => %{"user" => "testuser"},
      "num_uses" => 0,
      "orphan" => false,
      "path" => "auth/token/create",
      "policies" => ["default", "myapp"],
      "renewable" => true,
      "ttl" => 2400,
      "type" => "service"
    }
  }

  # Sample auth response for token creation/renewal
  @auth_response %{
    "auth" => %{
      "client_token" => "hvs.CAESIJ1234567890",
      "accessor" => "hmac-sha256:accessor123",
      "policies" => ["default", "myapp"],
      "token_policies" => ["default", "myapp"],
      "metadata" => %{"user" => "testuser"},
      "lease_duration" => 3600,
      "renewable" => true,
      "entity_id" => "entity-123",
      "token_type" => "service",
      "orphan" => false,
      "num_uses" => 0
    }
  }

  describe "authenticate/2" do
    test "looks up current token when no token provided" do
      expect_get(200, @token_info_response, fn url, _body, _opts ->
        assert String.contains?(url, "auth/token/lookup-self")
      end)

      credentials = %{}
      assert {:ok, token_info} = Token.authenticate(credentials)

      assert token_info.accessor == "hmac-sha256:accessor123"
      assert token_info.id == "hvs.CAESIJ1234567890"
      assert token_info.policies == ["default", "myapp"]
      assert token_info.renewable == true
      assert token_info.ttl == 2400
    end

    test "looks up specific token when token provided" do
      expect_post(200, @token_info_response, fn url, body, _opts ->
        assert String.contains?(url, "auth/token/lookup")
        assert body["token"] == "hvs.CAESIJ1234567890"
      end)

      credentials = %{token: "hvs.CAESIJ1234567890"}
      assert {:ok, token_info} = Token.authenticate(credentials)

      assert token_info.accessor == "hmac-sha256:accessor123"
      assert token_info.id == "hvs.CAESIJ1234567890"
      assert token_info.policies == ["default", "myapp"]
    end

    test "authenticates with custom mount path" do
      expect_get(200, @token_info_response, fn url, _body, _opts ->
        assert String.contains?(url, "auth/custom-token/lookup-self")
      end)

      credentials = %{}
      opts = [mount_path: "custom-token"]
      assert {:ok, _token_info} = Token.authenticate(credentials, opts)
    end

    test "handles authentication failure" do
      expect_get(403, %{"errors" => ["permission denied"]})

      credentials = %{}
      assert {:error, %Error{} = error} = Token.authenticate(credentials)
      assert error.type == :invalid_request
    end

    test "handles network errors" do
      stub_request_raw(:get, %Req.TransportError{reason: :timeout})

      credentials = %{}
      assert {:error, %Error{} = error} = Token.authenticate(credentials)
      assert error.type == :unknown_error
    end
  end

  describe "lookup_self/1" do
    test "looks up current token successfully" do
      expect_get(200, @token_info_response, fn url, _body, _opts ->
        assert String.contains?(url, "auth/token/lookup-self")
      end)

      assert {:ok, token_info} = Token.lookup_self()

      assert token_info.accessor == "hmac-sha256:accessor123"
      assert token_info.creation_time == 1_640_995_200
      assert token_info.creation_ttl == 3600
      assert token_info.display_name == "token"
      assert token_info.entity_id == "entity-123"
      assert token_info.expire_time == "2025-01-01T12:00:00Z"
      assert token_info.explicit_max_ttl == 0
      assert token_info.id == "hvs.CAESIJ1234567890"
      assert token_info.identity_policies == ["identity-policy"]
      assert token_info.issue_time == "2025-01-01T11:00:00Z"
      assert token_info.meta == %{"user" => "testuser"}
      assert token_info.num_uses == 0
      assert token_info.orphan == false
      assert token_info.path == "auth/token/create"
      assert token_info.policies == ["default", "myapp"]
      assert token_info.renewable == true
      assert token_info.ttl == 2400
      assert token_info.type == "service"
    end

    test "looks up with custom mount path" do
      expect_get(200, @token_info_response, fn url, _body, _opts ->
        assert String.contains?(url, "auth/custom-token/lookup-self")
      end)

      opts = [mount_path: "custom-token"]
      assert {:ok, _token_info} = Token.lookup_self(opts)
    end

    test "handles lookup failure" do
      expect_get(403, %{"errors" => ["permission denied"]})

      assert {:error, %Error{} = error} = Token.lookup_self()
      assert error.type == :invalid_request
    end

    test "handles network errors" do
      stub_request_raw(:get, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{} = error} = Token.lookup_self()
      assert error.type == :unknown_error
    end
  end

  describe "lookup_token/2" do
    test "looks up specific token successfully" do
      expect_post(200, @token_info_response, fn url, body, _opts ->
        assert String.contains?(url, "auth/token/lookup")
        assert body["token"] == "hvs.CAESIJ1234567890"
      end)

      assert {:ok, token_info} = Token.lookup_token("hvs.CAESIJ1234567890")
      assert token_info.id == "hvs.CAESIJ1234567890"
      assert token_info.policies == ["default", "myapp"]
    end

    test "looks up with custom mount path" do
      expect_post(200, @token_info_response, fn url, body, _opts ->
        assert String.contains?(url, "auth/custom-token/lookup")
        assert body["token"] == "hvs.CAESIJ1234567890"
      end)

      opts = [mount_path: "custom-token"]
      assert {:ok, _token_info} = Token.lookup_token("hvs.CAESIJ1234567890", opts)
    end

    test "handles invalid token format" do
      assert {:error, %Error{} = error} = Token.lookup_token("")
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Invalid token format")
    end

    test "handles non-string token" do
      assert {:error, %Error{} = error} = Token.lookup_token(123)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Invalid token format")
    end

    test "handles lookup failure" do
      expect_post(404, %{"errors" => ["token not found"]})

      assert {:error, %Error{} = error} = Token.lookup_token("hvs.CAESIJ1234567890")
      assert error.type == :invalid_request
    end

    test "handles network errors" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{} = error} = Token.lookup_token("hvs.CAESIJ1234567890")
      assert error.type == :unknown_error
    end
  end

  describe "create_token/2" do
    test "creates token with basic parameters" do
      expect_post(200, @auth_response, fn url, body, _opts ->
        assert String.contains?(url, "auth/token/create")
        assert body["policies"] == ["default", "myapp"]
        assert body["ttl"] == "1h"
        assert body["renewable"] == true
      end)

      params = %{
        policies: ["default", "myapp"],
        ttl: "1h",
        renewable: true
      }

      assert {:ok, auth_response} = Token.create_token(params)

      assert auth_response.client_token == "hvs.CAESIJ1234567890"
      assert auth_response.accessor == "hmac-sha256:accessor123"
      assert auth_response.policies == ["default", "myapp"]
      assert auth_response.lease_duration == 3600
      assert auth_response.renewable == true
    end

    test "creates token with role" do
      expect_post(200, @auth_response, fn url, body, _opts ->
        assert String.contains?(url, "auth/token/create/myrole")
        assert body["policies"] == ["default", "myapp"]
      end)

      params = %{
        role_name: "myrole",
        policies: ["default", "myapp"]
      }

      assert {:ok, _auth_response} = Token.create_token(params)
    end

    test "creates orphan token" do
      expect_post(200, @auth_response, fn url, body, _opts ->
        assert String.contains?(url, "auth/token/create-orphan")
        assert body["policies"] == ["default", "myapp"]
      end)

      params = %{
        no_parent: true,
        policies: ["default", "myapp"]
      }

      assert {:ok, _auth_response} = Token.create_token(params)
    end

    test "creates token with all parameters" do
      expect_post(200, @auth_response, fn url, body, _opts ->
        assert String.contains?(url, "auth/token/create")
        assert body["policies"] == ["default", "myapp"]
        assert body["ttl"] == "1h"
        assert body["renewable"] == true
        assert body["meta"] == %{"user" => "testuser"}
        assert body["no_default_policy"] == true
        assert body["display_name"] == "test-token"
        assert body["num_uses"] == 5
        assert body["period"] == "24h"
        assert body["explicit_max_ttl"] == "48h"
        assert body["type"] == "batch"
      end)

      params = %{
        policies: ["default", "myapp"],
        ttl: "1h",
        renewable: true,
        meta: %{"user" => "testuser"},
        no_default_policy: true,
        display_name: "test-token",
        num_uses: 5,
        period: "24h",
        explicit_max_ttl: "48h",
        type: "batch"
      }

      assert {:ok, _auth_response} = Token.create_token(params)
    end

    test "creates token with custom mount path" do
      expect_post(200, @auth_response, fn url, _body, _opts ->
        assert String.contains?(url, "auth/custom-token/create")
      end)

      params = %{policies: ["default"]}
      opts = [mount_path: "custom-token"]
      assert {:ok, _auth_response} = Token.create_token(params, opts)
    end

    test "handles invalid parameters" do
      assert {:error, %Error{} = error} = Token.create_token("invalid")
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Parameters must be a map")
    end

    test "handles creation failure" do
      expect_post(403, %{"errors" => ["insufficient permissions"]})

      params = %{policies: ["admin"]}
      assert {:error, %Error{} = error} = Token.create_token(params)
      assert error.type == :invalid_request
    end

    test "handles network errors" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      params = %{policies: ["default"]}
      assert {:error, %Error{} = error} = Token.create_token(params)
      assert error.type == :unknown_error
    end
  end

  describe "refresh_token/2" do
    test "delegates to renew_token" do
      expect_post(200, @auth_response, fn url, body, _opts ->
        assert String.contains?(url, "auth/token/renew")
        assert body["token"] == "hvs.CAESIJ1234567890"
      end)

      assert {:ok, _auth_response} = Token.refresh_token("hvs.CAESIJ1234567890")
    end
  end

  describe "renew_token/2" do
    test "renews current token (self)" do
      expect_post(200, @auth_response, fn url, body, _opts ->
        assert String.contains?(url, "auth/token/renew-self")
        assert body == %{}
      end)

      assert {:ok, auth_response} = Token.renew_token(nil)

      assert auth_response.client_token == "hvs.CAESIJ1234567890"
      assert auth_response.lease_duration == 3600
      assert auth_response.renewable == true
    end

    test "renews current token with increment" do
      expect_post(200, @auth_response, fn url, body, _opts ->
        assert String.contains?(url, "auth/token/renew-self")
        assert body["increment"] == "30m"
      end)

      opts = [increment: "30m"]
      assert {:ok, _auth_response} = Token.renew_token(nil, opts)
    end

    test "renews specific token" do
      expect_post(200, @auth_response, fn url, body, _opts ->
        assert String.contains?(url, "auth/token/renew")
        assert body["token"] == "hvs.CAESIJ1234567890"
      end)

      assert {:ok, _auth_response} = Token.renew_token("hvs.CAESIJ1234567890")
    end

    test "renews specific token with increment" do
      expect_post(200, @auth_response, fn url, body, _opts ->
        assert String.contains?(url, "auth/token/renew")
        assert body["token"] == "hvs.CAESIJ1234567890"
        assert body["increment"] == "1h"
      end)

      opts = [increment: "1h"]
      assert {:ok, _auth_response} = Token.renew_token("hvs.CAESIJ1234567890", opts)
    end

    test "renews with custom mount path" do
      expect_post(200, @auth_response, fn url, body, _opts ->
        assert String.contains?(url, "auth/custom-token/renew-self")
        assert body == %{}
      end)

      opts = [mount_path: "custom-token"]
      assert {:ok, _auth_response} = Token.renew_token(nil, opts)
    end

    test "handles renewal failure" do
      expect_post(403, %{"errors" => ["token not renewable"]})

      assert {:error, %Error{} = error} = Token.renew_token("hvs.CAESIJ1234567890")
      assert error.type == :invalid_request
    end

    test "handles network errors" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{} = error} = Token.renew_token("hvs.CAESIJ1234567890")
      assert error.type == :unknown_error
    end
  end

  describe "revoke_token/2" do
    test "revokes current token (self)" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "auth/token/revoke-self")
        assert body == %{}
      end)

      assert :ok = Token.revoke_token(nil)
    end

    test "revokes specific token" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "auth/token/revoke")
        assert body["token"] == "hvs.CAESIJ1234567890"
      end)

      assert :ok = Token.revoke_token("hvs.CAESIJ1234567890")
    end

    test "revokes with custom mount path" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "auth/custom-token/revoke-self")
        assert body == %{}
      end)

      opts = [mount_path: "custom-token"]
      assert :ok = Token.revoke_token(nil, opts)
    end

    test "handles invalid token format" do
      assert {:error, %Error{} = error} = Token.revoke_token("")
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Invalid token format")
    end

    test "handles non-string token" do
      assert {:error, %Error{} = error} = Token.revoke_token(123)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Invalid token format")
    end

    test "handles revocation failure" do
      stub_request(:post, :invalid_request, "insufficient permissions")

      assert {:error, %Error{} = error} = Token.revoke_token("hvs.CAESIJ1234567890")
      assert error.type == :invalid_request
    end

    test "handles network errors" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{} = error} = Token.revoke_token("hvs.CAESIJ1234567890")
      assert error.type == :unknown_error
    end
  end

  describe "validate_credentials/1" do
    test "accepts empty credentials" do
      assert :ok = Token.validate_credentials(%{})
    end

    test "accepts valid token" do
      credentials = %{token: "hvs.CAESIJ1234567890"}
      assert :ok = Token.validate_credentials(credentials)
    end

    test "rejects non-string token" do
      credentials = %{token: 123}
      assert {:error, %Error{} = error} = Token.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Token must be a string")
    end

    test "rejects empty string token" do
      credentials = %{token: ""}
      assert {:error, %Error{} = error} = Token.validate_credentials(credentials)
      assert error.type == :invalid_request
      assert String.contains?(error.message, "Invalid token format")
    end
  end

  describe "metadata/0" do
    test "returns correct metadata" do
      metadata = Token.metadata()

      assert metadata.name == "token"
      assert metadata.supports_refresh == true
      assert metadata.supports_revocation == true
      assert metadata.required_fields == []
      assert metadata.optional_fields == [:token]
      assert is_binary(metadata.description)
      assert String.contains?(metadata.description, "Token authentication")
    end
  end

  # Test edge cases and error conditions
  describe "edge cases" do
    test "handles malformed response data" do
      malformed_response = %{"data" => %{}}
      expect_get(200, malformed_response, fn _url, _body, _opts -> :ok end)

      assert {:ok, token_info} = Token.lookup_self()
      # Should handle missing fields gracefully
      assert is_nil(token_info.accessor)
      assert is_nil(token_info.id)
    end

    test "handles missing auth data in create response" do
      malformed_response = %{"data" => %{"some" => "data"}}
      expect_post(200, malformed_response)

      params = %{policies: ["default"]}
      assert {:error, %Error{}} = Token.create_token(params)
    end

    test "handles missing data field in lookup response" do
      malformed_response = %{"auth" => %{"client_token" => "test"}}
      expect_get(200, malformed_response)

      assert {:error, %Error{}} = Token.lookup_self()
    end

    test "filters nil values from create request body" do
      expect_post(200, @auth_response, fn _url, body, _opts ->
        # Should not contain nil values
        refute Map.has_key?(body, "meta")
        refute Map.has_key?(body, "display_name")
        assert body["policies"] == ["default"]
      end)

      params = %{
        policies: ["default"],
        meta: nil,
        display_name: nil
      }

      assert {:ok, _auth_response} = Token.create_token(params)
    end
  end
end
