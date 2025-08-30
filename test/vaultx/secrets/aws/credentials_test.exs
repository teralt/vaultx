defmodule Vaultx.Secrets.AWS.CredentialsTest do
  use ExUnit.Case, async: true

  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Secrets.AWS.Credentials

  describe "generate/2" do
    test "generates IAM user credentials successfully" do
      response_data = %{
        "access_key" => "AKIA123456789",
        "secret_key" => "secret123",
        "arn" => "arn:aws:iam::123456789012:user/vault-user-123"
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/aws/creds/my-role")
      end)

      assert {:ok, creds} = Credentials.generate("my-role")
      assert creds.access_key == "AKIA123456789"
      assert creds.secret_key == "secret123"
      assert creds.session_token == nil
      assert creds.arn == "arn:aws:iam::123456789012:user/vault-user-123"
      assert creds.expiration == nil
    end

    test "generates STS credentials successfully" do
      response_data = %{
        "access_key" => "ASIA123456789",
        "secret_key" => "secret123",
        "session_token" => "token123",
        "arn" => "arn:aws:sts::123456789012:assumed-role/MyRole/vault-session",
        "expiration" => "2025-08-30T23:59:59Z"
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/aws/sts/assume-role")
      end)

      assert {:ok, creds} = Credentials.generate("assume-role", credential_type: "assumed_role")
      assert creds.access_key == "ASIA123456789"
      assert creds.secret_key == "secret123"
      assert creds.session_token == "token123"
      assert creds.arn == "arn:aws:sts::123456789012:assumed-role/MyRole/vault-session"
      assert creds.expiration == "2025-08-30T23:59:59Z"
    end

    test "generates credentials with custom TTL" do
      response_data = %{
        "access_key" => "ASIA123456789",
        "secret_key" => "secret123",
        "session_token" => "token123",
        "expiration" => "2025-08-30T23:59:59Z"
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/aws/sts/my-role?ttl=2h")
      end)

      assert {:ok, creds} =
               Credentials.generate("my-role", ttl: "2h", credential_type: "assumed_role")

      assert creds.access_key == "ASIA123456789"
      assert creds.expiration == "2025-08-30T23:59:59Z"
    end

    test "generates credentials with role ARN and session name" do
      response_data = %{
        "access_key" => "ASIA123456789",
        "secret_key" => "secret123",
        "session_token" => "token123"
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        expected_arn = URI.encode_www_form("arn:aws:iam::123456789012:role/MyRole")
        expected_session = URI.encode_www_form("my-session")

        assert String.ends_with?(
                 url,
                 "/v1/aws/sts/my-role?role_arn=#{expected_arn}&role_session_name=#{expected_session}"
               )
      end)

      opts = [
        credential_type: "assumed_role",
        role_arn: "arn:aws:iam::123456789012:role/MyRole",
        role_session_name: "my-session"
      ]

      assert {:ok, creds} = Credentials.generate("my-role", opts)
      assert creds.access_key == "ASIA123456789"
    end

    test "handles credential generation errors" do
      expect_get(500, %{
        "errors" => ["role 'nonexistent' not found"]
      })

      assert {:error, error} = Credentials.generate("nonexistent")
      assert error.type == :server_error
    end

    test "handles HTTP errors" do
      stub_request_raw(:get, :timeout)

      assert {:error, error} = Credentials.generate("my-role")
      assert error.type == :http_error
    end
  end

  describe "get_static/2" do
    test "retrieves static credentials successfully" do
      response_data = %{
        "access_key" => "AKIA123456789",
        "secret_key" => "secret123",
        "expiration" => "2025-08-30T23:59:59Z"
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/aws/static-creds/my-static-role")
      end)

      assert {:ok, creds} = Credentials.get_static("my-static-role")
      assert creds.access_key == "AKIA123456789"
      assert creds.secret_key == "secret123"
      assert creds.expiration == "2025-08-30T23:59:59Z"
    end

    test "handles static credential retrieval errors" do
      expect_get(500, %{
        "errors" => ["static role 'nonexistent' not found"]
      })

      assert {:error, error} = Credentials.get_static("nonexistent")
      assert error.type == :server_error
    end

    test "handles HTTP errors during static credential retrieval" do
      stub_request_raw(:get, :timeout)

      assert {:error, error} = Credentials.get_static("my-role")
      assert error.type == :http_error
    end

    test "uses custom mount path" do
      response_data = %{
        "access_key" => "AKIA123456789",
        "secret_key" => "secret123"
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/custom-aws/static-creds/my-role")
      end)

      assert {:ok, _creds} = Credentials.get_static("my-role", mount_path: "custom-aws")
    end
  end

  describe "private functions" do
    test "detect_credential_type/1 identifies IAM user credentials" do
      creds = %{session_token: nil}
      assert Credentials.detect_credential_type(creds) == "iam_user"
    end

    test "detect_credential_type/1 identifies STS credentials" do
      creds = %{session_token: "token123"}
      assert Credentials.detect_credential_type(creds) == "sts_credential"
    end

    test "detect_credential_type/1 handles unknown format" do
      creds = %{}
      assert Credentials.detect_credential_type(creds) == "unknown"
    end

    test "parse_static_credentials_response/1 parses response correctly" do
      # This test will indirectly test the parse function through get_static
      response_data = %{
        "access_key" => "AKIA123456789",
        "secret_key" => "secret123",
        "expiration" => "2025-08-30T23:59:59Z"
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/aws/static-creds/test-role")
      end)

      assert {:ok, creds} = Credentials.get_static("test-role")
      assert creds.access_key == "AKIA123456789"
      assert creds.secret_key == "secret123"
      assert creds.expiration == "2025-08-30T23:59:59Z"
    end

    test "parse_static_credentials_response/1 handles direct response without data wrapper" do
      # Test the function clause that handles data directly without "data" wrapper
      response_data = %{
        "access_key" => "AKIA111111111",
        "secret_key" => "direct-secret",
        "expiration" => "2025-01-01T00:00:00Z"
      }

      expect_get(200, response_data, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/aws/static-creds/direct-role")
      end)

      assert {:ok, creds} = Credentials.get_static("direct-role")
      assert creds.access_key == "AKIA111111111"
      assert creds.secret_key == "direct-secret"
      assert creds.expiration == "2025-01-01T00:00:00Z"
    end
  end
end
