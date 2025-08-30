defmodule Vaultx.Secrets.AWSTest do
  use ExUnit.Case, async: true

  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Secrets.AWS

  describe "configure_root/2" do
    test "configures AWS root credentials successfully" do
      config = %{
        access_key: "AKIA123456789",
        secret_key: "secret123",
        region: "us-east-1"
      }

      expect_post(204, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/aws/config/root")
        assert body["access_key"] == "AKIA123456789"
        assert body["secret_key"] == "secret123"
        assert body["region"] == "us-east-1"
      end)

      assert :ok = AWS.configure_root(config)
    end

    test "handles configuration errors" do
      config = %{access_key: "invalid"}

      expect_post(500, %{
        "errors" => ["invalid access key format"]
      })

      assert {:error, error} = AWS.configure_root(config)
      assert error.type == :server_error
    end

    test "handles HTTP errors during configuration" do
      config = %{access_key: "AKIA123456789", secret_key: "secret123"}

      stub_request_raw(:post, :timeout)

      assert {:error, error} = AWS.configure_root(config)
      assert error.type == :http_error
    end
  end

  describe "read_root_config/1" do
    test "reads root configuration successfully" do
      response_data = %{
        "access_key" => "AKIA123456789",
        "region" => "us-east-1",
        "max_retries" => -1
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/aws/config/root")
      end)

      assert {:ok, config} = AWS.read_root_config()
      assert config["access_key"] == "AKIA123456789"
      assert config["region"] == "us-east-1"
    end

    test "handles read root config errors" do
      expect_get(500, %{
        "errors" => ["internal server error"]
      })

      assert {:error, error} = AWS.read_root_config()
      assert error.type == :server_error
    end

    test "handles HTTP errors during read root config" do
      stub_request_raw(:get, :timeout)

      assert {:error, error} = AWS.read_root_config()
      assert error.type == :http_error
    end
  end

  describe "rotate_root/1" do
    test "rotates root credentials successfully" do
      response_data = %{
        "access_key" => "AKIA987654321"
      }

      expect_post(200, %{"data" => response_data}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/aws/config/rotate-root")
        assert body == %{}
      end)

      assert {:ok, result} = AWS.rotate_root()
      assert result["access_key"] == "AKIA987654321"
    end

    test "handles rotate root errors" do
      expect_post(500, %{
        "errors" => ["rotation failed"]
      })

      assert {:error, error} = AWS.rotate_root()
      assert error.type == :server_error
    end

    test "handles HTTP errors during rotate root" do
      stub_request_raw(:post, :timeout)

      assert {:error, error} = AWS.rotate_root()
      assert error.type == :http_error
    end
  end

  describe "create_role/3" do
    test "creates IAM user role successfully" do
      role_config = %{
        credential_type: "iam_user",
        policy_document: "{\"Version\": \"2012-10-17\"}",
        iam_groups: ["developers"]
      }

      expect_post(204, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/aws/roles/dev-role")
        assert body["credential_type"] == "iam_user"
        assert body["policy_document"] == "{\"Version\": \"2012-10-17\"}"
        assert body["iam_groups"] == ["developers"]
      end)

      assert :ok = AWS.create_role("dev-role", role_config)
    end

    test "creates assumed role successfully" do
      role_config = %{
        credential_type: "assumed_role",
        role_arns: ["arn:aws:iam::123456789012:role/MyRole"],
        default_sts_ttl: "1h",
        max_sts_ttl: "12h"
      }

      expect_post(204, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/aws/roles/assume-role")
        assert body["credential_type"] == "assumed_role"
        assert body["role_arns"] == ["arn:aws:iam::123456789012:role/MyRole"]
        assert body["default_sts_ttl"] == "1h"
        assert body["max_sts_ttl"] == "12h"
      end)

      assert :ok = AWS.create_role("assume-role", role_config)
    end

    test "handles role creation errors" do
      role_config = %{credential_type: "invalid"}

      expect_post(500, %{
        "errors" => ["invalid credential type"]
      })

      assert {:error, error} = AWS.create_role("invalid-role", role_config)
      assert error.type == :server_error
    end

    test "handles HTTP errors during role creation" do
      role_config = %{credential_type: "iam_user"}

      stub_request_raw(:post, :timeout)

      assert {:error, error} = AWS.create_role("test-role", role_config)
      assert error.type == :http_error
    end
  end

  describe "read_role/2" do
    test "reads role configuration successfully" do
      response_data = %{
        "credential_type" => "assumed_role",
        "role_arns" => ["arn:aws:iam::123456789012:role/MyRole"],
        "policy_arns" => [],
        "iam_groups" => [],
        "default_sts_ttl" => "1h",
        "max_sts_ttl" => "12h"
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/aws/roles/my-role")
      end)

      assert {:ok, config} = AWS.read_role("my-role")
      assert config.credential_type == "assumed_role"
      assert config.role_arns == ["arn:aws:iam::123456789012:role/MyRole"]
      assert config.default_sts_ttl == "1h"
    end

    test "handles read role errors" do
      expect_get(500, %{
        "errors" => ["internal server error"]
      })

      assert {:error, error} = AWS.read_role("nonexistent")
      assert error.type == :server_error
    end

    test "handles HTTP errors during read role" do
      stub_request_raw(:get, :timeout)

      assert {:error, error} = AWS.read_role("test-role")
      assert error.type == :http_error
    end
  end

  describe "list_roles/1" do
    test "lists roles successfully" do
      response_data = %{
        "keys" => ["dev-role", "prod-role", "assume-role"]
      }

      expect_any(:list, 200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/aws/roles")
      end)

      assert {:ok, roles} = AWS.list_roles()
      assert roles == ["dev-role", "prod-role", "assume-role"]
    end

    test "handles list roles errors" do
      expect_any(:list, 500, %{
        "errors" => ["internal server error"]
      })

      assert {:error, error} = AWS.list_roles()
      assert error.type == :server_error
    end

    test "handles HTTP errors during list roles" do
      stub_request_raw(:list, :timeout)

      assert {:error, error} = AWS.list_roles()
      assert error.type == :http_error
    end
  end

  describe "delete_role/2" do
    test "deletes role successfully" do
      expect_delete(204, %{}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/aws/roles/old-role")
      end)

      assert :ok = AWS.delete_role("old-role")
    end

    test "handles delete role errors" do
      expect_delete(500, %{
        "errors" => ["internal server error"]
      })

      assert {:error, error} = AWS.delete_role("nonexistent")
      assert error.type == :server_error
    end

    test "handles HTTP errors during delete role" do
      stub_request_raw(:delete, :timeout)

      assert {:error, error} = AWS.delete_role("test-role")
      assert error.type == :http_error
    end
  end

  describe "create_static_role/3" do
    test "creates static role successfully" do
      role_config = %{
        username: "existing-iam-user",
        rotation_period: "24h"
      }

      response_data = %{
        "static_account" => %{
          "username" => "existing-iam-user",
          "rotation_period" => "24h"
        }
      }

      expect_post(200, %{"data" => response_data}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/aws/static-roles/my-static-role")
        assert body["username"] == "existing-iam-user"
        assert body["rotation_period"] == "24h"
      end)

      assert {:ok, result} = AWS.create_static_role("my-static-role", role_config)
      assert result["static_account"]["username"] == "existing-iam-user"
    end

    test "handles static role creation errors" do
      role_config = %{username: "invalid"}

      expect_post(500, %{
        "errors" => ["invalid username"]
      })

      assert {:error, error} = AWS.create_static_role("invalid-role", role_config)
      assert error.type == :server_error
    end

    test "handles HTTP errors during static role creation" do
      role_config = %{username: "test-user"}

      stub_request_raw(:post, :timeout)

      assert {:error, error} = AWS.create_static_role("test-role", role_config)
      assert error.type == :http_error
    end
  end

  describe "read_static_role/2" do
    test "reads static role configuration successfully" do
      response_data = %{
        "username" => "existing-iam-user",
        "rotation_period" => "24h"
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/aws/static-roles/my-static-role")
      end)

      assert {:ok, config} = AWS.read_static_role("my-static-role")
      assert config[:username] == "existing-iam-user"
      assert config[:rotation_period] == "24h"
    end

    test "reads static role configuration without data wrapper" do
      response_data = %{
        "username" => "direct-iam-user",
        "rotation_period" => "12h"
      }

      expect_get(200, response_data, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/aws/static-roles/direct-role")
      end)

      assert {:ok, config} = AWS.read_static_role("direct-role")
      assert config[:username] == "direct-iam-user"
      assert config[:rotation_period] == "12h"
    end

    test "handles read static role errors" do
      expect_get(500, %{
        "errors" => ["internal server error"]
      })

      assert {:error, error} = AWS.read_static_role("nonexistent")
      assert error.type == :server_error
    end

    test "handles HTTP errors during read static role" do
      stub_request_raw(:get, :timeout)

      assert {:error, error} = AWS.read_static_role("test-role")
      assert error.type == :http_error
    end
  end

  describe "list_static_roles/1" do
    test "lists static roles successfully" do
      response_data = %{
        "keys" => ["static-role-1", "static-role-2"]
      }

      expect_any(:list, 200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/aws/static-roles")
      end)

      assert {:ok, roles} = AWS.list_static_roles()
      assert roles == ["static-role-1", "static-role-2"]
    end

    test "handles list static roles errors" do
      expect_any(:list, 500, %{
        "errors" => ["internal server error"]
      })

      assert {:error, error} = AWS.list_static_roles()
      assert error.type == :server_error
    end

    test "handles HTTP errors during list static roles" do
      stub_request_raw(:list, :timeout)

      assert {:error, error} = AWS.list_static_roles()
      assert error.type == :http_error
    end
  end

  describe "delete_static_role/2" do
    test "deletes static role successfully" do
      expect_delete(204, %{}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/aws/static-roles/old-static-role")
      end)

      assert :ok = AWS.delete_static_role("old-static-role")
    end

    test "handles delete static role errors" do
      expect_delete(500, %{
        "errors" => ["internal server error"]
      })

      assert {:error, error} = AWS.delete_static_role("nonexistent")
      assert error.type == :server_error
    end

    test "handles HTTP errors during delete static role" do
      stub_request_raw(:delete, :timeout)

      assert {:error, error} = AWS.delete_static_role("test-role")
      assert error.type == :http_error
    end
  end

  describe "configure_lease/2" do
    test "configures lease settings successfully" do
      lease_config = %{
        lease: "1h",
        lease_max: "24h"
      }

      expect_post(204, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/aws/config/lease")
        assert body["lease"] == "1h"
        assert body["lease_max"] == "24h"
      end)

      assert :ok = AWS.configure_lease(lease_config)
    end

    test "handles lease configuration errors" do
      lease_config = %{lease: "invalid"}

      expect_post(500, %{
        "errors" => ["invalid lease format"]
      })

      assert {:error, error} = AWS.configure_lease(lease_config)
      assert error.type == :server_error
    end

    test "handles HTTP errors during lease configuration" do
      lease_config = %{lease: "1h"}

      stub_request_raw(:post, :timeout)

      assert {:error, error} = AWS.configure_lease(lease_config)
      assert error.type == :http_error
    end
  end

  describe "read_lease_config/1" do
    test "reads lease configuration successfully" do
      response_data = %{
        "lease" => "1h",
        "lease_max" => "24h"
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/aws/config/lease")
      end)

      assert {:ok, config} = AWS.read_lease_config()
      assert config.lease == "1h"
      assert config.lease_max == "24h"
    end

    test "handles read lease config errors" do
      expect_get(500, %{
        "errors" => ["internal server error"]
      })

      assert {:error, error} = AWS.read_lease_config()
      assert error.type == :server_error
    end

    test "handles HTTP errors during read lease config" do
      stub_request_raw(:get, :timeout)

      assert {:error, error} = AWS.read_lease_config()
      assert error.type == :http_error
    end
  end

  describe "generate_credentials/2" do
    test "delegates to Credentials module" do
      response_data = %{
        "access_key" => "AKIA123456789",
        "secret_key" => "secret123"
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/aws/creds/test-role")
      end)

      assert {:ok, creds} = AWS.generate_credentials("test-role")
      assert creds.access_key == "AKIA123456789"
    end
  end

  describe "get_static_credentials/2" do
    test "delegates to Credentials module" do
      response_data = %{
        "access_key" => "AKIA123456789",
        "secret_key" => "secret123"
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/aws/static-creds/test-role")
      end)

      assert {:ok, creds} = AWS.get_static_credentials("test-role")
      assert creds.access_key == "AKIA123456789"
    end
  end
end
