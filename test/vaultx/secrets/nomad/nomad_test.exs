defmodule Vaultx.Secrets.NomadTest do
  use ExUnit.Case, async: true

  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Secrets.Nomad

  describe "configure_access/2" do
    test "configures Nomad access with basic parameters" do
      config = %{
        address: "http://127.0.0.1:4646",
        token: "test-token"
      }

      expect_post(204, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/nomad/config/access")
        assert body["address"] == "http://127.0.0.1:4646"
        assert body["token"] == "test-token"
      end)

      assert :ok = Nomad.configure_access(config)
    end

    test "configures Nomad access with TLS parameters" do
      config = %{
        address: "https://nomad.example.com:4646",
        token: "test-token",
        max_token_name_length: 256,
        ca_cert: "-----BEGIN CERTIFICATE-----...",
        client_cert: "-----BEGIN CERTIFICATE-----...",
        client_key: "-----BEGIN PRIVATE KEY-----..."
      }

      expect_post(200, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/nomad/config/access")
        assert body["address"] == "https://nomad.example.com:4646"
        assert body["token"] == "test-token"
        assert body["max_token_name_length"] == 256
        assert body["ca_cert"] == "-----BEGIN CERTIFICATE-----..."
        assert body["client_cert"] == "-----BEGIN CERTIFICATE-----..."
        assert body["client_key"] == "-----BEGIN PRIVATE KEY-----..."
      end)

      assert :ok = Nomad.configure_access(config)
    end

    test "returns error on HTTP failure" do
      config = %{
        address: "http://127.0.0.1:4646",
        token: "test-token"
      }

      expect_post(400, %{
        "errors" => ["invalid configuration"]
      })

      assert {:error, error} = Nomad.configure_access(config)
      assert error.type == :invalid_request
    end

    test "handles HTTP errors during configuration" do
      config = %{address: "http://127.0.0.1:4646", token: "test-token"}

      stub_request_raw(:post, :timeout)

      assert {:error, error} = Nomad.configure_access(config)
      assert error.type == :http_error
    end
  end

  describe "read_access_config/1" do
    test "reads access configuration successfully" do
      response_data = %{
        "address" => "http://localhost:4646/"
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/nomad/config/access")
      end)

      assert {:ok, config} = Nomad.read_access_config()
      assert config.address == "http://localhost:4646/"
    end

    test "returns error when configuration not found" do
      expect_get(404, %{
        "errors" => ["configuration not found"]
      })

      assert {:error, error} = Nomad.read_access_config()
      assert error.type == :not_found
    end

    test "handles HTTP errors when reading access config" do
      stub_request_raw(:get, :timeout)

      assert {:error, error} = Nomad.read_access_config()
      assert error.type == :http_error
    end

    test "handles non-200 responses when reading access config" do
      expect_get(500, %{"errors" => ["internal server error"]})

      assert {:error, error} = Nomad.read_access_config()
      assert error.type == :server_error
    end
  end

  describe "configure_lease/2" do
    test "configures lease settings" do
      config = %{
        ttl: "1h",
        max_ttl: "24h"
      }

      expect_post(204, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/nomad/config/lease")
        assert body["ttl"] == "1h"
        assert body["max_ttl"] == "24h"
      end)

      assert :ok = Nomad.configure_lease(config)
    end

    test "handles errors when configuring lease" do
      config = %{ttl: "1h", max_ttl: "24h"}

      expect_post(400, %{"errors" => ["invalid lease configuration"]})

      assert {:error, error} = Nomad.configure_lease(config)
      assert error.type == :invalid_request
    end

    test "handles HTTP errors when configuring lease" do
      config = %{ttl: "1h", max_ttl: "24h"}

      stub_request_raw(:post, :timeout)

      assert {:error, error} = Nomad.configure_lease(config)
      assert error.type == :http_error
    end
  end

  describe "read_lease_config/1" do
    test "reads lease configuration successfully" do
      response_data = %{
        "ttl" => 3600,
        "max_ttl" => 86400
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/nomad/config/lease")
      end)

      assert {:ok, config} = Nomad.read_lease_config()
      assert config.ttl == 3600
      assert config.max_ttl == 86400
    end

    test "handles HTTP errors when reading lease config" do
      stub_request_raw(:get, :timeout)

      assert {:error, error} = Nomad.read_lease_config()
      assert error.type == :http_error
    end

    test "handles non-200 responses when reading lease config" do
      expect_get(500, %{"errors" => ["internal server error"]})

      assert {:error, error} = Nomad.read_lease_config()
      assert error.type == :server_error
    end
  end

  describe "delete_lease_config/1" do
    test "deletes lease configuration successfully" do
      expect_delete(204, %{}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/nomad/config/lease")
      end)

      assert :ok = Nomad.delete_lease_config()
    end

    test "handles errors when deleting lease config" do
      expect_delete(400, %{"errors" => ["cannot delete lease config"]})

      assert {:error, error} = Nomad.delete_lease_config()
      assert error.type == :invalid_request
    end

    test "handles HTTP errors when deleting lease config" do
      stub_request_raw(:delete, :timeout)

      assert {:error, error} = Nomad.delete_lease_config()
      assert error.type == :http_error
    end
  end

  describe "create_role/3" do
    test "creates a client role with policies" do
      config = %{
        policies: "web-policy,db-read-policy",
        type: "client",
        global: false
      }

      expect_post(204, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/nomad/role/web-service")
        assert body["policies"] == "web-policy,db-read-policy"
        assert body["type"] == "client"
        assert body["global"] == false
      end)

      assert :ok = Nomad.create_role("web-service", config)
    end

    test "creates a management role" do
      config = %{
        type: "management",
        global: true
      }

      expect_post(200, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/nomad/role/admin-role")
        assert body["type"] == "management"
        assert body["global"] == true
      end)

      assert :ok = Nomad.create_role("admin-role", config)
    end

    test "returns error on invalid role configuration" do
      config = %{
        type: "invalid-type"
      }

      expect_post(400, %{
        "errors" => ["invalid token type"]
      })

      assert {:error, error} = Nomad.create_role("invalid-role", config)
      assert error.type == :invalid_request
    end

    test "handles HTTP errors when creating role" do
      config = %{type: "client", policies: "test-policy"}

      stub_request_raw(:post, :timeout)

      assert {:error, error} = Nomad.create_role("test-role", config)
      assert error.type == :http_error
    end
  end

  describe "read_role/2" do
    test "reads role configuration successfully" do
      response_data = %{
        "policies" => ["web-policy", "db-read-policy"],
        "token_type" => "client",
        "global" => false,
        "lease" => "0s"
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/nomad/role/web-service")
      end)

      assert {:ok, config} = Nomad.read_role("web-service")
      assert config.policies == ["web-policy", "db-read-policy"]
      assert config.type == "client"
      assert config.global == false
      assert config.lease == "0s"
    end

    test "parses comma-separated policies string" do
      response_data = %{
        "policies" => "web-policy,db-read-policy",
        "token_type" => "client"
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/nomad/role/web-service")
      end)

      assert {:ok, config} = Nomad.read_role("web-service")
      assert config.policies == ["web-policy", "db-read-policy"]
    end

    test "returns error when role not found" do
      expect_get(404, %{
        "errors" => ["role not found"]
      })

      assert {:error, error} = Nomad.read_role("nonexistent")
      assert error.type == :not_found
    end

    test "handles HTTP errors when reading role" do
      stub_request_raw(:get, :timeout)

      assert {:error, error} = Nomad.read_role("test-role")
      assert error.type == :http_error
    end

    test "handles empty policies correctly" do
      response_data = %{
        "policies" => "",
        "token_type" => "client"
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/nomad/role/empty-policies")
      end)

      assert {:ok, config} = Nomad.read_role("empty-policies")
      assert config.policies == []
    end

    test "handles nil policies correctly" do
      response_data = %{
        "policies" => nil,
        "token_type" => "client"
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/nomad/role/nil-policies")
      end)

      assert {:ok, config} = Nomad.read_role("nil-policies")
      assert config.policies == []
    end

    test "handles policies with empty strings correctly" do
      response_data = %{
        "policies" => "policy1,,policy2, ,policy3",
        "token_type" => "client"
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/nomad/role/empty-string-policies")
      end)

      assert {:ok, config} = Nomad.read_role("empty-string-policies")
      assert config.policies == ["policy1", "policy2", "policy3"]
    end

    test "handles non-string non-list policies correctly" do
      response_data = %{
        "policies" => 123,
        "token_type" => "client"
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/nomad/role/invalid-policies")
      end)

      assert {:ok, config} = Nomad.read_role("invalid-policies")
      assert config.policies == []
    end
  end

  describe "list_roles/1" do
    test "lists all roles successfully" do
      response_data = %{
        "keys" => ["web-service", "api-service", "admin-role"]
      }

      expect_any(:list, 200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/nomad/role")
      end)

      assert {:ok, roles} = Nomad.list_roles()
      assert roles == ["web-service", "api-service", "admin-role"]
    end

    test "returns empty list when no roles exist" do
      response_data = %{
        "keys" => []
      }

      expect_any(:list, 200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/nomad/role")
      end)

      assert {:ok, roles} = Nomad.list_roles()
      assert roles == []
    end

    test "handles HTTP errors when listing roles" do
      stub_request_raw(:list, :timeout)

      assert {:error, error} = Nomad.list_roles()
      assert error.type == :http_error
    end

    test "handles non-200 responses when listing roles" do
      expect_any(:list, 500, %{"errors" => ["internal server error"]})

      assert {:error, error} = Nomad.list_roles()
      assert error.type == :server_error
    end
  end

  describe "delete_role/2" do
    test "deletes role successfully" do
      expect_delete(204, %{}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/nomad/role/old-role")
      end)

      assert :ok = Nomad.delete_role("old-role")
    end

    test "succeeds even when role doesn't exist" do
      expect_delete(204, %{}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/nomad/role/nonexistent")
      end)

      assert :ok = Nomad.delete_role("nonexistent")
    end

    test "handles HTTP errors when deleting role" do
      stub_request_raw(:delete, :timeout)

      assert {:error, error} = Nomad.delete_role("test-role")
      assert error.type == :http_error
    end
  end

  describe "generate_credentials/2" do
    test "generates credentials successfully" do
      response_data = %{
        "accessor_id" => "c834ba40-8d84-b0c1-c084-3a31d3383c03",
        "secret_id" => "65af6f07-7f57-bb24-cdae-a27f86a894ce"
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/nomad/creds/web-service")
      end)

      assert {:ok, creds} = Nomad.generate_credentials("web-service")
      assert creds.accessor_id == "c834ba40-8d84-b0c1-c084-3a31d3383c03"
      assert creds.secret_id == "65af6f07-7f57-bb24-cdae-a27f86a894ce"
    end

    test "returns error when role not found" do
      expect_get(404, %{
        "errors" => ["role not found"]
      })

      assert {:error, error} = Nomad.generate_credentials("nonexistent")
      assert error.type == :not_found
    end

    test "handles HTTP errors when generating credentials" do
      stub_request_raw(:get, :timeout)

      assert {:error, error} = Nomad.generate_credentials("test-role")
      assert error.type == :http_error
    end
  end
end
