defmodule Vaultx.Secrets.ConsulTest do
  use ExUnit.Case, async: true

  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Secrets.Consul

  describe "configure_access/2" do
    test "configures Consul access successfully" do
      config = %{
        address: "127.0.0.1:8500",
        scheme: "https",
        token: "management-token-123"
      }

      expect_post(204, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/consul/config/access")
        assert body["address"] == "127.0.0.1:8500"
        assert body["scheme"] == "https"
        assert body["token"] == "management-token-123"
      end)

      assert :ok = Consul.configure_access(config)
    end

    test "configures Consul access with TLS certificates" do
      config = %{
        address: "consul.example.com:8501",
        scheme: "https",
        token: "management-token",
        ca_cert: "-----BEGIN CERTIFICATE-----\nCA_CERT_DATA\n-----END CERTIFICATE-----",
        client_cert: "-----BEGIN CERTIFICATE-----\nCLIENT_CERT_DATA\n-----END CERTIFICATE-----",
        client_key: "-----BEGIN PRIVATE KEY-----\nCLIENT_KEY_DATA\n-----END PRIVATE KEY-----"
      }

      expect_post(204, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/consul/config/access")
        assert body["address"] == "consul.example.com:8501"
        assert body["scheme"] == "https"

        assert body["ca_cert"] ==
                 "-----BEGIN CERTIFICATE-----\nCA_CERT_DATA\n-----END CERTIFICATE-----"

        assert body["client_cert"] ==
                 "-----BEGIN CERTIFICATE-----\nCLIENT_CERT_DATA\n-----END CERTIFICATE-----"

        assert body["client_key"] ==
                 "-----BEGIN PRIVATE KEY-----\nCLIENT_KEY_DATA\n-----END PRIVATE KEY-----"
      end)

      assert :ok = Consul.configure_access(config)
    end

    test "handles configuration errors" do
      config = %{address: "invalid-address"}

      expect_post(500, %{
        "errors" => ["invalid address format"]
      })

      assert {:error, error} = Consul.configure_access(config)
      assert error.type == :server_error
    end

    test "handles HTTP errors during configuration" do
      config = %{address: "127.0.0.1:8500", token: "test-token"}

      stub_request_raw(:post, :timeout)

      assert {:error, error} = Consul.configure_access(config)
      assert error.type == :http_error
    end

    test "uses custom mount path" do
      config = %{address: "127.0.0.1:8500", token: "test-token"}

      expect_post(204, %{}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/custom-consul/config/access")
      end)

      assert :ok = Consul.configure_access(config, mount_path: "custom-consul")
    end
  end

  describe "create_role/3" do
    test "creates role with modern Consul policies" do
      role_config = %{
        consul_policies: ["web-policy", "db-read-policy"],
        consul_namespace: "production",
        ttl: "1h",
        max_ttl: "24h",
        local: false
      }

      expect_post(204, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/consul/roles/web-service")
        assert body["consul_policies"] == ["web-policy", "db-read-policy"]
        assert body["consul_namespace"] == "production"
        assert body["ttl"] == "1h"
        assert body["max_ttl"] == "24h"
        assert body["local"] == false
      end)

      assert :ok = Consul.create_role("web-service", role_config)
    end

    test "creates role with Consul roles" do
      role_config = %{
        consul_roles: ["web-role", "api-role"],
        consul_namespace: "staging"
      }

      expect_post(204, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/consul/roles/service-role")
        assert body["consul_roles"] == ["web-role", "api-role"]
        assert body["consul_namespace"] == "staging"
      end)

      assert :ok = Consul.create_role("service-role", role_config)
    end

    test "creates role with service identities" do
      role_config = %{
        service_identities: [
          "web:dc1,dc2",
          "api:dc1"
        ],
        consul_namespace: "production"
      }

      expect_post(204, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/consul/roles/service-identity-role")
        assert body["service_identities"] == ["web:dc1,dc2", "api:dc1"]
        assert body["consul_namespace"] == "production"
      end)

      assert :ok = Consul.create_role("service-identity-role", role_config)
    end

    test "creates role with node identities" do
      role_config = %{
        node_identities: [
          "web-01:dc1",
          "web-02:dc1"
        ],
        partition: "frontend"
      }

      expect_post(204, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/consul/roles/node-role")
        assert body["node_identities"] == ["web-01:dc1", "web-02:dc1"]
        assert body["partition"] == "frontend"
      end)

      assert :ok = Consul.create_role("node-role", role_config)
    end

    test "creates legacy role with base64 policy" do
      role_config = %{
        token_type: "client",
        policy: "a2V5ICIiIHsgcG9saWN5ID0gInJlYWQiIH0=",
        lease: "1h"
      }

      expect_post(204, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/consul/roles/legacy-role")
        assert body["token_type"] == "client"
        assert body["policy"] == "a2V5ICIiIHsgcG9saWN5ID0gInJlYWQiIH0="
        assert body["lease"] == "1h"
      end)

      assert :ok = Consul.create_role("legacy-role", role_config)
    end

    test "creates management token role" do
      role_config = %{
        token_type: "management"
      }

      expect_post(204, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/consul/roles/management-role")
        assert body["token_type"] == "management"
      end)

      assert :ok = Consul.create_role("management-role", role_config)
    end

    test "handles role creation errors" do
      role_config = %{consul_policies: ["nonexistent-policy"]}

      expect_post(500, %{
        "errors" => ["policy 'nonexistent-policy' not found"]
      })

      assert {:error, error} = Consul.create_role("invalid-role", role_config)
      assert error.type == :server_error
    end

    test "handles HTTP errors during role creation" do
      role_config = %{consul_policies: ["web-policy"]}

      stub_request_raw(:post, :timeout)

      assert {:error, error} = Consul.create_role("test-role", role_config)
      assert error.type == :http_error
    end

    test "uses custom mount path" do
      role_config = %{consul_policies: ["web-policy"]}

      expect_post(204, %{}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/custom-consul/roles/test-role")
      end)

      assert :ok = Consul.create_role("test-role", role_config, mount_path: "custom-consul")
    end
  end

  describe "read_role/2" do
    test "reads modern role configuration successfully" do
      response_data = %{
        "consul_policies" => ["web-policy", "db-read-policy"],
        "consul_roles" => [],
        "service_identities" => [],
        "node_identities" => [],
        "consul_namespace" => "production",
        "partition" => nil,
        "ttl" => "1h0m0s",
        "max_ttl" => "24h0m0s",
        "local" => false
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/consul/roles/web-service")
      end)

      assert {:ok, config} = Consul.read_role("web-service")
      assert config.consul_policies == ["web-policy", "db-read-policy"]
      assert config.consul_namespace == "production"
      assert config.ttl == "1h0m0s"
      assert config.max_ttl == "24h0m0s"
      assert config.local == false
    end

    test "reads role with service identities" do
      response_data = %{
        "consul_policies" => [],
        "consul_roles" => [],
        "service_identities" => ["web:dc1,dc2", "api:dc1"],
        "node_identities" => [],
        "consul_namespace" => "production"
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/consul/roles/service-role")
      end)

      assert {:ok, config} = Consul.read_role("service-role")
      assert config.service_identities == ["web:dc1,dc2", "api:dc1"]
      assert config.consul_namespace == "production"
    end

    test "reads legacy role configuration" do
      response_data = %{
        "token_type" => "client",
        "policy" => "a2V5ICIiIHsgcG9saWN5ID0gInJlYWQiIH0=",
        "policies" => ["legacy-policy"],
        "lease" => "1h0m0s"
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/consul/roles/legacy-role")
      end)

      assert {:ok, config} = Consul.read_role("legacy-role")
      assert config.token_type == "client"
      assert config.policy == "a2V5ICIiIHsgcG9saWN5ID0gInJlYWQiIH0="
      assert config.policies == ["legacy-policy"]
      assert config.lease == "1h0m0s"
    end

    test "handles read role errors" do
      expect_get(404, %{
        "errors" => ["role not found"]
      })

      assert {:error, error} = Consul.read_role("nonexistent")
      assert error.type == :not_found
    end

    test "handles HTTP errors during read role" do
      stub_request_raw(:get, :timeout)

      assert {:error, error} = Consul.read_role("test-role")
      assert error.type == :http_error
    end

    test "uses custom mount path" do
      response_data = %{
        "consul_policies" => ["web-policy"]
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/custom-consul/roles/test-role")
      end)

      assert {:ok, _config} = Consul.read_role("test-role", mount_path: "custom-consul")
    end
  end

  describe "list_roles/1" do
    test "lists roles successfully" do
      response_data = %{
        "keys" => ["web-service", "api-service", "node-role", "legacy-role"]
      }

      expect_any(:list, 200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/consul/roles")
      end)

      assert {:ok, roles} = Consul.list_roles()
      assert roles == ["web-service", "api-service", "node-role", "legacy-role"]
    end

    test "handles empty role list" do
      response_data = %{
        "keys" => []
      }

      expect_any(:list, 200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/consul/roles")
      end)

      assert {:ok, roles} = Consul.list_roles()
      assert roles == []
    end

    test "handles list roles errors" do
      expect_any(:list, 500, %{
        "errors" => ["internal server error"]
      })

      assert {:error, error} = Consul.list_roles()
      assert error.type == :server_error
    end

    test "handles HTTP errors during list roles" do
      stub_request_raw(:list, :timeout)

      assert {:error, error} = Consul.list_roles()
      assert error.type == :http_error
    end

    test "uses custom mount path" do
      response_data = %{
        "keys" => ["test-role"]
      }

      expect_any(:list, 200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/custom-consul/roles")
      end)

      assert {:ok, _roles} = Consul.list_roles(mount_path: "custom-consul")
    end
  end

  describe "delete_role/2" do
    test "deletes role successfully" do
      expect_delete(204, %{}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/consul/roles/old-role")
      end)

      assert :ok = Consul.delete_role("old-role")
    end

    test "deletes role with 200 response" do
      expect_delete(200, %{}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/consul/roles/test-role")
      end)

      assert :ok = Consul.delete_role("test-role")
    end

    test "handles delete role errors" do
      expect_delete(500, %{
        "errors" => ["internal server error"]
      })

      assert {:error, error} = Consul.delete_role("nonexistent")
      assert error.type == :server_error
    end

    test "handles HTTP errors during delete role" do
      stub_request_raw(:delete, :timeout)

      assert {:error, error} = Consul.delete_role("test-role")
      assert error.type == :http_error
    end

    test "uses custom mount path" do
      expect_delete(204, %{}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/custom-consul/roles/test-role")
      end)

      assert :ok = Consul.delete_role("test-role", mount_path: "custom-consul")
    end
  end

  describe "generate_credentials/2" do
    test "generates credentials successfully" do
      response_data = %{
        "token" => "8f246b77-f3e1-ff88-5b48-8ec93abf3e05"
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/consul/creds/web-service")
      end)

      assert {:ok, creds} = Consul.generate_credentials("web-service")
      assert creds.token == "8f246b77-f3e1-ff88-5b48-8ec93abf3e05"
    end

    test "handles credential generation errors" do
      expect_get(500, %{
        "errors" => ["failed to generate token"]
      })

      assert {:error, error} = Consul.generate_credentials("invalid-role")
      assert error.type == :server_error
    end

    test "handles role not found error" do
      expect_get(404, %{
        "errors" => ["role 'nonexistent-role' not found"]
      })

      assert {:error, error} = Consul.generate_credentials("nonexistent-role")
      assert error.type == :not_found
    end

    test "handles HTTP errors during credential generation" do
      stub_request_raw(:get, :timeout)

      assert {:error, error} = Consul.generate_credentials("test-role")
      assert error.type == :http_error
    end

    test "uses custom mount path" do
      response_data = %{
        "token" => "test-token-123"
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/custom-consul/creds/test-role")
      end)

      assert {:ok, creds} = Consul.generate_credentials("test-role", mount_path: "custom-consul")
      assert creds.token == "test-token-123"
    end
  end

  # Edge cases and comprehensive testing
  describe "edge cases and error scenarios" do
    test "handles malformed JSON responses gracefully" do
      expect_get(200, "invalid json")

      assert {:error, error} = Consul.read_role("test-role")
      assert error.type == :unknown_error
    end

    test "handles network timeouts gracefully" do
      stub_request_raw(:post, :timeout)

      config = %{address: "127.0.0.1:8500", token: "test-token"}
      assert {:error, error} = Consul.configure_access(config)
      assert error.type == :http_error
    end

    test "validates role names properly" do
      # Test with empty role name
      role_config = %{consul_policies: ["test-policy"]}

      expect_post(400, %{
        "errors" => ["role name cannot be empty"]
      })

      assert {:error, error} = Consul.create_role("", role_config)
      assert error.type == :invalid_request
    end

    test "handles concurrent role operations" do
      # Test concurrent role creation
      role_config = %{consul_policies: ["test-policy"]}

      # Mock multiple successful responses
      for _i <- 1..5 do
        expect_post(204, %{})
      end

      tasks =
        1..5
        |> Enum.map(fn i ->
          Task.async(fn ->
            Consul.create_role("concurrent-role-#{i}", role_config)
          end)
        end)

      results = Task.await_many(tasks, 5000)

      # All operations should succeed
      assert Enum.all?(results, &(&1 == :ok))
    end
  end
end
