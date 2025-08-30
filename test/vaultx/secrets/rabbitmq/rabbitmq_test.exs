defmodule Vaultx.Secrets.RabbitMQTest do
  use ExUnit.Case, async: true

  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Secrets.RabbitMQ

  describe "configure_connection/2" do
    test "configures RabbitMQ connection successfully" do
      config = %{
        connection_uri: "http://localhost:15672",
        username: "admin",
        password: "admin123"
      }

      expect_post(204, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/rabbitmq/config/connection")
        assert body["connection_uri"] == "http://localhost:15672"
        assert body["username"] == "admin"
        assert body["password"] == "admin123"
      end)

      assert :ok = RabbitMQ.configure_connection(config)
    end

    test "configures RabbitMQ connection with advanced options" do
      config = %{
        connection_uri: "https://rabbitmq.example.com:15671",
        username: "vault-admin",
        password: "secure-password",
        verify_connection: true,
        password_policy: "rabbitmq_policy",
        username_template: "vault-{{.DisplayName}}-{{random 8}}"
      }

      expect_post(204, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/rabbitmq/config/connection")
        assert body["connection_uri"] == "https://rabbitmq.example.com:15671"
        assert body["username"] == "vault-admin"
        assert body["password"] == "secure-password"
        assert body["verify_connection"] == true
        assert body["password_policy"] == "rabbitmq_policy"
        assert body["username_template"] == "vault-{{.DisplayName}}-{{random 8}}"
      end)

      assert :ok = RabbitMQ.configure_connection(config)
    end

    test "handles connection configuration errors" do
      config = %{connection_uri: "invalid-uri"}

      expect_post(500, %{
        "errors" => ["invalid connection URI format"]
      })

      assert {:error, error} = RabbitMQ.configure_connection(config)
      assert error.type == :server_error
    end

    test "handles HTTP errors during connection configuration" do
      config = %{
        connection_uri: "http://localhost:15672",
        username: "admin",
        password: "admin123"
      }

      stub_request_raw(:post, :timeout)

      assert {:error, error} = RabbitMQ.configure_connection(config)
      assert error.type == :http_error
    end

    test "uses custom mount path" do
      config = %{
        connection_uri: "http://localhost:15672",
        username: "admin",
        password: "admin123"
      }

      expect_post(204, %{}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/custom-rabbitmq/config/connection")
      end)

      assert :ok = RabbitMQ.configure_connection(config, mount_path: "custom-rabbitmq")
    end
  end

  describe "configure_lease/2" do
    test "configures lease settings successfully" do
      config = %{
        ttl: 1800,
        max_ttl: 3600
      }

      expect_post(204, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/rabbitmq/config/lease")
        assert body["ttl"] == 1800
        assert body["max_ttl"] == 3600
      end)

      assert :ok = RabbitMQ.configure_lease(config)
    end

    test "handles lease configuration errors" do
      config = %{ttl: -1}

      expect_post(400, %{
        "errors" => ["ttl must be non-negative"]
      })

      assert {:error, error} = RabbitMQ.configure_lease(config)
      assert error.type == :invalid_request
    end

    test "handles HTTP errors during lease configuration" do
      config = %{ttl: 1800, max_ttl: 3600}

      stub_request_raw(:post, :timeout)

      assert {:error, error} = RabbitMQ.configure_lease(config)
      assert error.type == :http_error
    end

    test "uses custom mount path" do
      config = %{ttl: 1800, max_ttl: 3600}

      expect_post(204, %{}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/custom-rabbitmq/config/lease")
      end)

      assert :ok = RabbitMQ.configure_lease(config, mount_path: "custom-rabbitmq")
    end
  end

  describe "create_role/3" do
    test "creates role with basic configuration" do
      role_config = %{
        tags: "management",
        vhosts: "{\"/\": {\"configure\":\".*\", \"write\":\".*\", \"read\": \".*\"}}"
      }

      expect_post(204, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/rabbitmq/roles/web-service")
        assert body["tags"] == "management"

        assert body["vhosts"] ==
                 "{\"/\": {\"configure\":\".*\", \"write\":\".*\", \"read\": \".*\"}}"
      end)

      assert :ok = RabbitMQ.create_role("web-service", role_config)
    end

    test "creates role with topic permissions" do
      role_config = %{
        tags: "monitoring",
        vhosts: "{\"/\": {\"configure\":\"\", \"write\":\"\", \"read\": \".*\"}}",
        vhost_topics: "{\"/\": {\"amq.topic\": {\"write\":\"\", \"read\": \".*\"}}}"
      }

      expect_post(204, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/rabbitmq/roles/monitoring-role")
        assert body["tags"] == "monitoring"
        assert body["vhosts"] == "{\"/\": {\"configure\":\"\", \"write\":\"\", \"read\": \".*\"}}"

        assert body["vhost_topics"] ==
                 "{\"/\": {\"amq.topic\": {\"write\":\"\", \"read\": \".*\"}}}"
      end)

      assert :ok = RabbitMQ.create_role("monitoring-role", role_config)
    end

    test "creates role with multiple tags" do
      role_config = %{
        tags: "management,monitoring,policymaker",
        vhosts: "{\"/\": {\"configure\":\".*\", \"write\":\".*\", \"read\": \".*\"}}"
      }

      expect_post(204, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/rabbitmq/roles/admin-role")
        assert body["tags"] == "management,monitoring,policymaker"
      end)

      assert :ok = RabbitMQ.create_role("admin-role", role_config)
    end

    test "handles role creation errors" do
      role_config = %{vhosts: "invalid-json"}

      expect_post(500, %{
        "errors" => ["invalid vhosts JSON format"]
      })

      assert {:error, error} = RabbitMQ.create_role("invalid-role", role_config)
      assert error.type == :server_error
    end

    test "handles HTTP errors during role creation" do
      role_config = %{tags: "management"}

      stub_request_raw(:post, :timeout)

      assert {:error, error} = RabbitMQ.create_role("test-role", role_config)
      assert error.type == :http_error
    end

    test "uses custom mount path" do
      role_config = %{tags: "management"}

      expect_post(204, %{}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/custom-rabbitmq/roles/test-role")
      end)

      assert :ok = RabbitMQ.create_role("test-role", role_config, mount_path: "custom-rabbitmq")
    end
  end

  describe "read_role/2" do
    test "reads role configuration successfully" do
      response_data = %{
        "tags" => "management",
        "vhosts" => "{\"/\": {\"configure\":\".*\", \"write\":\".*\", \"read\": \".*\"}}",
        "vhost_topics" => "{\"/\": {\"amq.topic\": {\"write\":\".*\", \"read\": \".*\"}}}"
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/rabbitmq/roles/web-service")
      end)

      assert {:ok, config} = RabbitMQ.read_role("web-service")
      assert config.tags == "management"

      assert config.vhosts ==
               "{\"/\": {\"configure\":\".*\", \"write\":\".*\", \"read\": \".*\"}}"

      assert config.vhost_topics ==
               "{\"/\": {\"amq.topic\": {\"write\":\".*\", \"read\": \".*\"}}}"
    end

    test "reads role with empty fields" do
      response_data = %{
        "tags" => "",
        "vhosts" => "",
        "vhost_topics" => ""
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/rabbitmq/roles/minimal-role")
      end)

      assert {:ok, config} = RabbitMQ.read_role("minimal-role")
      assert config.tags == ""
      assert config.vhosts == ""
      assert config.vhost_topics == ""
    end

    test "handles read role errors" do
      expect_get(404, %{
        "errors" => ["role not found"]
      })

      assert {:error, error} = RabbitMQ.read_role("nonexistent")
      assert error.type == :not_found
    end

    test "handles HTTP errors during read role" do
      stub_request_raw(:get, :timeout)

      assert {:error, error} = RabbitMQ.read_role("test-role")
      assert error.type == :http_error
    end

    test "uses custom mount path" do
      response_data = %{
        "tags" => "management",
        "vhosts" => "",
        "vhost_topics" => ""
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/custom-rabbitmq/roles/test-role")
      end)

      assert {:ok, _config} = RabbitMQ.read_role("test-role", mount_path: "custom-rabbitmq")
    end
  end

  describe "delete_role/2" do
    test "deletes role successfully" do
      expect_delete(204, %{}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/rabbitmq/roles/old-role")
      end)

      assert :ok = RabbitMQ.delete_role("old-role")
    end

    test "deletes role with 200 response" do
      expect_delete(200, %{}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/rabbitmq/roles/test-role")
      end)

      assert :ok = RabbitMQ.delete_role("test-role")
    end

    test "handles delete role errors" do
      expect_delete(500, %{
        "errors" => ["internal server error"]
      })

      assert {:error, error} = RabbitMQ.delete_role("nonexistent")
      assert error.type == :server_error
    end

    test "handles HTTP errors during delete role" do
      stub_request_raw(:delete, :timeout)

      assert {:error, error} = RabbitMQ.delete_role("test-role")
      assert error.type == :http_error
    end

    test "uses custom mount path" do
      expect_delete(204, %{}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/custom-rabbitmq/roles/test-role")
      end)

      assert :ok = RabbitMQ.delete_role("test-role", mount_path: "custom-rabbitmq")
    end
  end

  describe "generate_credentials/2" do
    test "generates credentials successfully" do
      response_data = %{
        "username" => "root-4b95bf47-281d-dcb5-8a60-9594f8056092",
        "password" => "e1b6c159-ca63-4c6a-3886-6639eae06c30"
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/rabbitmq/creds/web-service")
      end)

      assert {:ok, creds} = RabbitMQ.generate_credentials("web-service")
      assert creds.username == "root-4b95bf47-281d-dcb5-8a60-9594f8056092"
      assert creds.password == "e1b6c159-ca63-4c6a-3886-6639eae06c30"
    end

    test "handles credential generation errors" do
      expect_get(500, %{
        "errors" => ["failed to generate credentials"]
      })

      assert {:error, error} = RabbitMQ.generate_credentials("invalid-role")
      assert error.type == :server_error
    end

    test "handles role not found error" do
      expect_get(404, %{
        "errors" => ["role 'nonexistent-role' not found"]
      })

      assert {:error, error} = RabbitMQ.generate_credentials("nonexistent-role")
      assert error.type == :not_found
    end

    test "handles HTTP errors during credential generation" do
      stub_request_raw(:get, :timeout)

      assert {:error, error} = RabbitMQ.generate_credentials("test-role")
      assert error.type == :http_error
    end

    test "uses custom mount path" do
      response_data = %{
        "username" => "test-user-123",
        "password" => "test-password-456"
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/custom-rabbitmq/creds/test-role")
      end)

      assert {:ok, creds} =
               RabbitMQ.generate_credentials("test-role", mount_path: "custom-rabbitmq")

      assert creds.username == "test-user-123"
      assert creds.password == "test-password-456"
    end
  end

  # Edge cases and comprehensive testing
  describe "edge cases and error scenarios" do
    test "handles malformed JSON responses gracefully" do
      expect_get(200, "invalid json")

      assert {:error, error} = RabbitMQ.read_role("test-role")
      assert error.type == :unknown_error
    end

    test "handles network timeouts gracefully" do
      stub_request_raw(:post, :timeout)

      config = %{
        connection_uri: "http://localhost:15672",
        username: "admin",
        password: "admin123"
      }

      assert {:error, error} = RabbitMQ.configure_connection(config)
      assert error.type == :http_error
    end

    test "handles concurrent role operations" do
      # Test concurrent role creation
      role_config = %{tags: "management"}

      # Mock multiple successful responses
      for _i <- 1..5 do
        expect_post(204, %{})
      end

      tasks =
        1..5
        |> Enum.map(fn i ->
          Task.async(fn ->
            RabbitMQ.create_role("concurrent-role-#{i}", role_config)
          end)
        end)

      results = Task.await_many(tasks, 5000)

      # All operations should succeed
      assert Enum.all?(results, &(&1 == :ok))
    end

    test "handles empty configuration gracefully" do
      role_config = %{}

      expect_post(204, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/rabbitmq/roles/empty-role")
        assert body == %{}
      end)

      assert :ok = RabbitMQ.create_role("empty-role", role_config)
    end

    test "handles complex vhost permissions" do
      role_config = %{
        tags: "management,monitoring",
        vhosts:
          "{\"/\": {\"configure\":\"^amq\\.gen.*|^aliveness-test$\", \"write\":\"^amq\\.gen.*|^aliveness-test$\", \"read\": \"^amq\\.gen.*|^aliveness-test$\"}, \"/test\": {\"configure\":\".*\", \"write\":\".*\", \"read\": \".*\"}}",
        vhost_topics:
          "{\"/\": {\"amq.topic\": {\"write\":\"^logs\\\\.\", \"read\": \"^logs\\\\.\"}, \"logs\": {\"write\":\".*\", \"read\": \".*\"}}}"
      }

      expect_post(204, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/rabbitmq/roles/complex-role")
        assert body["tags"] == "management,monitoring"
        assert String.contains?(body["vhosts"], "/test")
        assert String.contains?(body["vhost_topics"], "amq.topic")
      end)

      assert :ok = RabbitMQ.create_role("complex-role", role_config)
    end
  end
end
