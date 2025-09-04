defmodule Vaultx.Secrets.DatabaseTest do
  use ExUnit.Case, async: true

  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Secrets.Database

  describe "configure_connection/3" do
    test "configures database connection with basic parameters" do
      config = %{
        plugin_name: "mysql-database-plugin",
        connection_url: "{{username}}:{{password}}@tcp(127.0.0.1:3306)/",
        username: "vaultuser",
        password: "secretpassword",
        allowed_roles: ["readonly"]
      }

      expect_post(204, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/database/config/mysql")
        assert body["plugin_name"] == "mysql-database-plugin"
        assert body["connection_url"] == "{{username}}:{{password}}@tcp(127.0.0.1:3306)/"
        assert body["username"] == "vaultuser"
        assert body["password"] == "secretpassword"
        assert body["allowed_roles"] == ["readonly"]
      end)

      assert :ok = Database.configure_connection("mysql", config)
    end

    test "configures PostgreSQL connection with TLS" do
      config = %{
        plugin_name: "postgresql-database-plugin",
        connection_url:
          "postgresql://{{username}}:{{password}}@localhost:5432/postgres?sslmode=require",
        username: "vaultuser",
        password: "secretpassword",
        verify_connection: true
      }

      expect_post(200, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/database/config/postgres")
        assert body["plugin_name"] == "postgresql-database-plugin"
        assert body["verify_connection"] == true
      end)

      assert :ok = Database.configure_connection("postgres", config)
    end

    test "returns error on HTTP failure" do
      config = %{
        plugin_name: "mysql-database-plugin",
        connection_url: "invalid-url"
      }

      expect_post(400, %{
        "errors" => ["invalid connection configuration"]
      })

      assert {:error, error} = Database.configure_connection("mysql", config)
      assert error.type == :invalid_request
    end

    test "handles HTTP errors during configuration" do
      config = %{plugin_name: "mysql-database-plugin"}

      stub_request_raw(:post, :timeout)

      assert {:error, error} = Database.configure_connection("mysql", config)
      assert error.type == :http_error
    end
  end

  describe "read_connection/2" do
    test "reads connection configuration successfully" do
      response_data = %{
        "allowed_roles" => ["readonly"],
        "connection_details" => %{
          "connection_url" => "{{username}}:{{password}}@tcp(127.0.0.1:3306)/",
          "username" => "vaultuser"
        },
        "plugin_name" => "mysql-database-plugin",
        "plugin_version" => "",
        "password_policy" => "",
        "root_credentials_rotate_statements" => [],
        "skip_static_role_import_rotation" => false
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/database/config/mysql")
      end)

      assert {:ok, config} = Database.read_connection("mysql")
      assert config.allowed_roles == ["readonly"]
      assert config.plugin_name == "mysql-database-plugin"
      assert config.skip_static_role_import_rotation == false
    end

    test "returns error when connection not found" do
      expect_get(404, %{
        "errors" => ["connection not found"]
      })

      assert {:error, error} = Database.read_connection("nonexistent")
      assert error.type == :not_found
    end

    test "handles HTTP errors when reading connection" do
      stub_request_raw(:get, :timeout)

      assert {:error, error} = Database.read_connection("mysql")
      assert error.type == :http_error
    end

    test "handles non-200 responses when reading connection" do
      expect_get(500, %{"errors" => ["internal server error"]})

      assert {:error, error} = Database.read_connection("mysql")
      assert error.type == :server_error
    end
  end

  describe "list_connections/1" do
    test "lists all connections successfully" do
      response_data = %{
        "keys" => ["mysql", "postgres", "mongodb"]
      }

      expect_any(:list, 200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/database/config")
      end)

      assert {:ok, connections} = Database.list_connections()
      assert connections == ["mysql", "postgres", "mongodb"]
    end

    test "returns empty list when no connections exist" do
      response_data = %{
        "keys" => []
      }

      expect_any(:list, 200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/database/config")
      end)

      assert {:ok, connections} = Database.list_connections()
      assert connections == []
    end

    test "handles HTTP errors when listing connections" do
      stub_request_raw(:list, :timeout)

      assert {:error, error} = Database.list_connections()
      assert error.type == :http_error
    end

    test "handles non-200 responses when listing connections" do
      expect_any(:list, 500, %{"errors" => ["internal server error"]})

      assert {:error, error} = Database.list_connections()
      assert error.type == :server_error
    end
  end

  describe "delete_connection/2" do
    test "deletes connection successfully" do
      expect_delete(204, %{}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/database/config/old-connection")
      end)

      assert :ok = Database.delete_connection("old-connection")
    end

    test "handles HTTP errors when deleting connection" do
      stub_request_raw(:delete, :timeout)

      assert {:error, error} = Database.delete_connection("mysql")
      assert error.type == :http_error
    end

    test "handles non-200 responses when deleting connection" do
      expect_delete(400, %{"errors" => ["cannot delete connection"]})

      assert {:error, error} = Database.delete_connection("mysql")
      assert error.type == :invalid_request
    end
  end

  describe "reset_connection/2" do
    test "resets connection successfully" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/database/reset/mysql")
        assert body == %{}
      end)

      assert :ok = Database.reset_connection("mysql")
    end

    test "handles HTTP errors when resetting connection" do
      stub_request_raw(:post, :timeout)

      assert {:error, error} = Database.reset_connection("mysql")
      assert error.type == :http_error
    end

    test "handles non-200 responses when resetting connection" do
      expect_post(400, %{"errors" => ["cannot reset connection"]})

      assert {:error, error} = Database.reset_connection("mysql")
      assert error.type == :invalid_request
    end
  end

  describe "reload_plugin/2" do
    test "reloads plugin successfully" do
      response_data = %{
        "connections" => ["pg1", "pg2"],
        "count" => 2
      }

      expect_post(200, %{"data" => response_data}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/database/reload/postgresql-database-plugin")
        assert body == %{}
      end)

      assert {:ok, result} = Database.reload_plugin("postgresql-database-plugin")
      assert result.connections == ["pg1", "pg2"]
      assert result.count == 2
    end

    test "handles HTTP errors when reloading plugin" do
      stub_request_raw(:post, :timeout)

      assert {:error, error} = Database.reload_plugin("postgresql-database-plugin")
      assert error.type == :http_error
    end

    test "handles non-200 responses when reloading plugin" do
      expect_post(400, %{"errors" => ["plugin not found"]})

      assert {:error, error} = Database.reload_plugin("nonexistent-plugin")
      assert error.type == :invalid_request
    end
  end

  describe "rotate_root_credentials/2" do
    test "rotates root credentials successfully" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/database/rotate-root/mysql")
        assert body == %{}
      end)

      assert :ok = Database.rotate_root_credentials("mysql")
    end

    test "handles HTTP errors when rotating root credentials" do
      stub_request_raw(:post, :timeout)

      assert {:error, error} = Database.rotate_root_credentials("mysql")
      assert error.type == :http_error
    end

    test "handles non-200 responses when rotating root credentials" do
      expect_post(400, %{"errors" => ["cannot rotate root credentials"]})

      assert {:error, error} = Database.rotate_root_credentials("mysql")
      assert error.type == :invalid_request
    end
  end
end
