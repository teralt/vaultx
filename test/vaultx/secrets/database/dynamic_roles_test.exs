defmodule Vaultx.Secrets.Database.DynamicRolesTest do
  use ExUnit.Case, async: true

  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Secrets.Database

  describe "create_role/3" do
    test "creates a MySQL readonly role" do
      config = %{
        db_name: "mysql",
        creation_statements: [
          "CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}'",
          "GRANT SELECT ON *.* TO '{{name}}'@'%'"
        ],
        default_ttl: 3600,
        max_ttl: 86400
      }

      expect_post(204, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/database/roles/readonly")
        assert body["db_name"] == "mysql"

        assert body["creation_statements"] == [
                 "CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}'",
                 "GRANT SELECT ON *.* TO '{{name}}'@'%'"
               ]

        assert body["default_ttl"] == 3600
        assert body["max_ttl"] == 86400
      end)

      assert :ok = Database.create_role("readonly", config)
    end

    test "creates a PostgreSQL role with schema permissions" do
      config = %{
        db_name: "postgres",
        creation_statements: [
          "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
          "GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"
        ],
        revocation_statements: [
          "DROP ROLE IF EXISTS \"{{name}}\";"
        ],
        credential_type: "password"
      }

      expect_post(200, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/database/roles/postgres-readonly")
        assert body["db_name"] == "postgres"
        assert body["credential_type"] == "password"
        assert body["revocation_statements"] == ["DROP ROLE IF EXISTS \"{{name}}\";"]
      end)

      assert :ok = Database.create_role("postgres-readonly", config)
    end

    test "returns error on invalid role configuration" do
      config = %{
        db_name: "nonexistent",
        creation_statements: []
      }

      expect_post(400, %{
        "errors" => ["invalid role configuration"]
      })

      assert {:error, error} = Database.create_role("invalid-role", config)
      assert error.type == :invalid_request
    end

    test "handles HTTP errors when creating role" do
      config = %{db_name: "mysql", creation_statements: ["CREATE USER '{{name}}'@'%'"]}

      stub_request_raw(:post, :timeout)

      assert {:error, error} = Database.create_role("test-role", config)
      assert error.type == :http_error
    end
  end

  describe "read_role/2" do
    test "reads role configuration successfully" do
      response_data = %{
        "creation_statements" => [
          "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
          "GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"
        ],
        "credential_type" => "password",
        "credential_config" => %{},
        "db_name" => "postgres",
        "default_ttl" => 3600,
        "max_ttl" => 86400,
        "renew_statements" => [],
        "revocation_statements" => ["DROP ROLE IF EXISTS \"{{name}}\";"],
        "rollback_statements" => []
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/database/roles/readonly")
      end)

      assert {:ok, config} = Database.read_role("readonly")

      assert config.creation_statements == [
               "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
               "GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"
             ]

      assert config.credential_type == "password"
      assert config.db_name == "postgres"
      assert config.default_ttl == 3600
      assert config.max_ttl == 86400
      assert config.revocation_statements == ["DROP ROLE IF EXISTS \"{{name}}\";"]
    end

    test "returns error when role not found" do
      expect_get(404, %{
        "errors" => ["role not found"]
      })

      assert {:error, error} = Database.read_role("nonexistent")
      assert error.type == :not_found
    end

    test "handles HTTP errors when reading role" do
      stub_request_raw(:get, :timeout)

      assert {:error, error} = Database.read_role("test-role")
      assert error.type == :http_error
    end

    test "handles non-200 responses when reading role" do
      expect_get(500, %{"errors" => ["internal server error"]})

      assert {:error, error} = Database.read_role("test-role")
      assert error.type == :server_error
    end
  end

  describe "list_roles/1" do
    test "lists all roles successfully" do
      response_data = %{
        "keys" => ["readonly", "readwrite", "admin"]
      }

      expect_any(:list, 200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/database/roles")
      end)

      assert {:ok, roles} = Database.list_roles()
      assert roles == ["readonly", "readwrite", "admin"]
    end

    test "returns empty list when no roles exist" do
      response_data = %{
        "keys" => []
      }

      expect_any(:list, 200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/database/roles")
      end)

      assert {:ok, roles} = Database.list_roles()
      assert roles == []
    end

    test "handles HTTP errors when listing roles" do
      stub_request_raw(:list, :timeout)

      assert {:error, error} = Database.list_roles()
      assert error.type == :http_error
    end
  end

  describe "delete_role/2" do
    test "deletes role successfully" do
      expect_delete(204, %{}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/database/roles/old-role")
      end)

      assert :ok = Database.delete_role("old-role")
    end

    test "handles HTTP errors when deleting role" do
      stub_request_raw(:delete, :timeout)

      assert {:error, error} = Database.delete_role("test-role")
      assert error.type == :http_error
    end

    test "handles non-200 responses when deleting role" do
      expect_delete(400, %{"errors" => ["cannot delete role"]})

      assert {:error, error} = Database.delete_role("test-role")
      assert error.type == :invalid_request
    end
  end

  describe "generate_credentials/2" do
    test "generates credentials successfully" do
      response_data = %{
        "username" => "root-1430158508-126",
        "password" => "132ae3ef-5a64-7499-351e-bfe59f3a2a21"
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/database/creds/readonly")
      end)

      assert {:ok, creds} = Database.generate_credentials("readonly")
      assert creds.username == "root-1430158508-126"
      assert creds.password == "132ae3ef-5a64-7499-351e-bfe59f3a2a21"
    end

    test "returns error when role not found" do
      expect_get(404, %{
        "errors" => ["role not found"]
      })

      assert {:error, error} = Database.generate_credentials("nonexistent")
      assert error.type == :not_found
    end

    test "handles HTTP errors when generating credentials" do
      stub_request_raw(:get, :timeout)

      assert {:error, error} = Database.generate_credentials("test-role")
      assert error.type == :http_error
    end
  end
end
