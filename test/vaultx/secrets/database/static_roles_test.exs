defmodule Vaultx.Secrets.Database.StaticRolesTest do
  use ExUnit.Case, async: true

  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Secrets.Database

  describe "create_static_role/3" do
    test "creates static role with rotation period" do
      config = %{
        db_name: "mysql",
        username: "static-database-user",
        rotation_statements: [
          "ALTER USER \"{{name}}\" IDENTIFIED BY '{{password}}';"
        ],
        rotation_period: 3600
      }

      expect_post(204, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/database/static-roles/static-user")
        assert body["db_name"] == "mysql"
        assert body["username"] == "static-database-user"

        assert body["rotation_statements"] == [
                 "ALTER USER \"{{name}}\" IDENTIFIED BY '{{password}}';"
               ]

        assert body["rotation_period"] == 3600
      end)

      assert :ok = Database.create_static_role("static-user", config)
    end

    test "creates static role with default options" do
      config = %{
        db_name: "mysql",
        username: "static-database-user",
        rotation_statements: [
          "ALTER USER \"{{name}}\" IDENTIFIED BY '{{password}}';"
        ],
        rotation_period: 3600
      }

      expect_post(204, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/database/static-roles/default-opts-user")
        assert body["db_name"] == "mysql"
      end)

      # Test with default opts (empty list)
      assert :ok = Database.create_static_role("default-opts-user", config)
    end

    test "creates static role with rotation schedule" do
      config = %{
        db_name: "mysql",
        username: "static-database-user",
        rotation_statements: [
          "ALTER USER \"{{name}}\" IDENTIFIED BY '{{password}}';"
        ],
        rotation_schedule: "0 0 * * SAT",
        rotation_window: 3600
      }

      expect_post(200, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/database/static-roles/scheduled-user")
        assert body["rotation_schedule"] == "0 0 * * SAT"
        assert body["rotation_window"] == 3600
      end)

      assert :ok = Database.create_static_role("scheduled-user", config)
    end

    test "returns error on invalid static role configuration" do
      config = %{
        db_name: "nonexistent",
        username: "invalid-user"
      }

      expect_post(400, %{
        "errors" => ["invalid static role configuration"]
      })

      assert {:error, error} = Database.create_static_role("invalid-static-role", config)
      assert error.type == :invalid_request
    end

    test "handles HTTP errors when creating static role" do
      config = %{db_name: "mysql", username: "test-user"}

      stub_request_raw(:post, :timeout)

      assert {:error, error} = Database.create_static_role("test-static-role", config)
      assert error.type == :http_error
    end
  end

  describe "read_static_role/2" do
    test "reads static role configuration with rotation period" do
      response_data = %{
        "credential_type" => "password",
        "credential_config" => %{},
        "db_name" => "mysql",
        "username" => "static-user",
        "rotation_statements" => [
          "ALTER USER \"{{name}}\" IDENTIFIED BY '{{password}}';"
        ],
        "rotation_period" => 3600,
        "skip_import_rotation" => false
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/database/static-roles/static-user")
      end)

      assert {:ok, config} = Database.read_static_role("static-user")
      assert config.credential_type == "password"
      assert config.db_name == "mysql"
      assert config.username == "static-user"

      assert config.rotation_statements == [
               "ALTER USER \"{{name}}\" IDENTIFIED BY '{{password}}';"
             ]

      assert config.rotation_period == 3600
      assert config.skip_import_rotation == false
    end

    test "reads static role configuration with rotation schedule" do
      response_data = %{
        "credential_type" => "password",
        "db_name" => "mysql",
        "username" => "static-user",
        "rotation_statements" => [
          "ALTER USER \"{{name}}\" IDENTIFIED BY '{{password}}';"
        ],
        "rotation_schedule" => "0 0 * * SAT",
        "rotation_window" => 3600,
        "skip_import_rotation" => false
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/database/static-roles/scheduled-user")
      end)

      assert {:ok, config} = Database.read_static_role("scheduled-user")
      assert config.rotation_schedule == "0 0 * * SAT"
      assert config.rotation_window == 3600
    end

    test "returns error when static role not found" do
      expect_get(404, %{
        "errors" => ["static role not found"]
      })

      assert {:error, error} = Database.read_static_role("nonexistent")
      assert error.type == :not_found
    end

    test "handles HTTP errors when reading static role" do
      stub_request_raw(:get, :timeout)

      assert {:error, error} = Database.read_static_role("test-static-role")
      assert error.type == :http_error
    end

    test "handles non-200 responses when reading static role" do
      expect_get(500, %{"errors" => ["internal server error"]})

      assert {:error, error} = Database.read_static_role("test-static-role")
      assert error.type == :server_error
    end
  end

  describe "list_static_roles/1" do
    test "lists all static roles successfully" do
      response_data = %{
        "keys" => ["static-user1", "static-user2", "admin-static"]
      }

      expect_any(:list, 200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/database/static-roles")
      end)

      assert {:ok, roles} = Database.list_static_roles()
      assert roles == ["static-user1", "static-user2", "admin-static"]
    end

    test "returns empty list when no static roles exist" do
      response_data = %{
        "keys" => []
      }

      expect_any(:list, 200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/database/static-roles")
      end)

      assert {:ok, roles} = Database.list_static_roles()
      assert roles == []
    end

    test "handles HTTP errors when listing static roles" do
      stub_request_raw(:list, :timeout)

      assert {:error, error} = Database.list_static_roles()
      assert error.type == :http_error
    end

    test "handles non-200 responses when listing static roles" do
      expect_any(:list, 500, %{"errors" => ["internal server error"]})

      assert {:error, error} = Database.list_static_roles()
      assert error.type == :server_error
    end
  end

  describe "delete_static_role/2" do
    test "deletes static role successfully" do
      expect_delete(204, %{}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/database/static-roles/old-static-role")
      end)

      assert :ok = Database.delete_static_role("old-static-role")
    end

    test "handles HTTP errors when deleting static role" do
      stub_request_raw(:delete, :timeout)

      assert {:error, error} = Database.delete_static_role("test-static-role")
      assert error.type == :http_error
    end

    test "handles non-200 responses when deleting static role" do
      expect_delete(400, %{"errors" => ["cannot delete static role"]})

      assert {:error, error} = Database.delete_static_role("test-static-role")
      assert error.type == :invalid_request
    end
  end

  describe "get_static_credentials/2" do
    test "gets static credentials with rotation period" do
      response_data = %{
        "username" => "static-user",
        "password" => "132ae3ef-5a64-7499-351e-bfe59f3a2a21",
        "last_vault_rotation" => "2019-05-06T15:26:42.525302-05:00",
        "rotation_period" => 30,
        "ttl" => 28
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/database/static-creds/static-user")
      end)

      assert {:ok, creds} = Database.get_static_credentials("static-user")
      assert creds.username == "static-user"
      assert creds.password == "132ae3ef-5a64-7499-351e-bfe59f3a2a21"
      assert creds.last_vault_rotation == "2019-05-06T15:26:42.525302-05:00"
      assert creds.rotation_period == 30
      assert creds.ttl == 28
    end

    test "gets static credentials with rotation schedule" do
      response_data = %{
        "username" => "static-user",
        "password" => "132ae3ef-5a64-7499-351e-bfe59f3a2a21",
        "last_vault_rotation" => "2019-05-06T15:26:42.525302-05:00",
        "rotation_schedule" => "0 0 * * SAT",
        "rotation_window" => 3600,
        "ttl" => 5000
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.ends_with?(url, "/v1/database/static-creds/scheduled-user")
      end)

      assert {:ok, creds} = Database.get_static_credentials("scheduled-user")
      assert creds.rotation_schedule == "0 0 * * SAT"
      assert creds.rotation_window == 3600
      assert creds.ttl == 5000
    end

    test "returns error when static role not found" do
      expect_get(404, %{
        "errors" => ["static role not found"]
      })

      assert {:error, error} = Database.get_static_credentials("nonexistent")
      assert error.type == :not_found
    end

    test "handles HTTP errors when getting static credentials" do
      stub_request_raw(:get, :timeout)

      assert {:error, error} = Database.get_static_credentials("test-static-role")
      assert error.type == :http_error
    end

    test "handles non-200 responses when getting static credentials" do
      expect_get(400, %{"errors" => ["static role not configured"]})

      assert {:error, error} = Database.get_static_credentials("test-static-role")
      assert error.type == :invalid_request
    end
  end

  describe "rotate_static_role_credentials/2" do
    test "rotates static role credentials successfully" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.ends_with?(url, "/v1/database/rotate-role/static-user")
        assert body == %{}
      end)

      assert :ok = Database.rotate_static_role_credentials("static-user")
    end

    test "handles HTTP errors when rotating static role credentials" do
      stub_request_raw(:post, :timeout)

      assert {:error, error} = Database.rotate_static_role_credentials("test-static-role")
      assert error.type == :http_error
    end

    test "handles non-200 responses when rotating static role credentials" do
      expect_post(400, %{"errors" => ["cannot rotate static role credentials"]})

      assert {:error, error} = Database.rotate_static_role_credentials("test-static-role")
      assert error.type == :invalid_request
    end
  end
end
