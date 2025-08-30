defmodule Vaultx.Sys.NamespacesTest do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Sys.Namespaces
  alias Vaultx.Base.Error

  # Sample namespace responses
  @namespace_list %{
    "data" => %{
      "keys" => ["development/", "production/", "staging/"],
      "key_info" => %{
        "development/" => %{
          "id" => "dev-123",
          "custom_metadata" => %{"team" => "dev", "environment" => "dev"}
        },
        "production/" => %{
          "id" => "prod-456",
          "custom_metadata" => %{"team" => "ops", "environment" => "prod"}
        },
        "staging/" => %{
          "id" => "stage-789",
          "custom_metadata" => %{"team" => "qa", "environment" => "staging"}
        }
      }
    }
  }

  @namespace_info %{
    "id" => "prod-456",
    "path" => "production/",
    "custom_metadata" => %{
      "team" => "ops",
      "environment" => "prod",
      "contact" => "ops@company.com"
    }
  }

  @empty_namespace_list %{
    "data" => %{
      "keys" => [],
      "key_info" => %{}
    }
  }

  describe "list/1" do
    test "lists namespaces successfully" do
      expect_get(200, @namespace_list, fn url, _body, opts ->
        assert String.contains?(url, "sys/namespaces")
        assert opts[:method] == "LIST"
      end)

      assert {:ok, namespaces} = Namespaces.list()
      assert namespaces.keys == ["development/", "production/", "staging/"]
      assert Map.has_key?(namespaces.key_info, "development/")
      assert namespaces.key_info["development/"]["id"] == "dev-123"
      assert namespaces.key_info["production/"]["custom_metadata"]["team"] == "ops"
    end

    test "handles empty namespace list" do
      expect_get(200, @empty_namespace_list, fn url, _body, opts ->
        assert String.contains?(url, "sys/namespaces")
        assert opts[:method] == "LIST"
      end)

      assert {:ok, namespaces} = Namespaces.list()
      assert namespaces.keys == []
      assert namespaces.key_info == %{}
    end

    test "handles missing data fields" do
      minimal_response = %{"data" => %{}}

      expect_get(200, minimal_response, fn _url, _body, opts ->
        assert opts[:method] == "LIST"
      end)

      assert {:ok, namespaces} = Namespaces.list()
      assert namespaces.keys == []
      assert namespaces.key_info == %{}
    end

    test "handles server errors" do
      expect_get(403, %{"errors" => ["permission denied"]})

      assert {:error, %Error{} = error} = Namespaces.list()
      assert error.type == :server_error
      assert String.contains?(error.message, "Failed to list namespaces")
    end

    test "handles network errors" do
      stub_request_raw(:get, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{} = error} = Namespaces.list()
      assert error.type == :unknown_error
    end

    test "passes custom options" do
      expect_get(200, @namespace_list, fn _url, _body, opts ->
        assert opts[:timeout] == 30_000
        assert opts[:method] == "LIST"
      end)

      assert {:ok, _namespaces} = Namespaces.list(timeout: 30_000)
    end
  end

  describe "create/3" do
    test "creates namespace without metadata" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/namespaces/development")
        assert body["custom_metadata"] == %{}
      end)

      assert {:ok, response} = Namespaces.create("development")
      assert response.status == 204
    end

    test "creates namespace with metadata" do
      metadata = %{
        "team" => "platform",
        "environment" => "prod",
        "contact" => "ops@company.com"
      }

      expect_post(200, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/namespaces/production")
        assert body["custom_metadata"] == metadata
      end)

      assert {:ok, response} = Namespaces.create("production", metadata)
      assert response.status == 200
    end

    test "handles creation errors" do
      expect_post(400, %{"errors" => ["invalid namespace path"]})

      assert {:error, %Error{} = error} = Namespaces.create("invalid/path")
      assert error.type == :server_error
      assert String.contains?(error.message, "Failed to create namespace")
      assert error.details.namespace_path == "invalid/path"
    end

    test "handles network errors" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{} = error} = Namespaces.create("test")
      assert error.type == :unknown_error
    end

    test "passes custom options" do
      expect_post(204, %{}, fn _url, _body, opts ->
        assert opts[:timeout] == 45_000
      end)

      assert {:ok, _response} = Namespaces.create("test", %{}, timeout: 45_000)
    end
  end

  describe "read/2" do
    test "reads namespace information successfully" do
      expect_get(200, @namespace_info, fn url, _body, _opts ->
        assert String.contains?(url, "sys/namespaces/production")
      end)

      assert {:ok, info} = Namespaces.read("production")
      assert info.id == "prod-456"
      assert info.path == "production/"
      assert info.custom_metadata["team"] == "ops"
      assert info.custom_metadata["environment"] == "prod"
      assert info.custom_metadata["contact"] == "ops@company.com"
    end

    test "handles missing custom metadata" do
      minimal_info = %{
        "id" => "test-123",
        "path" => "test/"
      }

      expect_get(200, minimal_info, fn _url, _body, _opts ->
        :ok
      end)

      assert {:ok, info} = Namespaces.read("test")
      assert info.id == "test-123"
      assert info.path == "test/"
      assert info.custom_metadata == %{}
    end

    test "handles namespace not found" do
      expect_get(404, %{"errors" => ["namespace not found"]})

      assert {:error, %Error{} = error} = Namespaces.read("nonexistent")
      assert error.type == :server_error
      assert String.contains?(error.message, "Failed to read namespace")
      assert error.details.namespace_path == "nonexistent"
    end

    test "handles server errors" do
      expect_get(500, %{"errors" => ["internal server error"]})

      assert {:error, %Error{} = error} = Namespaces.read("production")
      assert error.type == :server_error
    end

    test "handles network errors" do
      stub_request_raw(:get, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{} = error} = Namespaces.read("production")
      assert error.type == :unknown_error
    end

    test "passes custom options" do
      expect_get(200, @namespace_info, fn _url, _body, opts ->
        assert opts[:timeout] == 20_000
      end)

      assert {:ok, _info} = Namespaces.read("production", timeout: 20_000)
    end
  end

  describe "update/3" do
    test "updates namespace metadata successfully" do
      new_metadata = %{
        "team" => "platform",
        "environment" => "production",
        "updated_at" => "2025-03-26T15:00:00Z"
      }

      expect_post(200, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/namespaces/production")
        assert body["custom_metadata"] == new_metadata
      end)

      assert {:ok, response} = Namespaces.update("production", new_metadata)
      assert response.status == 200
    end

    test "handles update errors" do
      expect_post(404, %{"errors" => ["namespace not found"]})

      assert {:error, %Error{} = error} = Namespaces.update("nonexistent", %{})
      assert error.type == :server_error
      assert String.contains?(error.message, "Failed to update namespace")
      assert error.details.namespace_path == "nonexistent"
    end

    test "handles network errors" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{} = error} = Namespaces.update("production", %{})
      assert error.type == :unknown_error
    end

    test "passes custom options" do
      expect_post(204, %{}, fn _url, _body, opts ->
        assert opts[:timeout] == 25_000
      end)

      assert {:ok, _response} = Namespaces.update("test", %{}, timeout: 25_000)
    end
  end

  describe "delete/2" do
    test "deletes namespace successfully" do
      expect_delete(204, %{}, fn url, _body, _opts ->
        assert String.contains?(url, "sys/namespaces/old-project")
      end)

      assert {:ok, response} = Namespaces.delete("old-project")
      assert response.status == 204
    end

    test "handles delete errors" do
      expect_delete(404, %{"errors" => ["namespace not found"]})

      assert {:error, %Error{} = error} = Namespaces.delete("nonexistent")
      assert error.type == :server_error
      assert String.contains?(error.message, "Failed to delete namespace")
      assert error.details.namespace_path == "nonexistent"
    end

    test "handles network errors" do
      stub_request_raw(:delete, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{} = error} = Namespaces.delete("test")
      assert error.type == :unknown_error
    end

    test "passes custom options" do
      expect_delete(200, %{}, fn _url, _body, opts ->
        assert opts[:timeout] == 35_000
      end)

      assert {:ok, _response} = Namespaces.delete("test", timeout: 35_000)
    end
  end

  describe "exists?/2" do
    test "returns true when namespace exists" do
      expect_get(200, @namespace_info, fn _url, _body, _opts ->
        :ok
      end)

      assert {:ok, true} = Namespaces.exists?("production")
    end

    test "returns false when namespace does not exist" do
      expect_get(404, %{"errors" => ["namespace not found"]})

      assert {:ok, false} = Namespaces.exists?("nonexistent")
    end

    test "handles other errors" do
      expect_get(500, %{"errors" => ["internal server error"]})

      assert {:error, %Error{} = error} = Namespaces.exists?("production")
      assert error.type == :server_error
    end

    test "passes custom options" do
      expect_get(200, @namespace_info, fn _url, _body, opts ->
        assert opts[:timeout] == 15_000
      end)

      assert {:ok, true} = Namespaces.exists?("production", timeout: 15_000)
    end
  end

  describe "list_names/1" do
    test "returns list of namespace names" do
      expect_get(200, @namespace_list, fn _url, _body, opts ->
        assert opts[:method] == "LIST"
      end)

      assert {:ok, names} = Namespaces.list_names()
      assert names == ["development/", "production/", "staging/"]
    end

    test "returns empty list when no namespaces" do
      expect_get(200, @empty_namespace_list, fn _url, _body, opts ->
        assert opts[:method] == "LIST"
      end)

      assert {:ok, names} = Namespaces.list_names()
      assert names == []
    end

    test "handles errors from list operation" do
      expect_get(403, %{"errors" => ["permission denied"]})

      assert {:error, %Error{} = error} = Namespaces.list_names()
      assert error.type == :server_error
    end

    test "passes custom options" do
      expect_get(200, @namespace_list, fn _url, _body, opts ->
        assert opts[:timeout] == 10_000
        assert opts[:method] == "LIST"
      end)

      assert {:ok, _names} = Namespaces.list_names(timeout: 10_000)
    end
  end

  describe "edge cases and error scenarios" do
    test "handles malformed JSON response" do
      expect_get(200, "invalid json")

      assert {:error, %Error{} = error} = Namespaces.list()
      assert error.type == :server_error
    end

    test "handles various HTTP error codes" do
      error_codes = [400, 401, 403, 404, 500, 502, 503]

      Enum.each(error_codes, fn code ->
        expect_get(code, %{"errors" => ["error #{code}"]})

        assert {:error, %Error{} = error} = Namespaces.list()
        assert error.type == :server_error
        assert String.contains?(error.message, "HTTP #{code}")
      end)
    end

    test "handles unicode namespace names" do
      unicode_metadata = %{"description" => "测试命名空间"}

      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/namespaces/测试")
        assert body["custom_metadata"] == unicode_metadata
      end)

      assert {:ok, _response} = Namespaces.create("测试", unicode_metadata)
    end

    test "handles empty metadata maps" do
      expect_post(204, %{}, fn _url, body, _opts ->
        assert body["custom_metadata"] == %{}
      end)

      assert {:ok, _response} = Namespaces.create("test", %{})
    end

    test "handles large metadata maps" do
      large_metadata =
        1..100
        |> Enum.map(fn i -> {"key_#{i}", "value_#{i}"} end)
        |> Enum.into(%{})

      expect_post(204, %{}, fn _url, body, _opts ->
        assert body["custom_metadata"] == large_metadata
      end)

      assert {:ok, _response} = Namespaces.create("test", large_metadata)
    end
  end

  describe "integration scenarios" do
    test "complete namespace lifecycle" do
      namespace_path = "test-project"
      initial_metadata = %{"team" => "dev", "environment" => "test"}
      updated_metadata = %{"team" => "dev", "environment" => "test", "status" => "active"}

      # Step 1: Create namespace
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/namespaces/#{namespace_path}")
        assert body["custom_metadata"] == initial_metadata
      end)

      assert {:ok, _} = Namespaces.create(namespace_path, initial_metadata)

      # Step 2: Read namespace
      namespace_info = %{
        "id" => "test-123",
        "path" => "#{namespace_path}/",
        "custom_metadata" => initial_metadata
      }

      expect_get(200, namespace_info, fn url, _body, _opts ->
        assert String.contains?(url, "sys/namespaces/#{namespace_path}")
      end)

      assert {:ok, info} = Namespaces.read(namespace_path)
      assert info.custom_metadata == initial_metadata

      # Step 3: Update namespace
      expect_post(200, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/namespaces/#{namespace_path}")
        assert body["custom_metadata"] == updated_metadata
      end)

      assert {:ok, _} = Namespaces.update(namespace_path, updated_metadata)

      # Step 4: Verify existence
      updated_info = %{namespace_info | "custom_metadata" => updated_metadata}

      expect_get(200, updated_info, fn _url, _body, _opts ->
        :ok
      end)

      assert {:ok, true} = Namespaces.exists?(namespace_path)

      # Step 5: Delete namespace
      expect_delete(204, %{}, fn url, _body, _opts ->
        assert String.contains?(url, "sys/namespaces/#{namespace_path}")
      end)

      assert {:ok, _} = Namespaces.delete(namespace_path)
    end

    test "namespace discovery workflow" do
      # Step 1: List all namespaces
      expect_get(200, @namespace_list, fn _url, _body, opts ->
        assert opts[:method] == "LIST"
      end)

      assert {:ok, namespaces} = Namespaces.list()
      assert length(namespaces.keys) == 3

      # Step 2: Get just names
      expect_get(200, @namespace_list, fn _url, _body, opts ->
        assert opts[:method] == "LIST"
      end)

      assert {:ok, names} = Namespaces.list_names()
      assert names == ["development/", "production/", "staging/"]

      # Step 3: Read details for each namespace
      Enum.each(["development", "production", "staging"], fn ns ->
        expect_get(200, @namespace_info, fn url, _body, _opts ->
          assert String.contains?(url, "sys/namespaces/#{ns}")
        end)

        assert {:ok, _info} = Namespaces.read(ns)
      end)
    end

    test "error handling across all operations" do
      # All operations should handle errors consistently
      expect_get(500, %{"errors" => ["server error"]})
      assert {:error, %Error{type: :server_error}} = Namespaces.list()

      expect_post(500, %{"errors" => ["server error"]})
      assert {:error, %Error{type: :server_error}} = Namespaces.create("test")

      expect_get(500, %{"errors" => ["server error"]})
      assert {:error, %Error{type: :server_error}} = Namespaces.read("test")

      expect_post(500, %{"errors" => ["server error"]})
      assert {:error, %Error{type: :server_error}} = Namespaces.update("test", %{})

      expect_delete(500, %{"errors" => ["server error"]})
      assert {:error, %Error{type: :server_error}} = Namespaces.delete("test")

      expect_get(500, %{"errors" => ["server error"]})
      assert {:error, %Error{type: :server_error}} = Namespaces.exists?("test")

      expect_get(500, %{"errors" => ["server error"]})
      assert {:error, %Error{type: :server_error}} = Namespaces.list_names()
    end
  end
end
