defmodule Vaultx.Secrets.KV.V1Test do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Secrets.KV.V1
  alias Vaultx.Base.Error

  describe "read/2" do
    test "reads secret successfully" do
      # HTTP client returns Vault shape: {status, body: %{"data" => data}}
      expect_get(200, %{"data" => %{"username" => "admin"}})

      assert {:ok, secret} = V1.read("myapp/config")
      assert %{data: %{"username" => "admin"}} = secret
      assert secret.version == nil
      assert secret.metadata == nil
      refute secret.destroyed
    end

    test "returns not_found error on 404" do
      expect_get(404, %{"errors" => ["not found"]})

      assert {:error, %Error{type: :not_found}} = V1.read("missing/path")
    end

    test "returns server_error on unexpected status" do
      expect_get(500, %{"errors" => ["boom"]})

      assert {:error, %Error{type: :server_error}} = V1.read("myapp/config")
    end

    test "wraps network error" do
      stub_request_raw(:get, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{type: :network_error}} = V1.read("myapp/config")
    end
  end

  describe "write/3" do
    test "writes secret successfully" do
      expect_post(200, %{})

      assert {:ok, res} = V1.write("myapp/config", %{"k" => "v"})

      assert res.version == nil
      refute res.destroyed
    end

    test "returns error on non-map data" do
      assert {:error, %Error{type: :invalid_request}} = V1.write("path", [1, 2, 3])
    end

    test "returns server_error on unexpected status (400+)" do
      expect_post(422, %{"errors" => ["invalid"]})

      assert {:error, %Error{type: :server_error}} =
               V1.write("myapp/config", %{"k" => "v"})
    end

    test "wraps network error" do
      stub_request_raw(:post, :nxdomain)

      assert {:error, %Error{type: :network_error}} =
               V1.write("myapp/config", %{})
    end
  end

  describe "delete/2" do
    test "deletes secret successfully" do
      stub_ok(:delete, 204, %{})

      assert :ok = V1.delete("myapp/config")
    end

    test "returns not_found when deleting missing secret" do
      stub_ok(:delete, 404, %{"errors" => ["not found"]})

      assert {:error, %Error{type: :not_found}} = V1.delete("myapp/config")
    end

    test "returns server_error on unexpected status" do
      stub_ok(:delete, 500, %{"errors" => ["boom"]})

      assert {:error, %Error{type: :server_error}} = V1.delete("myapp/config")
    end

    test "wraps network error" do
      stub_request_raw(:delete, %Req.TransportError{reason: :econnrefused})

      assert {:error, %Error{type: :network_error}} = V1.delete("myapp/config")
    end
  end

  describe "validation error mapping" do
    test "list/2 invalid_type -> invalid_request" do
      assert {:error, %Error{type: :invalid_request, message: "Path must be a string"}} =
               V1.list(123)
    end

    test "list/2 invalid_characters -> invalid_request" do
      assert {:error, %Error{type: :invalid_request, message: "Path contains invalid characters"}} =
               V1.list("bad path")
    end

    test "read/2 invalid_characters -> invalid_request" do
      assert {:error, %Error{type: :invalid_request, message: "Path contains invalid characters"}} =
               V1.read("bad path")
    end

    test "write/3 invalid_characters -> invalid_request" do
      assert {:error, %Error{type: :invalid_request, message: "Path contains invalid characters"}} =
               V1.write("bad path", %{})
    end

    test "write/3 invalid_type -> invalid_request" do
      assert {:error, %Error{type: :invalid_request, message: "Path must be a string"}} =
               V1.write(123, %{})
    end

    test "delete/2 invalid_characters -> invalid_request" do
      assert {:error, %Error{type: :invalid_request, message: "Path contains invalid characters"}} =
               V1.delete("bad path")
    end

    test "delete/2 invalid_type -> invalid_request" do
      assert {:error, %Error{type: :invalid_request, message: "Path must be a string"}} =
               V1.delete(123)
    end
  end

  describe "list/2" do
    test "lists keys successfully" do
      stub_ok(:get, 200, %{"data" => %{"keys" => ["a", "b/"]}})

      assert {:ok, %{keys: ["a", "b/"]}} = V1.list("myapp/")
    end

    test "returns not_found on 404" do
      stub_ok(:get, 404, %{"errors" => ["not found"]})

      assert {:error, %Error{type: :not_found}} = V1.list("missing/")
    end

    test "returns server_error on unexpected status" do
      stub_ok(:get, 502, %{"errors" => ["bad gateway"]})

      assert {:error, %Error{type: :server_error}} = V1.list("myapp/")
    end

    test "wraps network error" do
      stub_request_raw(:get, :timeout)

      assert {:error, %Error{type: :network_error}} = V1.list("myapp/")
    end
  end

  describe "unsupported KV v1 operations" do
    test "metadata operations not implemented" do
      assert {:error, %Error{type: :not_implemented}} = V1.read_metadata("p", [])
      assert {:error, %Error{type: :not_implemented}} = V1.write_metadata("p", %{}, [])
      assert {:error, %Error{type: :not_implemented}} = V1.delete_metadata("p", [])
    end

    test "versioning operations not implemented" do
      assert {:error, %Error{type: :not_implemented}} = V1.undelete("p", [])
      assert {:error, %Error{type: :not_implemented}} = V1.destroy("p", [])
      assert {:error, %Error{type: :not_implemented}} = V1.list_versions("p", [])
    end

    test "configure not implemented" do
      assert {:error, %Error{type: :not_implemented}} = V1.configure(%{}, [])
    end
  end

  describe "validation error handling" do
    test "read/2 handles validation errors" do
      # Test empty path
      assert {:error, %Error{type: :invalid_request, message: msg}} = V1.read("", [])
      assert String.contains?(msg, "Path cannot be empty")

      # Test non-string path
      assert {:error, %Error{type: :invalid_request, message: msg}} = V1.read(123, [])
      assert String.contains?(msg, "string")

      # Test invalid options
      assert {:error, %Error{type: :invalid_request, message: msg}} = V1.read("path", "invalid")
      assert String.contains?(msg, "keyword")
    end

    test "write/3 handles validation errors" do
      # Test invalid secret data
      assert {:error, %Error{type: :invalid_request, message: msg}} =
               V1.write("path", "invalid", [])

      assert String.contains?(msg, "Secret data must be a map")

      # Test path validation
      assert {:error, %Error{type: :invalid_request}} = V1.write("", %{"key" => "value"}, [])

      # Test invalid options
      assert {:error, %Error{type: :invalid_request}} =
               V1.write("path", %{"key" => "value"}, "invalid")
    end

    test "delete/2 handles validation errors" do
      assert {:error, %Error{type: :invalid_request}} = V1.delete("", [])
      assert {:error, %Error{type: :invalid_request}} = V1.delete("path", "invalid")
    end

    test "list/2 handles validation errors" do
      assert {:error, %Error{type: :invalid_request}} = V1.list("", [])
      assert {:error, %Error{type: :invalid_request}} = V1.list("path", "invalid")
    end
  end

  describe "edge cases and error paths" do
    test "read/2 handles different validation error types" do
      # Test different validation error atoms that get mapped to Error structs
      assert {:error, %Error{type: :invalid_request, message: msg}} = V1.read("", [])
      assert String.contains?(msg, "empty")

      assert {:error, %Error{type: :invalid_request, message: msg}} = V1.read(nil, [])
      assert String.contains?(msg, "string")

      assert {:error, %Error{type: :invalid_request, message: msg}} =
               V1.read("test", %{invalid: true})

      assert String.contains?(msg, "keyword")
    end

    test "write/3 handles Error struct passthrough" do
      # Test the else clause that handles Error structs directly
      # This happens when validate_secret_data returns an Error struct
      assert {:error, %Error{type: :invalid_request, message: msg}} =
               V1.write("path", [], [])

      assert String.contains?(msg, "map")
    end
  end
end
