defmodule Vaultx.Secrets.KV.V2Test do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Secrets.KV.V2
  alias Vaultx.Base.Error

  describe "validation error mapping" do
    test "list/2 invalid_characters -> invalid_request" do
      assert {:error, %Error{type: :invalid_request, message: "Path contains invalid characters"}} =
               V2.list("bad path")
    end

    test "list/2 invalid_type -> invalid_request" do
      assert {:error, %Error{type: :invalid_request, message: "Path must be a string"}} =
               V2.list(123)
    end
  end

  describe "read/2" do
    test "parse_datetime fallback on non-string timestamps -> nil" do
      expect_get(
        200,
        %{
          "data" => %{
            "data" => %{"k" => "v"},
            "metadata" => %{
              "version" => 1,
              "created_time" => 123,
              "deletion_time" => 456,
              "destroyed" => false
            }
          }
        },
        assert_url_contains("/v1/secret/data/p")
      )

      assert {:ok, %Vaultx.Secrets.KV.Behaviour.SecretData{created_time: nil, deletion_time: nil}} =
               V2.read("p", mount_path: "secret")
    end

    test "reads latest version successfully" do
      now_iso = DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()

      stub_ok(:get, 200, %{
        "data" => %{
          "data" => %{"key" => "val"},
          "metadata" => %{
            "version" => 2,
            "created_time" => now_iso,
            "deletion_time" => nil,
            "destroyed" => false
          }
        }
      })

      assert {:ok, %Vaultx.Secrets.KV.Behaviour.SecretData{} = s} = V2.read("apps/config")
      assert s.data == %{"key" => "val"}
      assert s.version == 2
      assert %DateTime{} = s.created_time
      assert s.deletion_time == nil
      refute s.destroyed
    end

    test "reads specific version and handles 404" do
      # 404 branch with version param
      stub_ok(:get, 404, %{"errors" => ["version not found"]})

      assert {:error, %Error{type: :not_found}} =
               V2.read("apps/config", version: 99)
    end

    test "unexpected response -> server_error and network error" do
      # use stub so V2.read can retry internally without exhausting expectation count
      stub_ok(:get, 418, %{"errors" => ["teapot"]})

      assert {:error, %Error{type: :server_error}} = V2.read("p")

      # now stub network error
      stub_request_raw(:get, :timeout)

      assert {:error, %Error{type: :network_error}} = V2.read("p")
    end
  end

  describe "write/3" do
    test "writes with CAS and parses response" do
      # capture JSON body to assert CAS option presence
      expect_post(
        200,
        %{
          "data" => %{
            "version" => 3,
            "created_time" => DateTime.utc_now() |> DateTime.to_iso8601(),
            "destroyed" => false
          }
        },
        fn _url, decoded, _opts ->
          assert decoded["options"]["cas"] == 1
          assert decoded["data"]["k"] == "v"
        end
      )

      assert {:ok, %Vaultx.Secrets.KV.Behaviour.WriteResult{version: 3}} =
               V2.write("apps/config", %{"k" => "v"}, cas: 1)
    end

    test "handles 400 errors with cas message and generic" do
      # cas mismatch error mapping
      expect_post(400, %{"errors" => ["check-and-set parameter did not match"]})

      assert {:error, %Error{type: :invalid_request}} = V2.write("p", %{})

      # other error list
      expect_post(400, %{"errors" => ["cannot write to a destroyed version"]})

      assert {:error, %Error{type: :invalid_request}} = V2.write("p", %{})
    end

    test "unexpected and transport errors" do
      stub_ok(:post, 503, %{})

      assert {:error, %Error{type: :server_error}} = V2.write("p", %{})

      stub_request_raw(:post, :econnrefused)

      assert {:error, %Error{type: :network_error}} = V2.write("p", %{})
    end
  end

  describe "undelete/2 and destroy/2 heads" do
    test "undelete/2 success covers function head" do
      expect_post(204, %{}, fn url, decoded, _opts ->
        assert String.contains?(url, "/v1/secret/undelete/p")
        assert decoded["versions"] == [1, 2]
      end)

      assert :ok = V2.undelete("p", versions: [1, 2], mount_path: "secret")
    end

    test "destroy/2 success covers function head" do
      expect_post(204, %{}, fn url, decoded, _opts ->
        assert String.contains?(url, "/v1/secret/destroy/p")
        assert decoded["versions"] == [9]
      end)

      assert :ok = V2.destroy("p", versions: [9], mount_path: "secret")
    end

    test "undelete/2 error when versions missing (covers head defaults)" do
      assert {:error,
              %Error{
                type: :invalid_request,
                message: "Versions list is required for undelete operation"
              }} =
               V2.undelete("p")
    end

    test "destroy/2 error when versions missing (covers head defaults)" do
      assert {:error,
              %Error{
                type: :invalid_request,
                message: "Versions list is required for destroy operation"
              }} =
               V2.destroy("p")
    end
  end

  describe "delete/2" do
    test "deletes latest and specific versions" do
      # delete latest (HTTP.encode_body returns "" for nil)
      expect_post(
        204,
        %{},
        fn url, body, _opts ->
          assert body == ""
          assert String.contains?(url, "/data/")
        end,
        decode: false
      )

      assert :ok = V2.delete("apps/config")

      # delete specific versions
      expect_post(200, %{}, fn url, decoded, _opts ->
        assert String.contains?(url, "/delete/")
        assert decoded["versions"] == [1, 2]
      end)

      assert :ok = V2.delete("apps/config", versions: [1, 2])
    end

    test "delete 404 and network error" do
      expect_post(404, %{})

      assert {:error, %Error{type: :not_found}} = V2.delete("p")

      # Use stub to allow retries without exhausting expectation count
      stub_request_raw(:post, :timeout)

      assert {:error, %Error{type: :network_error}} = V2.delete("p")
    end
  end

  describe "metadata ops" do
    test "read_metadata/2 success and 404" do
      now = DateTime.utc_now() |> DateTime.to_iso8601()

      expect_any(:get, 200, %{"data" => %{"created_time" => now, "deletion_time" => nil}})

      assert {:ok, %Vaultx.Secrets.KV.Behaviour.SecretData{metadata: %{"created_time" => ^now}}} = V2.read_metadata("p")

      expect_any(:get, 404, %{})

      assert {:error, %Error{type: :not_found}} = V2.read_metadata("p")
    end

    test "write_metadata/3 success and network error" do
      expect_post(204, %{})

      assert :ok = V2.write_metadata("p", %{"max_versions" => 10})

      # Use stub because HTTP layer may retry
      stub_request_raw(:post, :timeout)

      assert {:error, %Error{type: :network_error}} = V2.write_metadata("p", %{})
    end

    test "delete_metadata/2 success and 404" do
      expect_delete(200, %{}, fn url, _body, _opts ->
        assert String.contains?(url, "/metadata/")
      end)

      assert :ok = V2.delete_metadata("p")

      expect_delete(404, %{})

      assert {:error, %Error{type: :not_found}} = V2.delete_metadata("p")
    end
  end

  describe "validation and edge cases" do
    test "read/2 validates path and opts; parses nil times on invalid format" do
      # invalid path
      assert {:error, %Error{type: :invalid_request, message: msg}} = V2.read("")
      assert String.contains?(msg, "Path cannot be empty")
      # invalid opts type
      assert {:error, %Error{type: :invalid_request, message: msg}} = V2.read("p", %{})
      assert String.contains?(msg, "Options must be a keyword list")

      # parse_datetime invalid -> nils
      bad_time = "not-an-iso"

      stub_ok(:get, 200, %{
        "data" => %{
          "data" => %{"k" => "v"},
          "metadata" => %{
            "version" => 1,
            "created_time" => bad_time,
            "deletion_time" => bad_time,
            "destroyed" => false
          }
        }
      })

      assert {:ok, %Vaultx.Secrets.KV.Behaviour.SecretData{created_time: nil, deletion_time: nil}} = V2.read("p")
    end

    test "list/2, delete/2 validate opts type" do
      # list maps validation error to Error struct
      assert {:error, %Error{type: :invalid_request}} = V2.list("p", %{})
      # delete also maps validation error to Error struct
      assert {:error, %Error{type: :invalid_request}} = V2.delete("p", %{})
    end

    test "metadata ops validate opts type" do
      assert {:error, %Error{type: :invalid_request}} = V2.read_metadata("p", %{})
      assert {:error, %Error{type: :invalid_request}} = V2.write_metadata("p", %{}, %{})
      assert {:error, %Error{type: :invalid_request}} = V2.delete_metadata("p", %{})
      assert {:error, %Error{type: :invalid_request}} = V2.undelete("p", %{})
      assert {:error, %Error{type: :invalid_request}} = V2.destroy("p", %{})
      assert {:error, %Error{type: :invalid_request}} = V2.list_versions("p", %{})
    end

    test "undelete/2 requires non-empty versions list" do
      assert {:error, %Error{type: :invalid_request, message: message}} =
               V2.undelete("p", versions: [])

      assert String.contains?(message, "Versions list is required")
    end

    test "destroy/2 requires non-empty versions list" do
      assert {:error, %Error{type: :invalid_request, message: message}} =
               V2.destroy("p", versions: [])

      assert String.contains?(message, "Versions list is required")
    end

    test "undelete/2 success and error paths" do
      # Success
      expect_post(200, %{}, fn url, decoded, _opts ->
        assert String.contains?(url, "/undelete/")
        assert decoded["versions"] == [1, 2]
      end)

      assert :ok = V2.undelete("p", versions: [1, 2])

      # 404 error
      expect_post(404, %{})

      assert {:error, %Error{type: :not_found}} = V2.undelete("p", versions: [1])

      # Server error
      expect_post(500, %{"errors" => ["internal error"]})

      assert {:error, %Error{type: :server_error}} = V2.undelete("p", versions: [1])
    end

    test "destroy/2 success and error paths" do
      # Success
      expect_post(204, %{}, fn url, decoded, _opts ->
        assert String.contains?(url, "/destroy/")
        assert decoded["versions"] == [1, 2]
      end)

      assert :ok = V2.destroy("p", versions: [1, 2])

      # 404 error
      expect_post(404, %{})

      assert {:error, %Error{type: :not_found}} = V2.destroy("p", versions: [1])
    end

    test "list_versions/2 success and error paths" do
      # Success
      expect_get(
        200,
        %{
          "data" => %{
            "versions" => %{
              "1" => %{"created_time" => "2025-01-15T00:00:00Z"},
              "3" => %{"created_time" => "2025-01-17T00:00:00Z"}
            }
          }
        },
        fn url, _body, _opts ->
          assert String.contains?(url, "/metadata/")
        end
      )

      assert {:ok, %Vaultx.Secrets.KV.Behaviour.ListResult{keys: ["1", "3"]}} = V2.list_versions("p")

      # 404 error
      expect_get(404, %{})

      assert {:error, %Error{type: :not_found}} = V2.list_versions("p")

      # Server error
      expect_get(500, %{"errors" => ["server error"]})

      assert {:error, %Error{type: :server_error}} = V2.list_versions("p")
    end
  end

  describe "list/2 and list_versions/2" do
    test "list/2 returns keys and errors" do
      expect_get(200, %{"data" => %{"keys" => ["a", "b/"]}}, assert_url_contains("/metadata/"))

      assert {:ok, %Vaultx.Secrets.KV.Behaviour.ListResult{keys: ["a", "b/"]}} = V2.list("p/")

      expect_any(:get, 404, %{})

      assert {:error, %Error{type: :not_found}} = V2.list("missing/")
    end

    test "list_versions/2 builds sorted numeric keys" do
      body = %{"data" => %{"versions" => %{"2" => %{}, "10" => %{}, "1" => %{}}}}

      expect_any(:get, 200, body)

      assert {:ok, %Vaultx.Secrets.KV.Behaviour.ListResult{keys: ["1", "2", "10"]}} = V2.list_versions("p")
    end
  end

  describe "configure/2, metadata/0, health_check/1" do
    test "configure success and error" do
      expect_post(204, %{})

      assert :ok = V2.configure(%{"max_versions" => 5})

      expect_post(500, %{})

      assert {:error, %Error{type: :server_error}} = V2.configure(%{})
    end
  end

  describe "additional kv2 edge branches" do
    test "read/2 404 without version" do
      expect_get(404, %{})

      assert {:error, %Error{type: :not_found}} = V2.read("p")
    end

    test "write/3 handles 400 generic error list" do
      expect_post(400, %{"errors" => ["something else"]})

      assert {:error, %Error{type: :server_error}} = V2.write("p", %{"k" => "v"})
    end

    test "delete/2 unexpected server error" do
      expect_post(500, %{})

      assert {:error, %Error{type: :server_error}} = V2.delete("p")
    end

    test "list/2 server_error and network error" do
      expect_get(500, %{})

      assert {:error, %Error{type: :server_error}} = V2.list("p/")

      stub_request_raw(:get, :timeout)

      assert {:error, %Error{type: :network_error}} = V2.list("p/")
    end

    test "configure/2 network error" do
      stub_request_raw(:post, :timeout)

      assert {:error, %Error{type: :network_error}} = V2.configure(%{"max_versions" => 1})
    end

    test "read_metadata/2 server_error and network error" do
      expect_get(500, %{})

      assert {:error, %Error{type: :server_error}} = V2.read_metadata("p")

      stub_request_raw(:get, :timeout)

      assert {:error, %Error{type: :network_error}} = V2.read_metadata("p")
    end

    test "write_metadata/3 server_error" do
      expect_post(500, %{})

      assert {:error, %Error{type: :server_error}} = V2.write_metadata("p", %{})
    end

    test "delete_metadata/2 server_error and network error" do
      expect_delete(500, %{})

      assert {:error, %Error{type: :server_error}} = V2.delete_metadata("p")

      stub_request_raw(:delete, :timeout)

      assert {:error, %Error{type: :network_error}} = V2.delete_metadata("p")
    end

    test "undelete/2 network error" do
      stub_request_raw(:post, :timeout)

      assert {:error, %Error{type: :network_error}} = V2.undelete("p", versions: [1])
    end

    test "destroy/2 server_error and network error" do
      expect_post(500, %{})

      assert {:error, %Error{type: :server_error}} = V2.destroy("p", versions: [1])

      stub_request_raw(:post, :timeout)

      assert {:error, %Error{type: :network_error}} = V2.destroy("p", versions: [1])
    end

    test "list_versions/2 network error" do
      stub_request_raw(:get, :timeout)

      assert {:error, %Error{type: :network_error}} = V2.list_versions("p")
    end

    test "write/3 validates data must be a map" do
      assert {:error, %Error{type: :invalid_request}} = V2.write("p", "not-a-map")
    end

    test "write_metadata/3 validates metadata must be a map" do
      assert {:error, %Error{type: :invalid_request}} = V2.write_metadata("p", "not-a-map")
    end

    test "list/2 invalid path is mapped to Error" do
      assert {:error, %Error{type: :invalid_request}} = V2.list("")
    end
  end
end
