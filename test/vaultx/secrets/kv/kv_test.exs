defmodule Vaultx.Secrets.KV.KVTest do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Secrets.KV
  alias Vaultx.Base.Error
  alias Vaultx.Types

  describe "detect_kv_version/2 and cache" do
    test "detects via /sys/mounts with explicit version and caches" do
      # First call: /v1/sys/mounts returns kv v2 (use stub to avoid retry backoff)
      expect_get(200, %{
        "data" => %{"secret/" => %{"type" => "kv", "options" => %{"version" => "2"}}}
      })

      assert {:ok, 2} = KV.detect_kv_version("secret")

      # Second call should use ETS cache and not call HTTP
      assert {:ok, 2} = KV.detect_kv_version("secret")
    end

    test "kv engine without version defaults to v2" do
      expect_get(200, %{"data" => %{"secret/" => %{"type" => "kv"}}})

      assert {:ok, 2} = KV.detect_kv_version("secret")
    end

    test "mount not found returns error" do
      expect_get(200, %{"data" => %{}})

      assert {:error, %Error{type: :not_found}} = KV.detect_kv_version("missing")
    end

    test "invalid version string falls back to API behavior detection -> v2" do
      # mounts returns invalid version
      expect_get(200, %{
        "data" => %{"secret/" => %{"type" => "kv", "options" => %{"version" => "invalid"}}}
      })

      # API behavior detection: config endpoint returns 200 -> v2
      expect_get(200, %{})

      assert {:ok, 2} = KV.detect_kv_version("secret")
    end

    test "invalid version string falls back to API behavior detection -> v1" do
      # mounts returns invalid version
      expect_get(200, %{
        "data" => %{"secret/" => %{"type" => "kv", "options" => %{"version" => "invalid"}}}
      })

      # API behavior detection: config endpoint returns 404 -> v1
      expect_get(404, %{})

      assert {:ok, 1} = KV.detect_kv_version("secret")
    end

    test "non-kv engine type falls back to API behavior detection -> v2" do
      # mounts returns non-kv engine type
      expect_get(200, %{
        "data" => %{"secret/" => %{"type" => "database"}}
      })

      # API behavior detection: config endpoint returns 200 -> v2
      expect_get(200, %{})

      assert {:ok, 2} = KV.detect_kv_version("secret")
    end

    test "non-kv engine type falls back to API behavior detection -> v1" do
      # mounts returns non-kv engine type
      expect_get(200, %{
        "data" => %{"secret/" => %{"type" => "database"}}
      })

      # API behavior detection: config endpoint returns 404 -> v1
      expect_get(404, %{})

      assert {:ok, 1} = KV.detect_kv_version("secret")
    end

    test "clear_version_cache/1 clears specific and all" do
      # Seed cache
      expect_get(200, %{
        "data" => %{"secret/" => %{"type" => "kv", "options" => %{"version" => "2"}}}
      })

      assert {:ok, 2} = KV.detect_kv_version("secret")

      assert :ok = KV.clear_version_cache("secret")
      assert :ok = KV.clear_version_cache(:all)
    end
  end

  describe "with_version_detection delegates to correct engine" do
    test "read/write/list/delete work with v1 mount" do
      # 1) detect v1 via /sys/mounts (version=1)
      expect_get(
        200,
        %{"data" => %{"kv1/" => %{"type" => "kv", "options" => %{"version" => "1"}}}},
        fn url, _body, _opts ->
          assert String.contains?(url, "/sys/mounts")
        end
      )

      # 2) read
      expect_get(200, %{"data" => %{"x" => "1"}}, fn url, _body, _opts ->
        assert String.contains?(url, "/v1/kv1/")
      end)

      assert {:ok, %Types.SecretData{data: %{"x" => "1"}}} = KV.read("app/x", mount_path: "kv1")

      # 3) write
      expect_post(200, %{})

      assert {:ok, _} = KV.write("app/x", %{"x" => "1"}, mount_path: "kv1")

      # 4) list
      expect_get(200, %{"data" => %{"keys" => ["a/"]}})

      assert {:ok, %Types.ListResult{keys: ["a/"]}} = KV.list("app/", mount_path: "kv1")

      # 5) delete
      expect_delete(204, %{})

      assert :ok = KV.delete("app/x", mount_path: "kv1")
    end

    test "write_metadata/3 head with default opts (no opts passed)" do
      # default mount_path should be used; still route to v2 after mounts
      expect_get(
        200,
        %{
          "data" => %{"secret/" => %{"type" => "kv", "options" => %{"version" => "2"}}}
        },
        assert_url_contains("/sys/mounts")
      )

      expect_post(204, %{}, fn url, decoded, _opts ->
        assert String.contains?(url, "/v1/secret/metadata/p")
        assert decoded["max_versions"] == 5
      end)

      assert :ok = KV.write_metadata("p", %{"max_versions" => 5})
    end

    test "write_metadata delegates to v2 (covers kv.ex write_metadata/3 head)" do
      # 1) detect v2 via /sys/mounts
      expect_get(
        200,
        %{
          "data" => %{"secret/" => %{"type" => "kv", "options" => %{"version" => "2"}}}
        },
        assert_url_contains("/sys/mounts")
      )

      # 2) forward to V2.write_metadata
      expect_post(204, %{}, fn url, decoded, _opts ->
        assert String.contains?(url, "/v1/secret/metadata/p")
        assert decoded["max_versions"] == 5
      end)

      assert :ok = KV.write_metadata("p", %{"max_versions" => 5}, mount_path: "secret")
    end

    test "v2-only operations route when v2 detected" do
      # detect v2 via /config 200
      expect_get(
        200,
        %{
          "data" => %{"secret/" => %{"type" => "kv", "options" => %{"version" => "2"}}}
        },
        assert_url_contains("/sys/mounts")
      )

      # read_metadata
      expect_get(200, %{"data" => %{}})

      assert {:ok, %Types.SecretData{}} =
               KV.read_metadata("p", mount_path: "secret")

      # undelete
      expect_post(204, %{}, fn url, decoded, _opts ->
        assert String.contains?(url, "/undelete/")
        assert decoded["versions"] == [1]
      end)

      assert :ok = KV.undelete("p", versions: [1], mount_path: "secret")

      # list_versions
      expect_get(200, %{"data" => %{"versions" => %{}}})

      assert {:ok, %Types.ListResult{}} =
               KV.list_versions("p", mount_path: "secret")
    end

    test "health_check delegates to proper engine and error path returns healthy: false" do
      # version detection fails -> health_check returns healthy: false
      stub_request_raw(:get, :timeout)

      assert {:ok, %Types.HealthStatus{healthy: false}} = KV.health_check(mount_path: "secret")
    end
  end

  describe "KV module extras" do
    test "metadata/0 returns auto_detection capability" do
      assert {:ok, %Types.EngineMetadata{type: :kv, version: nil, capabilities: caps}} =
               KV.metadata()

      assert :auto_detection in caps
    end

    test "with_version_detection error path bubbles up on read/2" do
      # make version detection fail: mounts error and config error
      stub_request_raw(:get, :econnrefused)

      assert {:error, %Error{type: :unknown_error}} = KV.read("app/x", mount_path: "secret")
    end

    test "configure/2 delegates to v2 when detected" do
      # mounts -> v2
      expect_get(
        200,
        %{
          "data" => %{"secret/" => %{"type" => "kv", "options" => %{"version" => "2"}}}
        },
        assert_url_contains("/sys/mounts")
      )

      # V2.configure -> POST /config
      expect_post(204, %{}, assert_url_contains("/v1/secret/config"))

      assert :ok = KV.configure(%{"max_versions" => 3}, mount_path: "secret")
    end
  end

  describe "additional detection and delegation coverage" do
    test "detect_kv_version via config 200 -> v2" do
      stub_ok(:get, 200, %{}, fn url, _body, _opts ->
        if String.contains?(url, "/sys/mounts") do
          ok_resp(418, %{})
        else
          assert String.contains?(url, "/v1/secret/config")
          ok_resp(200, %{})
        end
      end)

      assert {:ok, 2} = KV.detect_kv_version("secret")
    end

    test "detect_kv_version defaults to v1 on uncertain config status" do
      stub_ok(:get, 500, %{}, fn url, _body, _opts ->
        if String.contains?(url, "/sys/mounts") do
          ok_resp(418, %{})
        else
          ok_resp(500, %{})
        end
      end)

      assert {:ok, 1} = KV.detect_kv_version("secret")
    end

    test "invalid version string in mounts falls back to API behavior" do
      stub_ok(:get, 404, %{}, fn url, _body, _opts ->
        if String.contains?(url, "/sys/mounts") do
          ok_resp(200, %{
            "data" => %{"secret/" => %{"type" => "kv", "options" => %{"version" => "invalid"}}}
          })
        else
          ok_resp(404, %{})
        end
      end)

      assert {:ok, 1} = KV.detect_kv_version("secret")
    end

    test "non-kv engine type falls back then v2 via config" do
      stub_ok(:get, 200, %{}, fn url, _body, _opts ->
        if String.contains?(url, "/sys/mounts") do
          ok_resp(200, %{"data" => %{"secret/" => %{"type" => "database"}}})
        else
          ok_resp(200, %{})
        end
      end)

      assert {:ok, 2} = KV.detect_kv_version("secret")
    end

    test "delegates write_metadata/delete_metadata/destroy to v2 when detected" do
      # Mock version detection -> v2
      expect_get(
        200,
        %{"data" => %{"secret/" => %{"type" => "kv", "options" => %{"version" => "2"}}}},
        fn url, _body, _opts ->
          assert String.contains?(url, "/sys/mounts")
        end
      )

      # Mock write_metadata
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "/v1/secret/metadata/p")
        assert body["max_versions"] == 10
      end)

      # Mock delete_metadata
      expect_delete(200, %{}, fn url, _body, _opts ->
        assert String.contains?(url, "/v1/secret/metadata/p")
      end)

      # Mock destroy
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "/v1/secret/destroy/p")
        assert body["versions"] == [1]
      end)

      assert :ok = KV.write_metadata("p", %{"max_versions" => 10}, mount_path: "secret")
      assert :ok = KV.delete_metadata("p", mount_path: "secret")
      assert :ok = KV.destroy("p", versions: [1], mount_path: "secret")
    end

    test "health_check ok branch when version detected" do
      stub_ok(
        :get,
        200,
        %{
          "data" => %{"secret/" => %{"type" => "kv", "options" => %{"version" => "2"}}}
        },
        fn url, _body, _opts ->
          cond do
            String.contains?(url, "/sys/mounts") ->
              ok_resp(200, %{
                "data" => %{"secret/" => %{"type" => "kv", "options" => %{"version" => "2"}}}
              })

            String.contains?(url, "/v1/secret/config") ->
              ok_resp(200, %{})

            true ->
              ok_resp(500, %{})
          end
        end
      )

      assert {:ok, %Types.HealthStatus{healthy: true}} = KV.health_check(mount_path: "secret")
    end
  end

  describe "convenience functions" do
    test "read_version/3 reads specific version" do
      # Mock version detection -> v2
      expect_get(
        200,
        %{"data" => %{"secret/" => %{"type" => "kv", "options" => %{"version" => "2"}}}},
        fn url, _body, _opts ->
          assert String.contains?(url, "/sys/mounts")
        end
      )

      # Mock read with version parameter
      expect_get(
        200,
        %{
          "data" => %{
            "data" => %{"key" => "value"},
            "metadata" => %{"version" => 2}
          }
        },
        fn url, _body, _opts ->
          assert String.contains?(url, "/v1/secret/data/test")
          # Version parameter is encoded directly in the URL
          assert String.contains?(url, "version=2")
        end
      )

      assert {:ok, %Types.SecretData{data: %{"key" => "value"}}} =
               KV.read_version("test", 2, mount_path: "secret")
    end

    test "read_version/2 with default opts (covers function head with default args)" do
      # Mock version detection -> v2
      expect_get(
        200,
        %{"data" => %{"secret/" => %{"type" => "kv", "options" => %{"version" => "2"}}}},
        fn url, _body, _opts ->
          assert String.contains?(url, "/sys/mounts")
        end
      )

      # Mock read with version parameter
      expect_get(
        200,
        %{
          "data" => %{
            "data" => %{"key" => "value"},
            "metadata" => %{"version" => 2}
          }
        },
        fn url, _body, _opts ->
          assert String.contains?(url, "/v1/secret/data/test")
          assert String.contains?(url, "version=2")
        end
      )

      # Call with only 2 args to trigger the default opts clause
      assert {:ok, %Types.SecretData{data: %{"key" => "value"}}} =
               KV.read_version("test", 2)
    end

    test "write_cas/4 writes with CAS parameter" do
      # Mock version detection -> v2
      expect_get(
        200,
        %{"data" => %{"secret/" => %{"type" => "kv", "options" => %{"version" => "2"}}}},
        fn url, _body, _opts ->
          assert String.contains?(url, "/sys/mounts")
        end
      )

      # Mock write with CAS parameter
      expect_post(
        200,
        %{
          "data" => %{
            "version" => 2,
            "created_time" => "2025-01-15T00:00:00Z"
          }
        },
        fn url, body, _opts ->
          assert String.contains?(url, "/v1/secret/data/test")
          assert body["options"]["cas"] == 1
          assert body["data"] == %{"key" => "value"}
        end
      )

      assert {:ok, %Types.WriteResult{}} =
               KV.write_cas("test", %{"key" => "value"}, 1, mount_path: "secret")
    end

    test "delete_versions/3 deletes specific versions" do
      # Mock version detection -> v2
      expect_get(
        200,
        %{"data" => %{"secret/" => %{"type" => "kv", "options" => %{"version" => "2"}}}},
        fn url, _body, _opts ->
          assert String.contains?(url, "/sys/mounts")
        end
      )

      # Mock delete with versions parameter
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "/v1/secret/delete/test")
        assert body["versions"] == [1, 2]
      end)

      assert :ok = KV.delete_versions("test", [1, 2], mount_path: "secret")
    end

    test "delete_versions/2 with default opts (covers function head with default args)" do
      # Mock version detection -> v2
      expect_get(
        200,
        %{"data" => %{"secret/" => %{"type" => "kv", "options" => %{"version" => "2"}}}},
        fn url, _body, _opts ->
          assert String.contains?(url, "/sys/mounts")
        end
      )

      # Mock delete with versions parameter
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "/v1/secret/delete/test")
        assert body["versions"] == [1, 2]
      end)

      # Call with only 2 args to trigger the default opts clause
      assert :ok = KV.delete_versions("test", [1, 2])
    end

    test "read_latest/2 is alias for read/2" do
      # Mock version detection -> v2
      expect_get(
        200,
        %{"data" => %{"secret/" => %{"type" => "kv", "options" => %{"version" => "2"}}}},
        fn url, _body, _opts ->
          assert String.contains?(url, "/sys/mounts")
        end
      )

      # Mock read (latest version)
      expect_get(
        200,
        %{
          "data" => %{
            "data" => %{"key" => "value"},
            "metadata" => %{"version" => 3}
          }
        },
        fn url, _body, _opts ->
          assert String.contains?(url, "/v1/secret/data/test")
        end
      )

      assert {:ok, %Types.SecretData{data: %{"key" => "value"}}} =
               KV.read_latest("test", mount_path: "secret")
    end

    test "exists?/2 returns true when secret exists" do
      # Mock version detection -> v2
      expect_get(
        200,
        %{"data" => %{"secret/" => %{"type" => "kv", "options" => %{"version" => "2"}}}},
        fn url, _body, _opts ->
          assert String.contains?(url, "/sys/mounts")
        end
      )

      # Mock successful read
      expect_get(
        200,
        %{
          "data" => %{
            "data" => %{"key" => "value"}
          }
        },
        fn url, _body, _opts ->
          assert String.contains?(url, "/v1/secret/data/test")
        end
      )

      assert KV.exists?("test", mount_path: "secret") == true
    end

    test "exists?/2 returns false when secret doesn't exist" do
      # Mock version detection -> v2
      expect_get(
        200,
        %{"data" => %{"secret/" => %{"type" => "kv", "options" => %{"version" => "2"}}}},
        fn url, _body, _opts ->
          assert String.contains?(url, "/sys/mounts")
        end
      )

      # Mock 404 response
      expect_get(
        404,
        %{
          "errors" => ["no value found at secret/data/test"]
        },
        fn url, _body, _opts ->
          assert String.contains?(url, "/v1/secret/data/test")
        end
      )

      assert KV.exists?("test", mount_path: "secret") == false
    end

    test "keys/2 returns field names from KV v2 secret" do
      # Mock version detection -> v2
      expect_get(
        200,
        %{"data" => %{"secret/" => %{"type" => "kv", "options" => %{"version" => "2"}}}},
        fn url, _body, _opts ->
          assert String.contains?(url, "/sys/mounts")
        end
      )

      # Mock read with multiple fields
      expect_get(
        200,
        %{
          "data" => %{
            "data" => %{"username" => "admin", "password" => "secret", "port" => 5432}
          }
        },
        fn url, _body, _opts ->
          assert String.contains?(url, "/v1/secret/data/test")
        end
      )

      assert {:ok, keys} = KV.keys("test", mount_path: "secret")
      assert Enum.sort(keys) == ["password", "port", "username"]
    end

    test "keys/2 returns field names from KV v1 secret" do
      # Mock version detection -> v1
      expect_get(
        200,
        %{"data" => %{"secret/" => %{"type" => "kv", "options" => %{"version" => "1"}}}},
        fn url, _body, _opts ->
          assert String.contains?(url, "/sys/mounts")
        end
      )

      # Mock v1 read (no data wrapper)
      expect_get(
        200,
        %{
          "data" => %{"username" => "admin", "password" => "secret"}
        },
        fn url, _body, _opts ->
          assert String.contains?(url, "/v1/secret/test")
        end
      )

      assert {:ok, keys} = KV.keys("test", mount_path: "secret")
      assert Enum.sort(keys) == ["password", "username"]
    end

    test "keys/2 handles error" do
      # Mock version detection -> v2
      expect_get(
        200,
        %{"data" => %{"secret/" => %{"type" => "kv", "options" => %{"version" => "2"}}}},
        fn url, _body, _opts ->
          assert String.contains?(url, "/sys/mounts")
        end
      )

      # Mock 404 response
      expect_get(
        404,
        %{
          "errors" => ["no value found"]
        },
        fn url, _body, _opts ->
          assert String.contains?(url, "/v1/secret/data/test")
        end
      )

      assert {:error, %Error{}} = KV.keys("test", mount_path: "secret")
    end

    test "get_field/3 returns specific field value" do
      # Mock version detection -> v2
      expect_get(
        200,
        %{"data" => %{"secret/" => %{"type" => "kv", "options" => %{"version" => "2"}}}},
        fn url, _body, _opts ->
          assert String.contains?(url, "/sys/mounts")
        end
      )

      # Mock read with fields
      expect_get(
        200,
        %{
          "data" => %{
            "data" => %{"username" => "admin", "password" => "secret"}
          }
        },
        fn url, _body, _opts ->
          assert String.contains?(url, "/v1/secret/data/test")
        end
      )

      assert {:ok, "admin"} = KV.get_field("test", "username", mount_path: "secret")
    end

    test "get_field/3 returns error for missing field" do
      # Mock version detection -> v2
      expect_get(
        200,
        %{"data" => %{"secret/" => %{"type" => "kv", "options" => %{"version" => "2"}}}},
        fn url, _body, _opts ->
          assert String.contains?(url, "/sys/mounts")
        end
      )

      # Mock read with limited fields
      expect_get(
        200,
        %{
          "data" => %{
            "data" => %{"username" => "admin"}
          }
        },
        fn url, _body, _opts ->
          assert String.contains?(url, "/v1/secret/data/test")
        end
      )

      assert {:error, %Error{type: :not_found}} =
               KV.get_field("test", "password", mount_path: "secret")
    end

    test "get_field/3 handles read error (covers error branch)" do
      # Mock version detection -> v2
      expect_get(
        200,
        %{"data" => %{"secret/" => %{"type" => "kv", "options" => %{"version" => "2"}}}},
        fn url, _body, _opts ->
          assert String.contains?(url, "/sys/mounts")
        end
      )

      # Mock 404 response for read to trigger error branch
      expect_get(
        404,
        %{
          "errors" => ["no value found"]
        },
        fn url, _body, _opts ->
          assert String.contains?(url, "/v1/secret/data/test")
        end
      )

      assert {:error, %Error{}} = KV.get_field("test", "password", mount_path: "secret")
    end

    test "update_field/4 updates single field preserving others" do
      # Mock version detection -> v2
      expect_get(
        200,
        %{"data" => %{"secret/" => %{"type" => "kv", "options" => %{"version" => "2"}}}},
        fn url, _body, _opts ->
          assert String.contains?(url, "/sys/mounts")
        end
      )

      # Mock read to get current data
      expect_get(
        200,
        %{
          "data" => %{
            "data" => %{"username" => "admin", "password" => "old_secret"}
          }
        },
        fn url, _body, _opts ->
          assert String.contains?(url, "/v1/secret/data/test")
        end
      )

      # Mock write with updated data
      expect_post(
        200,
        %{
          "data" => %{
            "version" => 2,
            "created_time" => "2025-01-15T00:00:00Z"
          }
        },
        fn url, body, _opts ->
          assert String.contains?(url, "/v1/secret/data/test")
          expected_data = %{"username" => "admin", "password" => "new_secret"}
          assert body["data"] == expected_data
        end
      )

      assert {:ok, %Types.WriteResult{}} =
               KV.update_field("test", "password", "new_secret", mount_path: "secret")
    end

    test "update_field/4 handles read error" do
      # Mock version detection -> v2
      expect_get(
        200,
        %{"data" => %{"secret/" => %{"type" => "kv", "options" => %{"version" => "2"}}}},
        fn url, _body, _opts ->
          assert String.contains?(url, "/sys/mounts")
        end
      )

      # Mock 404 response for read
      expect_get(
        404,
        %{
          "errors" => ["no value found"]
        },
        fn url, _body, _opts ->
          assert String.contains?(url, "/v1/secret/data/test")
        end
      )

      assert {:error, %Error{}} =
               KV.update_field("test", "password", "new_secret", mount_path: "secret")
    end
  end
end
