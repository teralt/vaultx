defmodule Vaultx.Secrets.TOTPTest do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Secrets.TOTP
  alias Vaultx.Base.Error

  describe "create_key/3" do
    test "creates key with generated secret and returns QR/url" do
      response = %{
        "data" => %{
          "barcode" => "data:image/png;base64,AAA...",
          "url" => "otpauth://totp/MyApp:user@example.com?secret=ABC&issuer=MyApp"
        }
      }

      expect_post(200, response, fn url, body, _opts ->
        assert String.contains?(url, "totp/keys/user-key")
        assert body["generate"] == true
        assert body["exported"] == true
        assert body["issuer"] == "MyApp"
        assert body["account_name"] == "user@example.com"
        assert body["algorithm"] == "SHA256"
        assert body["digits"] == 6
        assert body["period"] == 30
        assert body["qr_size"] == 200
      end)

      config = %{
        generate: true,
        exported: true,
        issuer: "MyApp",
        account_name: "user@example.com",
        algorithm: "SHA256",
        digits: 6,
        period: 30,
        qr_size: 200
      }

      assert {:ok, result} = TOTP.create_key("user-key", config)
      assert result.barcode =~ "data:image/png"
      assert String.starts_with?(result.url, "otpauth://totp/")
    end

    test "imports existing key via URL" do
      expect_post(200, %{"data" => %{}}, fn url, body, _opts ->
        assert String.contains?(url, "totp/keys/imported-key")
        assert body["url"] =~ "otpauth://totp/"
      end)

      config = %{
        url:
          "otpauth://totp/Google:test@gmail.com?secret=Y64VEVMBTSXCYIWRSHRNDZW62MPGVU2G&issuer=Google"
      }

      assert {:ok, _} = TOTP.create_key("imported-key", config)
    end

    test "supports custom mount path" do
      expect_post(200, %{"data" => %{}}, fn url, _body, _opts ->
        assert String.contains?(url, "mfa/keys/custom")
      end)

      assert {:ok, _} =
               TOTP.create_key("custom", %{generate: true, issuer: "X", account_name: "y"},
                 mount_path: "mfa"
               )
    end

    test "returns empty map when 204 without data" do
      expect_post(204, %{})

      assert {:ok, %{} = _} =
               TOTP.create_key("k", %{generate: true, issuer: "a", account_name: "b"})
    end

    test "handles creation failure" do
      expect_post(400, %{"errors" => ["invalid config"]})

      assert {:error, %Error{type: :invalid_request}} =
               TOTP.create_key("bad", %{generate: true})
    end

    test "handles network error" do
      stub_request_raw(:post, :timeout)

      assert {:error, %Error{type: :http_error}} =
               TOTP.create_key("user-key", %{generate: true, issuer: "MyApp", account_name: "u"})
    end
  end

  describe "read_key/2" do
    test "reads key configuration successfully" do
      response = %{
        "data" => %{
          "account_name" => "user@example.com",
          "algorithm" => "SHA1",
          "digits" => 6,
          "issuer" => "MyApp",
          "period" => 30
        }
      }

      expect_get(200, response, fn url, _body, _opts ->
        assert String.contains?(url, "totp/keys/user-key")
      end)

      assert {:ok, info} = TOTP.read_key("user-key")
      assert info.account_name == "user@example.com"
      assert info.algorithm == "SHA1"
      assert info.digits == 6
      assert info.issuer == "MyApp"
      assert info.period == 30
    end

    test "reads with custom mount path" do
      expect_get(200, %{"data" => %{}}, fn url, _body, _opts ->
        assert String.contains?(url, "mfa/keys/k1")
      end)

      assert {:ok, _} = TOTP.read_key("k1", mount_path: "mfa")
    end

    test "handles read failure" do
      expect_get(403, %{"errors" => ["permission denied"]})
      assert {:error, %Error{type: :authorization_denied}} = TOTP.read_key("user-key")
    end

    test "handles network error" do
      stub_request_raw(:get, :timeout)
      assert {:error, %Error{type: :http_error}} = TOTP.read_key("user-key")
    end

    test "handles missing fields with defaults" do
      expect_get(200, %{"data" => %{}})
      assert {:ok, info} = TOTP.read_key("k")
      assert info.account_name == ""
      assert info.algorithm == "SHA1"
      assert info.digits == 6
      assert info.issuer == ""
      assert info.period == 30
    end
  end

  describe "list_keys/1" do
    test "lists keys successfully" do
      expect_any(:list, 200, %{"data" => %{"keys" => ["user1", "admin"]}}, fn url, _b, _o ->
        assert String.ends_with?(url, "/v1/totp/keys")
      end)

      assert {:ok, keys} = TOTP.list_keys()
      assert keys == ["user1", "admin"]
    end

    test "lists keys with custom mount path" do
      expect_any(:list, 200, %{"data" => %{"keys" => ["k1"]}}, fn url, _b, _o ->
        assert String.ends_with?(url, "/v1/mfa/keys")
      end)

      assert {:ok, keys} = TOTP.list_keys(mount_path: "mfa")
      assert keys == ["k1"]
    end

    test "handles list failure" do
      expect_any(:list, 404, %{"errors" => ["no keys"]})
      assert {:error, %Error{type: :not_found}} = TOTP.list_keys()
    end

    test "handles network error" do
      stub_request_raw(:list, :timeout)
      assert {:error, %Error{type: :http_error}} = TOTP.list_keys()
    end
  end

  describe "delete_key/2" do
    test "deletes key successfully (200/204)" do
      expect_delete(200, %{}, fn url, _body, _opts ->
        assert String.contains?(url, "totp/keys/old")
      end)

      assert :ok = TOTP.delete_key("old")

      expect_delete(204, %{})
      assert :ok = TOTP.delete_key("old")
    end

    test "deletes with custom mount path" do
      expect_delete(200, %{}, fn url, _body, _opts ->
        assert String.contains?(url, "mfa/keys/old")
      end)

      assert :ok = TOTP.delete_key("old", mount_path: "mfa")
    end

    test "handles deletion failure" do
      expect_delete(403, %{"errors" => ["denied"]})
      assert {:error, %Error{type: :authorization_denied}} = TOTP.delete_key("old")
    end

    test "handles network error" do
      stub_request_raw(:delete, :timeout)
      assert {:error, %Error{type: :http_error}} = TOTP.delete_key("old")
    end
  end

  describe "generate_code/2" do
    test "generates TOTP code successfully" do
      expect_get(200, %{"data" => %{"code" => "123456"}}, fn url, _body, _opts ->
        assert String.contains?(url, "totp/code/user-key")
      end)

      assert {:ok, code} = TOTP.generate_code("user-key")
      assert code.code == "123456"
    end

    test "generates with custom mount path" do
      expect_get(200, %{"data" => %{"code" => "654321"}}, fn url, _body, _opts ->
        assert String.contains?(url, "mfa/code/u1")
      end)

      assert {:ok, code} = TOTP.generate_code("u1", mount_path: "mfa")
      assert code.code == "654321"
    end

    test "handles generation failure" do
      expect_get(500, %{"errors" => ["server error"]})
      assert {:error, %Error{type: :server_error}} = TOTP.generate_code("user-key")
    end

    test "handles network error" do
      stub_request_raw(:get, :timeout)
      assert {:error, %Error{type: :http_error}} = TOTP.generate_code("user-key")
    end
  end

  describe "validate_code/3" do
    test "validates TOTP code successfully" do
      expect_post(200, %{"data" => %{"valid" => true}}, fn url, body, _opts ->
        assert String.contains?(url, "totp/code/user-key")
        assert body["code"] == "123456"
      end)

      assert {:ok, result} = TOTP.validate_code("user-key", "123456")
      assert result.valid == true
    end

    test "validates with custom mount path" do
      expect_post(200, %{"data" => %{"valid" => false}}, fn url, body, _opts ->
        assert String.contains?(url, "mfa/code/u1")
        assert body["code"] == "000000"
      end)

      assert {:ok, result} = TOTP.validate_code("u1", "000000", mount_path: "mfa")
      assert result.valid == false
    end

    test "handles validation failure" do
      expect_post(400, %{"errors" => ["bad code"]})
      assert {:error, %Error{type: :invalid_request}} = TOTP.validate_code("k", "bad")
    end

    test "handles network error" do
      stub_request_raw(:post, :timeout)
      assert {:error, %Error{type: :http_error}} = TOTP.validate_code("k", "123456")
    end
  end
end
