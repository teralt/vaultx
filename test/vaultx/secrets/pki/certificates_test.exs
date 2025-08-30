defmodule Vaultx.Secrets.PKI.CertificatesTest do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Secrets.PKI.Certificates
  alias Vaultx.Base.Error

  describe "issue/3" do
    test "issues certificate successfully with minimal options" do
      expect_post(
        200,
        %{
          "data" => %{
            "certificate" => "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
            "issuing_ca" => "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
            "ca_chain" => ["-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"],
            "private_key" =>
              "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----",
            "private_key_type" => "rsa",
            "serial_number" => "39:dd:2e:90:b7:23:1f:8d",
            "expiration" => "2024-02-01T00:00:00Z"
          }
        },
        fn url, body, _opts ->
          assert String.contains?(url, "pki/issue/web-server")
          assert body["common_name"] == "example.com"
          assert body["ttl"] == "30d"
        end
      )

      assert {:ok, cert_info} =
               Certificates.issue("web-server", %{
                 common_name: "example.com",
                 ttl: "30d"
               })

      assert cert_info.certificate =~ "BEGIN CERTIFICATE"
      assert cert_info.private_key =~ "BEGIN RSA PRIVATE KEY"
      assert cert_info.serial_number == "39:dd:2e:90:b7:23:1f:8d"
      assert cert_info.private_key_type == "rsa"
    end

    test "issues certificate with all options" do
      expect_post(
        200,
        %{
          "data" => %{
            "certificate" => "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
            "issuing_ca" => "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
            "ca_chain" => ["-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"],
            "private_key" =>
              "-----BEGIN EC PRIVATE KEY-----\nMIIE...\n-----END EC PRIVATE KEY-----",
            "private_key_type" => "ec",
            "serial_number" => "12:34:56:78:90:ab:cd:ef",
            "expiration" => "2024-04-01T00:00:00Z"
          }
        },
        fn url, body, _opts ->
          assert String.contains?(url, "pki/issue/web-server")
          assert body["common_name"] == "example.com"
          assert body["alt_names"] == "www.example.com,api.example.com"
          assert body["ip_sans"] == "192.168.1.100"
          assert body["uri_sans"] == "https://example.com"
          assert body["other_sans"] == "1.2.3.4;UTF8:example"
          assert body["ttl"] == "90d"
          assert body["format"] == "pem_bundle"
          assert body["private_key_format"] == "pkcs8"
          assert body["exclude_cn_from_sans"] == true
          assert body["not_after"] == "2025-08-30T23:59:59Z"
          assert body["remove_roots_from_chain"] == true
        end
      )

      assert {:ok, cert_info} =
               Certificates.issue("web-server", %{
                 common_name: "example.com",
                 alt_names: "www.example.com,api.example.com",
                 ip_sans: "192.168.1.100",
                 uri_sans: "https://example.com",
                 other_sans: "1.2.3.4;UTF8:example",
                 ttl: "90d",
                 format: "pem_bundle",
                 private_key_format: "pkcs8",
                 exclude_cn_from_sans: true,
                 not_after: "2025-08-30T23:59:59Z",
                 remove_roots_from_chain: true
               })

      assert cert_info.private_key_type == "ec"
      assert cert_info.serial_number == "12:34:56:78:90:ab:cd:ef"
    end

    test "handles role not found error" do
      expect_post(404, %{
        "errors" => ["role not found"]
      })

      assert {:error, %Error{type: :not_found}} =
               Certificates.issue("nonexistent-role", %{
                 common_name: "example.com"
               })
    end

    test "handles domain not allowed error" do
      expect_post(400, %{
        "errors" => ["domain not allowed by role policy"]
      })

      assert {:error, %Error{type: :invalid_request}} =
               Certificates.issue("web-server", %{
                 common_name: "forbidden.com"
               })
    end

    test "handles network error" do
      stub_request_raw(:post, :timeout)

      assert {:error, %Error{type: :network_error}} =
               Certificates.issue("web-server", %{
                 common_name: "example.com"
               })
    end

    test "uses custom mount path and timeout" do
      expect_post(
        200,
        %{
          "data" => %{
            "certificate" => "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
            "serial_number" => "39:dd:2e:90:b7:23:1f:8d"
          }
        },
        fn url, _body, opts ->
          assert String.contains?(url, "custom-pki/issue/web-server")
          assert opts[:timeout] == 60_000
        end
      )

      assert {:ok, _cert_info} =
               Certificates.issue(
                 "web-server",
                 %{
                   common_name: "example.com"
                 },
                 mount_path: "custom-pki",
                 timeout: 60_000
               )
    end
  end

  describe "sign/4" do
    test "signs CSR successfully" do
      expect_post(
        200,
        %{
          "data" => %{
            "certificate" => "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
            "issuing_ca" => "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
            "ca_chain" => ["-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"],
            "serial_number" => "39:dd:2e:90:b7:23:1f:8d",
            "expiration" => "2024-02-01T00:00:00Z"
          }
        },
        fn url, body, _opts ->
          assert String.contains?(url, "pki/sign/web-server")
          assert body["csr"] =~ "BEGIN CERTIFICATE REQUEST"
          assert body["common_name"] == "example.com"
          assert body["ttl"] == "30d"
        end
      )

      csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----"

      assert {:ok, cert_info} =
               Certificates.sign("web-server", csr, %{
                 common_name: "example.com",
                 ttl: "30d"
               })

      assert cert_info.certificate =~ "BEGIN CERTIFICATE"
      assert cert_info.serial_number == "39:dd:2e:90:b7:23:1f:8d"
      # CSR signing doesn't return private key
      assert is_nil(cert_info.private_key)
    end

    test "handles invalid CSR error" do
      expect_post(400, %{
        "errors" => ["invalid certificate signing request"]
      })

      assert {:error, %Error{type: :invalid_request}} =
               Certificates.sign("web-server", "invalid-csr", %{
                 common_name: "example.com"
               })
    end
  end

  describe "revoke/2" do
    test "revokes certificate successfully" do
      expect_post(200, %{}, fn url, body, _opts ->
        assert String.contains?(url, "pki/revoke")
        assert body["serial_number"] == "39:dd:2e:90:b7:23:1f:8d"
      end)

      assert :ok = Certificates.revoke("39:dd:2e:90:b7:23:1f:8d")
    end

    test "handles certificate not found error" do
      expect_post(404, %{
        "errors" => ["certificate not found"]
      })

      assert {:error, %Error{type: :not_found}} = Certificates.revoke("nonexistent:serial")
    end

    test "handles already revoked error" do
      expect_post(400, %{
        "errors" => ["certificate already revoked"]
      })

      assert {:error, %Error{type: :invalid_request}} =
               Certificates.revoke("39:dd:2e:90:b7:23:1f:8d")
    end
  end

  describe "read/2" do
    test "reads certificate successfully" do
      cert_pem = "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"

      expect_get(200, cert_pem, fn url, _body, _opts ->
        assert String.contains?(url, "pki/cert/39:dd:2e:90:b7:23:1f:8d")
      end)

      assert {:ok, ^cert_pem} = Certificates.read("39:dd:2e:90:b7:23:1f:8d")
    end

    test "handles certificate not found error" do
      expect_get(404, %{
        "errors" => ["certificate not found"]
      })

      assert {:error, %Error{type: :not_found}} = Certificates.read("nonexistent:serial")
    end
  end

  describe "list/1" do
    test "lists certificates successfully" do
      expect_get(
        200,
        %{
          "data" => %{
            "keys" => [
              "39:dd:2e:90:b7:23:1f:8d",
              "12:34:56:78:90:ab:cd:ef",
              "aa:bb:cc:dd:ee:ff:00:11"
            ]
          }
        },
        fn url, _body, _opts ->
          assert String.contains?(url, "pki/certs?list=true")
        end
      )

      assert {:ok, serials} = Certificates.list()
      assert length(serials) == 3
      assert "39:dd:2e:90:b7:23:1f:8d" in serials
      assert "12:34:56:78:90:ab:cd:ef" in serials
      assert "aa:bb:cc:dd:ee:ff:00:11" in serials
    end

    test "handles empty certificate list" do
      expect_get(200, %{
        "data" => %{
          "keys" => []
        }
      })

      assert {:ok, []} = Certificates.list()
    end

    test "handles missing keys field" do
      expect_get(200, %{
        "data" => %{}
      })

      assert {:ok, []} = Certificates.list()
    end
  end

  describe "sign_verbatim/3" do
    test "signs certificate verbatim successfully" do
      expect_post(
        200,
        %{
          "data" => %{
            "certificate" => "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
            "issuing_ca" => "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
            "ca_chain" => ["-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"],
            "serial_number" => "39:dd:2e:90:b7:23:1f:8d",
            "expiration" => "2024-02-01T00:00:00Z"
          }
        },
        fn url, body, _opts ->
          assert String.contains?(url, "pki/sign-verbatim")
          assert body["csr"] =~ "BEGIN CERTIFICATE REQUEST"
          assert body["ttl"] == "30d"
          assert body["format"] == "pem"
        end
      )

      csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----"

      assert {:ok, cert_info} =
               Certificates.sign_verbatim(csr, %{
                 ttl: "30d",
                 format: "pem"
               })

      assert cert_info.certificate =~ "BEGIN CERTIFICATE"
      assert cert_info.serial_number == "39:dd:2e:90:b7:23:1f:8d"
    end
  end

  describe "revoke_with_key/3" do
    test "revokes certificate with private key successfully" do
      expect_post(200, %{}, fn url, body, _opts ->
        assert String.contains?(url, "pki/revoke-with-key")
        assert body["certificate"] =~ "BEGIN CERTIFICATE"
        assert body["private_key"] =~ "BEGIN PRIVATE KEY"
      end)

      cert = "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"
      key = "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----"

      assert :ok = Certificates.revoke_with_key(cert, key)
    end

    test "handles invalid certificate or key error" do
      expect_post(400, %{
        "errors" => ["certificate and private key do not match"]
      })

      assert {:error, %Error{type: :invalid_request}} =
               Certificates.revoke_with_key("invalid", "invalid")
    end
  end

  describe "network error handling" do
    test "handles network error in sign operation" do
      stub_request_raw(:post, :timeout)

      csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----"

      assert {:error, %Error{type: :network_error}} =
               Certificates.sign("web-server", csr, %{
                 common_name: "example.com"
               })
    end

    test "handles network error in revoke operation" do
      stub_request_raw(:post, :timeout)

      assert {:error, %Error{type: :network_error}} =
               Certificates.revoke("39:dd:2e:90:b7:23:1f:8d")
    end

    test "handles network error in read operation" do
      stub_request_raw(:get, :timeout)

      assert {:error, %Error{type: :network_error}} = Certificates.read("39:dd:2e:90:b7:23:1f:8d")
    end

    test "handles network error in list operation" do
      stub_request_raw(:get, :timeout)

      assert {:error, %Error{type: :network_error}} = Certificates.list()
    end

    test "handles HTTP error in list operation" do
      expect_get(500, %{
        "errors" => ["internal server error"]
      })

      assert {:error, %Error{type: :server_error}} = Certificates.list()
    end

    test "handles network error in sign_verbatim operation" do
      stub_request_raw(:post, :timeout)

      csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----"

      assert {:error, %Error{type: :network_error}} =
               Certificates.sign_verbatim(csr, %{
                 ttl: "30d"
               })
    end

    test "handles HTTP error in sign_verbatim operation" do
      expect_post(400, %{
        "errors" => ["invalid CSR"]
      })

      csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----"

      assert {:error, %Error{type: :invalid_request}} =
               Certificates.sign_verbatim(csr, %{
                 ttl: "30d"
               })
    end

    test "handles network error in revoke_with_key operation" do
      stub_request_raw(:post, :timeout)

      cert = "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"
      key = "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----"

      assert {:error, %Error{type: :network_error}} = Certificates.revoke_with_key(cert, key)
    end
  end

  describe "helper functions and edge cases" do
    test "build_certificate_payload ignores unknown options" do
      expect_post(
        200,
        %{
          "data" => %{
            "certificate" => "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
            "serial_number" => "39:dd:2e:90:b7:23:1f:8d"
          }
        },
        fn _url, body, _opts ->
          # Should only include known options
          refute Map.has_key?(body, "unknown_option")
          refute Map.has_key?(body, "invalid_key")
          assert body["common_name"] == "example.com"
        end
      )

      assert {:ok, _cert_info} =
               Certificates.issue("web-server", %{
                 common_name: "example.com",
                 unknown_option: "should be ignored",
                 invalid_key: 123
               })
    end

    test "build_sign_payload with all supported options" do
      expect_post(
        200,
        %{
          "data" => %{
            "certificate" => "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
            "serial_number" => "39:dd:2e:90:b7:23:1f:8d"
          }
        },
        fn _url, body, _opts ->
          assert body["csr"] =~ "BEGIN CERTIFICATE REQUEST"
          assert body["common_name"] == "example.com"
          assert body["alt_names"] == "www.example.com"
          assert body["ip_sans"] == "192.168.1.1"
          assert body["uri_sans"] == "https://example.com"
          assert body["ttl"] == "30d"
          assert body["format"] == "pem"
          assert body["exclude_cn_from_sans"] == true
        end
      )

      csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----"

      assert {:ok, _cert_info} =
               Certificates.sign("web-server", csr, %{
                 common_name: "example.com",
                 alt_names: "www.example.com",
                 ip_sans: "192.168.1.1",
                 uri_sans: "https://example.com",
                 ttl: "30d",
                 format: "pem",
                 exclude_cn_from_sans: true,
                 unknown_option: "ignored"
               })
    end

    test "parse_certificate_response handles malformed data" do
      expect_post(200, %{}, fn url, _body, _opts ->
        assert String.contains?(url, "pki/issue/web-server")
      end)

      assert {:ok, cert_info} =
               Certificates.issue("web-server", %{
                 common_name: "example.com"
               })

      assert cert_info.certificate == ""
      assert cert_info.serial_number == ""
      assert is_nil(cert_info.private_key)
    end

    test "parse_certificate_response handles nil data" do
      expect_post(200, %{"data" => nil}, fn url, _body, _opts ->
        assert String.contains?(url, "pki/issue/web-server")
      end)

      assert {:ok, cert_info} =
               Certificates.issue("web-server", %{
                 common_name: "example.com"
               })

      assert cert_info.certificate == ""
      assert cert_info.serial_number == ""
    end

    test "parse_certificate_response with non-map input" do
      expect_post(200, "not a map", fn url, _body, _opts ->
        assert String.contains?(url, "pki/issue/web-server")
      end)

      assert {:ok, cert_info} =
               Certificates.issue("web-server", %{
                 common_name: "example.com"
               })

      assert cert_info.certificate == ""
      assert cert_info.serial_number == ""
      assert is_nil(cert_info.private_key)
      assert cert_info.ca_chain == []
    end
  end
end
