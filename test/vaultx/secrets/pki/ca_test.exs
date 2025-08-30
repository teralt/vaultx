defmodule Vaultx.Secrets.PKI.CATest do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Secrets.PKI.CA
  alias Vaultx.Base.Error

  describe "generate_root/2" do
    test "generates root CA successfully with minimal options" do
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
            "expiration" => "2034-01-01T00:00:00Z"
          }
        },
        fn url, body, _opts ->
          assert String.contains?(url, "pki/root/generate/internal")
          assert body["common_name"] == "Test Root CA"
          assert body["ttl"] == "10y"
        end
      )

      assert {:ok, ca_info} =
               CA.generate_root(%{
                 common_name: "Test Root CA",
                 ttl: "10y"
               })

      assert ca_info.certificate =~ "BEGIN CERTIFICATE"
      assert ca_info.private_key =~ "BEGIN RSA PRIVATE KEY"
      assert ca_info.serial_number == "39:dd:2e:90:b7:23:1f:8d"
      assert ca_info.private_key_type == "rsa"
    end

    test "generates root CA with all options" do
      expect_post(
        200,
        %{
          "data" => %{
            "certificate" => "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
            "issuing_ca" => "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
            "ca_chain" => [],
            "private_key" =>
              "-----BEGIN EC PRIVATE KEY-----\nMIIE...\n-----END EC PRIVATE KEY-----",
            "private_key_type" => "ec",
            "serial_number" => "12:34:56:78:90:ab:cd:ef",
            "expiration" => "2029-01-01T00:00:00Z"
          }
        },
        fn url, body, _opts ->
          assert String.contains?(url, "pki/root/generate/internal")
          assert body["common_name"] == "Example Root CA"
          assert body["alt_names"] == "ca.example.com"
          assert body["ip_sans"] == "192.168.1.1"
          assert body["uri_sans"] == "https://ca.example.com"
          assert body["ttl"] == "5y"
          assert body["key_type"] == "ec"
          assert body["key_bits"] == 384
          assert body["max_path_length"] == 2
          assert body["permitted_dns_domains"] == "example.com,example.org"
          assert body["excluded_dns_domains"] == "bad.example.com"
          assert body["format"] == "pem"
        end
      )

      assert {:ok, ca_info} =
               CA.generate_root(%{
                 common_name: "Example Root CA",
                 alt_names: "ca.example.com",
                 ip_sans: "192.168.1.1",
                 uri_sans: "https://ca.example.com",
                 ttl: "5y",
                 key_type: "ec",
                 key_bits: 384,
                 max_path_length: 2,
                 permitted_dns_domains: ["example.com", "example.org"],
                 excluded_dns_domains: ["bad.example.com"],
                 format: "pem"
               })

      assert ca_info.private_key_type == "ec"
      assert ca_info.serial_number == "12:34:56:78:90:ab:cd:ef"
    end

    test "handles HTTP error response" do
      expect_post(400, %{
        "errors" => ["invalid common name"]
      })

      assert {:error, %Error{type: :invalid_request}} =
               CA.generate_root(%{
                 common_name: ""
               })
    end

    test "handles network error" do
      stub_request_raw(:post, :timeout)

      assert {:error, %Error{type: :network_error}} =
               CA.generate_root(%{
                 common_name: "Test CA"
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
          assert String.contains?(url, "custom-pki/root/generate/internal")
          assert opts[:timeout] == 60_000
        end
      )

      assert {:ok, _ca_info} =
               CA.generate_root(
                 %{
                   common_name: "Test CA"
                 },
                 mount_path: "custom-pki",
                 timeout: 60_000
               )
    end
  end

  describe "generate_intermediate/2" do
    test "generates intermediate CA CSR successfully" do
      expect_post(
        200,
        %{
          "data" => %{
            "csr" =>
              "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----",
            "private_key" =>
              "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----",
            "private_key_type" => "rsa"
          }
        },
        fn url, body, _opts ->
          assert String.contains?(url, "pki/intermediate/generate/internal")
          assert body["common_name"] == "Test Intermediate CA"
          assert body["key_type"] == "rsa"
          assert body["key_bits"] == 2048
        end
      )

      assert {:ok, result} =
               CA.generate_intermediate(%{
                 common_name: "Test Intermediate CA",
                 key_type: "rsa",
                 key_bits: 2048
               })

      assert result.csr =~ "BEGIN CERTIFICATE REQUEST"
      assert result.private_key =~ "BEGIN RSA PRIVATE KEY"
      assert result.private_key_type == "rsa"
    end

    test "handles error response" do
      expect_post(500, %{
        "errors" => ["internal server error"]
      })

      assert {:error, %Error{type: :server_error}} =
               CA.generate_intermediate(%{
                 common_name: "Test CA"
               })
    end

    test "handles network error" do
      stub_request_raw(:post, :timeout)

      assert {:error, %Error{type: :network_error}} =
               CA.generate_intermediate(%{
                 common_name: "Test CA"
               })
    end
  end

  describe "import_ca/3" do
    test "imports CA certificate and key successfully" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "pki/config/ca")
        assert body["pem_bundle"] =~ "BEGIN CERTIFICATE"
        assert body["pem_bundle"] =~ "BEGIN PRIVATE KEY"
      end)

      ca_cert = "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"
      ca_key = "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----"

      assert :ok = CA.import_ca(ca_cert, ca_key)
    end

    test "handles import error" do
      expect_post(400, %{
        "errors" => ["invalid certificate format"]
      })

      assert {:error, %Error{type: :invalid_request}} = CA.import_ca("invalid", "invalid")
    end

    test "handles network error on import" do
      stub_request_raw(:post, :timeout)

      assert {:error, %Error{type: :network_error}} = CA.import_ca("cert", "key")
    end
  end

  describe "read_ca_certificate/1" do
    test "reads CA certificate successfully" do
      ca_cert = "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"

      expect_get(200, ca_cert, fn url, _body, _opts ->
        assert String.contains?(url, "pki/ca/pem")
      end)

      assert {:ok, ^ca_cert} = CA.read_ca_certificate()
    end

    test "handles not found error" do
      expect_get(404, %{
        "errors" => ["no CA certificate configured"]
      })

      assert {:error, %Error{type: :not_found}} = CA.read_ca_certificate()
    end

    test "handles network error on read" do
      stub_request_raw(:get, :timeout)

      assert {:error, %Error{type: :network_error}} = CA.read_ca_certificate()
    end
  end

  describe "read_ca_chain/1" do
    test "reads CA certificate chain successfully" do
      ca_chain = """
      -----BEGIN CERTIFICATE-----
      MIIC...intermediate...
      -----END CERTIFICATE-----
      -----BEGIN CERTIFICATE-----
      MIIC...root...
      -----END CERTIFICATE-----
      """

      expect_get(200, ca_chain, fn url, _body, _opts ->
        assert String.contains?(url, "pki/ca_chain")
      end)

      assert {:ok, chain} = CA.read_ca_chain()
      assert length(chain) == 2
      assert Enum.all?(chain, &String.contains?(&1, "BEGIN CERTIFICATE"))
    end

    test "handles empty chain" do
      expect_get(200, "", fn url, _body, _opts ->
        assert String.contains?(url, "pki/ca_chain")
      end)

      assert {:ok, []} = CA.read_ca_chain()
    end

    test "handles chain read error" do
      expect_get(500, %{
        "errors" => ["internal server error"]
      })

      assert {:error, %Error{type: :server_error}} = CA.read_ca_chain()
    end

    test "handles network error on chain read" do
      stub_request_raw(:get, :timeout)

      assert {:error, %Error{type: :network_error}} = CA.read_ca_chain()
    end
  end

  describe "sign_intermediate/3" do
    test "signs intermediate CA certificate successfully" do
      expect_post(
        200,
        %{
          "data" => %{
            "certificate" => "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
            "issuing_ca" => "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
            "ca_chain" => ["-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"],
            "serial_number" => "12:34:56:78:90:ab:cd:ef",
            "expiration" => "2029-01-01T00:00:00Z"
          }
        },
        fn url, body, _opts ->
          assert String.contains?(url, "pki/root/sign-intermediate")
          assert body["csr"] =~ "BEGIN CERTIFICATE REQUEST"
          assert body["common_name"] == "Intermediate CA"
          assert body["ttl"] == "5y"
          assert body["max_path_length"] == 1
        end
      )

      csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----"

      assert {:ok, cert_info} =
               CA.sign_intermediate(csr, %{
                 common_name: "Intermediate CA",
                 ttl: "5y",
                 max_path_length: 1
               })

      assert cert_info.certificate =~ "BEGIN CERTIFICATE"
      assert cert_info.serial_number == "12:34:56:78:90:ab:cd:ef"
    end

    test "handles signing error" do
      expect_post(400, %{
        "errors" => ["invalid CSR"]
      })

      csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----"

      assert {:error, %Error{type: :invalid_request}} =
               CA.sign_intermediate(csr, %{
                 common_name: "Intermediate CA"
               })
    end

    test "handles network error on signing" do
      stub_request_raw(:post, :timeout)

      csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----"

      assert {:error, %Error{type: :network_error}} =
               CA.sign_intermediate(csr, %{
                 common_name: "Intermediate CA"
               })
    end
  end

  describe "set_intermediate_certificate/2" do
    test "sets intermediate certificate successfully" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "pki/intermediate/set-signed")
        assert body["certificate"] =~ "BEGIN CERTIFICATE"
      end)

      cert = "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"

      assert :ok = CA.set_intermediate_certificate(cert)
    end

    test "handles invalid certificate error" do
      expect_post(400, %{
        "errors" => ["invalid certificate"]
      })

      assert {:error, %Error{type: :invalid_request}} = CA.set_intermediate_certificate("invalid")
    end

    test "handles network error on set certificate" do
      stub_request_raw(:post, :timeout)

      assert {:error, %Error{type: :network_error}} = CA.set_intermediate_certificate("cert")
    end
  end

  describe "edge cases and helper functions" do
    test "handles malformed response bodies" do
      expect_post(200, %{"data" => %{}}, fn url, _body, _opts ->
        assert String.contains?(url, "pki/root/generate/internal")
      end)

      assert {:ok, ca_info} = CA.generate_root(%{common_name: "Test CA"})
      assert ca_info.certificate == ""
      assert ca_info.serial_number == ""
    end

    test "handles nil response data" do
      expect_post(200, %{}, fn url, _body, _opts ->
        assert String.contains?(url, "pki/root/generate/internal")
      end)

      assert {:ok, ca_info} = CA.generate_root(%{common_name: "Test CA"})
      assert ca_info.certificate == ""
    end

    test "handles missing response data" do
      expect_post(200, %{}, fn url, _body, _opts ->
        assert String.contains?(url, "pki/root/generate/internal")
      end)

      assert {:ok, ca_info} = CA.generate_root(%{common_name: "Test CA"})
      assert ca_info.certificate == ""
    end

    test "build_ca_payload ignores unknown options" do
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
        end
      )

      assert {:ok, _ca_info} =
               CA.generate_root(%{
                 common_name: "Test CA",
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
          assert body["common_name"] == "Test CA"
          assert body["alt_names"] == "ca.test.com"
          assert body["ip_sans"] == "192.168.1.1"
          assert body["uri_sans"] == "https://ca.test.com"
          assert body["ttl"] == "1y"
          assert body["max_path_length"] == 0
          assert body["permitted_dns_domains"] == "test.com"
          assert body["excluded_dns_domains"] == "bad.test.com"
          assert body["format"] == "pem"
        end
      )

      csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----"

      assert {:ok, _cert_info} =
               CA.sign_intermediate(csr, %{
                 common_name: "Test CA",
                 alt_names: "ca.test.com",
                 ip_sans: "192.168.1.1",
                 uri_sans: "https://ca.test.com",
                 ttl: "1y",
                 max_path_length: 0,
                 permitted_dns_domains: ["test.com"],
                 excluded_dns_domains: ["bad.test.com"],
                 format: "pem"
               })
    end

    test "parse_ca_chain with malformed PEM data" do
      expect_get(200, "not a valid pem", fn url, _body, _opts ->
        assert String.contains?(url, "pki/ca_chain")
      end)

      assert {:ok, chain} = CA.read_ca_chain()
      assert is_list(chain)
    end

    test "parse_ca_response with non-map input" do
      expect_post(200, "not a map", fn url, _body, _opts ->
        assert String.contains?(url, "pki/root/generate/internal")
      end)

      assert {:ok, ca_info} = CA.generate_root(%{common_name: "Test CA"})
      # The fallback returns an empty map, but the function expects certain keys
      # So we just verify it doesn't crash and returns something
      assert is_map(ca_info)
    end

    test "parse_intermediate_response with non-map input" do
      expect_post(200, "not a map", fn url, _body, _opts ->
        assert String.contains?(url, "pki/intermediate/generate/internal")
      end)

      assert {:ok, result} = CA.generate_intermediate(%{common_name: "Test CA"})
      # The fallback returns an empty map, but the function expects certain keys
      # So we just verify it doesn't crash and returns something
      assert is_map(result)
    end

    test "build_sign_option with unsupported option types" do
      expect_post(
        200,
        %{
          "data" => %{
            "certificate" => "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
            "serial_number" => "39:dd:2e:90:b7:23:1f:8d"
          }
        },
        fn _url, body, _opts ->
          # Should not include unsupported option types
          refute Map.has_key?(body, "invalid_number")
          refute Map.has_key?(body, "invalid_atom")
          refute Map.has_key?(body, "invalid_list")
          assert body["csr"] =~ "BEGIN CERTIFICATE REQUEST"
        end
      )

      csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----"

      # Test with various invalid option types that should be ignored
      assert {:ok, _cert_info} =
               CA.sign_intermediate(csr, %{
                 common_name: "Test CA",
                 invalid_number: 123,
                 invalid_atom: :atom,
                 invalid_list: [:a, :b, :c],
                 invalid_map: %{key: "value"}
               })
    end
  end
end
