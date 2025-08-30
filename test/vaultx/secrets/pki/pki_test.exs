defmodule Vaultx.Secrets.PKI.PKITest do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Secrets.PKI
  alias Vaultx.Base.Error

  describe "behaviour implementation" do
    test "implements PKI behaviour" do
      behaviours = PKI.__info__(:attributes)[:behaviour] || []
      assert Vaultx.Secrets.PKI.Behaviour in behaviours
    end

    test "has all required callback functions" do
      # CA operations
      assert function_exported?(PKI, :generate_root, 2)
      assert function_exported?(PKI, :generate_intermediate, 2)
      assert function_exported?(PKI, :import_ca, 3)
      assert function_exported?(PKI, :read_ca_certificate, 1)
      assert function_exported?(PKI, :read_ca_chain, 1)

      # Certificate operations
      assert function_exported?(PKI, :issue_certificate, 3)
      assert function_exported?(PKI, :sign_certificate, 4)
      assert function_exported?(PKI, :sign_intermediate, 3)
      assert function_exported?(PKI, :sign_self_issued, 3)
      assert function_exported?(PKI, :sign_verbatim, 3)
      assert function_exported?(PKI, :read_certificate, 2)
      assert function_exported?(PKI, :list_certificates, 1)
      assert function_exported?(PKI, :revoke_certificate, 2)
      assert function_exported?(PKI, :revoke_certificate_with_key, 3)

      # Role operations
      assert function_exported?(PKI, :create_role, 3)
      assert function_exported?(PKI, :read_role, 2)
      assert function_exported?(PKI, :update_role, 3)
      assert function_exported?(PKI, :delete_role, 2)
      assert function_exported?(PKI, :list_roles, 1)

      # CRL operations
      assert function_exported?(PKI, :read_crl, 1)
      assert function_exported?(PKI, :rotate_crl, 1)

      # Configuration operations
      assert function_exported?(PKI, :read_urls, 1)
      assert function_exported?(PKI, :write_urls, 2)

      # Maintenance operations
      assert function_exported?(PKI, :tidy, 2)
      assert function_exported?(PKI, :tidy_status, 1)
      assert function_exported?(PKI, :tidy_cancel, 1)
    end
  end

  describe "create_role/3" do
    test "creates role successfully with minimal options" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "pki/roles/web-server")
        assert body["allowed_domains"] == ["example.com"]
        assert body["allow_subdomains"] == true
        assert body["max_ttl"] == "90d"
      end)

      assert :ok =
               PKI.create_role("web-server", %{
                 allowed_domains: ["example.com"],
                 allow_subdomains: true,
                 max_ttl: "90d"
               })
    end

    test "creates role with all options" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "pki/roles/full-role")
        assert body["allowed_domains"] == ["example.com", "example.org"]
        assert body["allow_subdomains"] == true
        assert body["allow_any_name"] == false
        assert body["allow_bare_domains"] == true
        assert body["allow_localhost"] == false
        assert body["allow_ip_sans"] == true
        assert body["key_type"] == "ec"
        assert body["key_bits"] == 256
        assert body["max_ttl"] == "365d"
        assert body["ttl"] == "30d"
        assert body["server_flag"] == true
        assert body["client_flag"] == false
        assert body["code_signing_flag"] == false
        assert body["email_protection_flag"] == true
      end)

      assert :ok =
               PKI.create_role("full-role", %{
                 allowed_domains: ["example.com", "example.org"],
                 allow_subdomains: true,
                 allow_any_name: false,
                 allow_bare_domains: true,
                 allow_localhost: false,
                 allow_ip_sans: true,
                 key_type: "ec",
                 key_bits: 256,
                 max_ttl: "365d",
                 ttl: "30d",
                 server_flag: true,
                 client_flag: false,
                 code_signing_flag: false,
                 email_protection_flag: true
               })
    end

    test "handles role creation error" do
      expect_post(400, %{
        "errors" => ["invalid role configuration"]
      })

      assert {:error, %Error{type: :invalid_request}} =
               PKI.create_role("invalid-role", %{
                 max_ttl: "invalid"
               })
    end

    test "uses custom mount path and timeout" do
      expect_post(204, %{}, fn url, _body, opts ->
        assert String.contains?(url, "custom-pki/roles/web-server")
        assert opts[:timeout] == 60_000
      end)

      assert :ok =
               PKI.create_role(
                 "web-server",
                 %{
                   allowed_domains: ["example.com"]
                 },
                 mount_path: "custom-pki",
                 timeout: 60_000
               )
    end
  end

  describe "read_role/2" do
    test "reads role successfully" do
      expect_get(
        200,
        %{
          "data" => %{
            "allowed_domains" => ["example.com"],
            "allow_subdomains" => true,
            "allow_any_name" => false,
            "key_type" => "rsa",
            "key_bits" => 2048,
            "max_ttl" => "90d",
            "ttl" => "30d",
            "server_flag" => true,
            "client_flag" => false
          }
        },
        fn url, _body, _opts ->
          assert String.contains?(url, "pki/roles/web-server")
        end
      )

      assert {:ok, role_info} = PKI.read_role("web-server")
      assert role_info.name == "web-server"
      assert role_info.allowed_domains == ["example.com"]
      assert role_info.allow_subdomains == true
      assert role_info.key_type == "rsa"
      assert role_info.key_bits == 2048
      assert role_info.max_ttl == "90d"
      assert role_info.server_flag == true
      assert role_info.client_flag == false
    end

    test "handles role not found error" do
      expect_get(404, %{
        "errors" => ["role not found"]
      })

      assert {:error, %Error{type: :not_found}} = PKI.read_role("nonexistent-role")
    end
  end

  describe "delete_role/2" do
    test "deletes role successfully" do
      expect_delete(204, %{}, fn url, _body, _opts ->
        assert String.contains?(url, "pki/roles/web-server")
      end)

      assert :ok = PKI.delete_role("web-server")
    end

    test "handles role not found error" do
      expect_delete(404, %{
        "errors" => ["role not found"]
      })

      assert {:error, %Error{type: :not_found}} = PKI.delete_role("nonexistent-role")
    end
  end

  describe "list_roles/1" do
    test "lists roles successfully" do
      expect_get(
        200,
        %{
          "data" => %{
            "keys" => ["web-server", "api-server", "client-cert"]
          }
        },
        fn url, _body, _opts ->
          assert String.contains?(url, "pki/roles?list=true")
        end
      )

      assert {:ok, roles} = PKI.list_roles()
      assert length(roles) == 3
      assert "web-server" in roles
      assert "api-server" in roles
      assert "client-cert" in roles
    end

    test "handles empty role list" do
      expect_get(200, %{
        "data" => %{
          "keys" => []
        }
      })

      assert {:ok, []} = PKI.list_roles()
    end
  end

  describe "read_crl/1" do
    test "reads CRL successfully" do
      crl_pem = "-----BEGIN X509 CRL-----\nMIIC...\n-----END X509 CRL-----"

      expect_get(200, crl_pem, fn url, _body, _opts ->
        assert String.contains?(url, "pki/crl/pem")
      end)

      assert {:ok, ^crl_pem} = PKI.read_crl()
    end

    test "handles CRL not available error" do
      expect_get(404, %{
        "errors" => ["CRL not available"]
      })

      assert {:error, %Error{type: :not_found}} = PKI.read_crl()
    end
  end

  describe "rotate_crl/1" do
    test "rotates CRL successfully" do
      expect_get(200, %{}, fn url, _body, _opts ->
        assert String.contains?(url, "pki/crl/rotate")
      end)

      assert :ok = PKI.rotate_crl()
    end

    test "handles CRL rotation error" do
      expect_get(500, %{
        "errors" => ["CRL rotation failed"]
      })

      assert {:error, %Error{type: :server_error}} = PKI.rotate_crl()
    end
  end

  describe "read_urls/1" do
    test "reads URLs configuration successfully" do
      expect_get(
        200,
        %{
          "data" => %{
            "issuing_certificates" => ["https://vault.example.com/v1/pki/ca"],
            "crl_distribution_points" => ["https://vault.example.com/v1/pki/crl"],
            "ocsp_servers" => ["https://vault.example.com/v1/pki/ocsp"]
          }
        },
        fn url, _body, _opts ->
          assert String.contains?(url, "pki/config/urls")
        end
      )

      assert {:ok, config} = PKI.read_urls()
      assert config["issuing_certificates"] == ["https://vault.example.com/v1/pki/ca"]
      assert config["crl_distribution_points"] == ["https://vault.example.com/v1/pki/crl"]
      assert config["ocsp_servers"] == ["https://vault.example.com/v1/pki/ocsp"]
    end
  end

  describe "write_urls/2" do
    test "writes URLs configuration successfully" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "pki/config/urls")
        assert body["issuing_certificates"] == ["https://vault.example.com/v1/pki/ca"]
        assert body["crl_distribution_points"] == ["https://vault.example.com/v1/pki/crl"]
      end)

      config = %{
        "issuing_certificates" => ["https://vault.example.com/v1/pki/ca"],
        "crl_distribution_points" => ["https://vault.example.com/v1/pki/crl"]
      }

      assert :ok = PKI.write_urls(config)
    end
  end

  describe "tidy/2" do
    test "starts tidy operation successfully" do
      expect_post(202, %{}, fn url, body, _opts ->
        assert String.contains?(url, "pki/tidy")
        assert body["tidy_cert_store"] == true
        assert body["tidy_revoked_certs"] == true
        assert body["safety_buffer"] == "72h"
      end)

      assert :ok =
               PKI.tidy(
                 tidy_cert_store: true,
                 tidy_revoked_certs: true,
                 safety_buffer: "72h"
               )
    end

    test "handles tidy operation error" do
      expect_post(400, %{
        "errors" => ["invalid tidy configuration"]
      })

      assert {:error, %Error{type: :invalid_request}} = PKI.tidy(safety_buffer: "invalid")
    end
  end

  describe "tidy_status/1" do
    test "reads tidy status successfully" do
      expect_get(
        200,
        %{
          "data" => %{
            "state" => "running",
            "error" => nil,
            "time_started" => "2025-01-01T00:00:00Z",
            "time_finished" => nil,
            "cert_store_deleted_count" => 42,
            "revoked_cert_deleted_count" => 13
          }
        },
        fn url, _body, _opts ->
          assert String.contains?(url, "pki/tidy-status")
        end
      )

      assert {:ok, status} = PKI.tidy_status()
      assert status["state"] == "running"
      assert status["cert_store_deleted_count"] == 42
      assert status["revoked_cert_deleted_count"] == 13
    end
  end

  describe "tidy_cancel/1" do
    test "cancels tidy operation successfully" do
      expect_post(200, %{}, fn url, body, _opts ->
        assert String.contains?(url, "pki/tidy-cancel")
        assert body == %{}
      end)

      assert :ok = PKI.tidy_cancel()
    end

    test "handles no running tidy operation" do
      expect_post(400, %{
        "errors" => ["no tidy operation running"]
      })

      assert {:error, %Error{type: :invalid_request}} = PKI.tidy_cancel()
    end
  end

  describe "delegation to sub-modules" do
    test "delegates CA operations to CA module" do
      # These are integration tests to ensure delegation works
      # The actual functionality is tested in the respective module tests

      # Mock a simple CA operation
      expect_post(200, %{
        "data" => %{
          "certificate" => "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
          "serial_number" => "39:dd:2e:90:b7:23:1f:8d"
        }
      })

      assert {:ok, _ca_info} = PKI.generate_root(%{common_name: "Test CA"})
    end

    test "delegates certificate operations to Certificates module" do
      # Mock a simple certificate operation
      expect_post(200, %{
        "data" => %{
          "certificate" => "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
          "serial_number" => "39:dd:2e:90:b7:23:1f:8d"
        }
      })

      assert {:ok, _cert_info} =
               PKI.issue_certificate("web-server", %{common_name: "example.com"})
    end

    test "delegates generate_intermediate to CA module" do
      expect_post(200, %{
        "data" => %{
          "csr" =>
            "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----",
          "private_key" =>
            "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
        }
      })

      assert {:ok, _result} = PKI.generate_intermediate(%{common_name: "Test CA"})
    end

    test "delegates import_ca to CA module" do
      expect_post(204, %{})

      assert :ok = PKI.import_ca("cert", "key")
    end

    test "delegates read_ca_certificate to CA module" do
      expect_get(200, "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----")

      assert {:ok, _cert} = PKI.read_ca_certificate()
    end

    test "delegates read_ca_chain to CA module" do
      expect_get(200, "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----")

      assert {:ok, _chain} = PKI.read_ca_chain()
    end

    test "delegates sign_certificate to Certificates module" do
      expect_post(200, %{
        "data" => %{
          "certificate" => "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
          "serial_number" => "39:dd:2e:90:b7:23:1f:8d"
        }
      })

      assert {:ok, _cert_info} =
               PKI.sign_certificate("web-server", "csr", %{common_name: "example.com"})
    end

    test "delegates sign_intermediate to CA module" do
      expect_post(200, %{
        "data" => %{
          "certificate" => "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
          "serial_number" => "39:dd:2e:90:b7:23:1f:8d"
        }
      })

      assert {:ok, _cert_info} = PKI.sign_intermediate("csr", %{common_name: "Intermediate CA"})
    end

    test "delegates sign_self_issued to sign_verbatim" do
      expect_post(200, %{
        "data" => %{
          "certificate" => "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
          "serial_number" => "39:dd:2e:90:b7:23:1f:8d"
        }
      })

      assert {:ok, _cert_info} = PKI.sign_self_issued("cert", %{ttl: "30d"})
    end

    test "delegates sign_verbatim to Certificates module" do
      expect_post(200, %{
        "data" => %{
          "certificate" => "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
          "serial_number" => "39:dd:2e:90:b7:23:1f:8d"
        }
      })

      assert {:ok, _cert_info} = PKI.sign_verbatim("csr", %{ttl: "30d"})
    end

    test "delegates read_certificate to Certificates module" do
      expect_get(200, "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----")

      assert {:ok, _cert} = PKI.read_certificate("39:dd:2e:90:b7:23:1f:8d")
    end

    test "delegates list_certificates to Certificates module" do
      expect_get(200, %{
        "data" => %{
          "keys" => ["39:dd:2e:90:b7:23:1f:8d"]
        }
      })

      assert {:ok, _serials} = PKI.list_certificates()
    end

    test "delegates revoke_certificate to Certificates module" do
      expect_post(200, %{})

      assert :ok = PKI.revoke_certificate("39:dd:2e:90:b7:23:1f:8d")
    end

    test "delegates revoke_certificate_with_key to Certificates module" do
      expect_post(200, %{})

      assert :ok = PKI.revoke_certificate_with_key("cert", "key")
    end
  end

  describe "error handling and edge cases" do
    test "handles network errors in role operations" do
      stub_request_raw(:post, :timeout)

      assert {:error, %Error{type: :network_error}} =
               PKI.create_role("test-role", %{
                 allowed_domains: ["example.com"]
               })
    end

    test "handles network errors in role read" do
      stub_request_raw(:get, :timeout)

      assert {:error, %Error{type: :network_error}} = PKI.read_role("test-role")
    end

    test "handles network errors in role delete" do
      stub_request_raw(:delete, :timeout)

      assert {:error, %Error{type: :network_error}} = PKI.delete_role("test-role")
    end

    test "handles network errors in role list" do
      stub_request_raw(:get, :timeout)

      assert {:error, %Error{type: :network_error}} = PKI.list_roles()
    end

    test "handles HTTP errors in role list" do
      expect_get(500, %{
        "errors" => ["internal server error"]
      })

      assert {:error, %Error{type: :server_error}} = PKI.list_roles()
    end

    test "handles missing keys in role list response" do
      expect_get(200, %{
        "data" => %{}
      })

      assert {:ok, []} = PKI.list_roles()
    end

    test "update_role delegates to create_role" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "pki/roles/test-role")
        assert body["allowed_domains"] == ["example.com"]
      end)

      assert :ok =
               PKI.update_role("test-role", %{
                 allowed_domains: ["example.com"]
               })
    end

    test "handles network errors in CRL operations" do
      stub_request_raw(:get, :timeout)

      assert {:error, %Error{type: :network_error}} = PKI.read_crl()
      assert {:error, %Error{type: :network_error}} = PKI.rotate_crl()
    end

    test "handles network errors in URLs configuration" do
      stub_request_raw(:get, :timeout)

      assert {:error, %Error{type: :network_error}} = PKI.read_urls()
    end

    test "handles HTTP errors in URLs configuration read" do
      expect_get(500, %{
        "errors" => ["internal server error"]
      })

      assert {:error, %Error{type: :server_error}} = PKI.read_urls()
    end

    test "handles network errors in URLs configuration write" do
      stub_request_raw(:post, :timeout)

      assert {:error, %Error{type: :network_error}} =
               PKI.write_urls(%{
                 "issuing_certificates" => ["https://vault.example.com/v1/pki/ca"]
               })
    end

    test "handles HTTP errors in URLs configuration write" do
      expect_post(400, %{
        "errors" => ["invalid configuration"]
      })

      assert {:error, %Error{type: :invalid_request}} =
               PKI.write_urls(%{
                 "invalid" => "config"
               })
    end

    test "handles network errors in tidy operations" do
      stub_request_raw(:post, :timeout)

      assert {:error, %Error{type: :network_error}} = PKI.tidy(tidy_cert_store: true)
    end

    test "handles network errors in tidy status" do
      stub_request_raw(:get, :timeout)

      assert {:error, %Error{type: :network_error}} = PKI.tidy_status()
    end

    test "handles HTTP errors in tidy status" do
      expect_get(500, %{
        "errors" => ["internal server error"]
      })

      assert {:error, %Error{type: :server_error}} = PKI.tidy_status()
    end

    test "handles network errors in tidy cancel" do
      stub_request_raw(:post, :timeout)

      assert {:error, %Error{type: :network_error}} = PKI.tidy_cancel()
    end

    test "build_role_payload ignores unknown options" do
      expect_post(204, %{}, fn _url, body, _opts ->
        # Should only include known options
        refute Map.has_key?(body, "unknown_option")
        refute Map.has_key?(body, "invalid_key")
        assert body["allowed_domains"] == ["example.com"]
      end)

      assert :ok =
               PKI.create_role("test-role", %{
                 allowed_domains: ["example.com"],
                 unknown_option: "should be ignored",
                 invalid_key: 123
               })
    end

    test "parse_role_response handles malformed data" do
      expect_get(200, %{}, fn url, _body, _opts ->
        assert String.contains?(url, "pki/roles/test-role")
      end)

      assert {:ok, role_info} = PKI.read_role("test-role")
      assert role_info.name == "test-role"
      assert role_info.allowed_domains == []
      assert role_info.key_type == "rsa"
      assert role_info.key_bits == 2048
    end

    test "build_tidy_payload with all options" do
      expect_post(202, %{}, fn _url, body, _opts ->
        assert body["tidy_cert_store"] == true
        assert body["tidy_revoked_certs"] == false
        assert body["safety_buffer"] == "24h"
      end)

      assert :ok =
               PKI.tidy(
                 tidy_cert_store: true,
                 tidy_revoked_certs: false,
                 safety_buffer: "24h",
                 unknown_option: "ignored"
               )
    end

    test "parse_role_response with non-map input" do
      expect_get(200, "not a map", fn url, _body, _opts ->
        assert String.contains?(url, "pki/roles/test-role")
      end)

      assert {:ok, role_info} = PKI.read_role("test-role")
      # The fallback only sets the name, other fields won't exist
      assert role_info.name == "test-role"
      # Don't check other fields as they won't exist in the fallback response
    end
  end
end
