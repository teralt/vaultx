defmodule Vaultx.Secrets.TransitTest do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Secrets.Transit
  alias Vaultx.Base.Error

  describe "create_key/3 with key type normalization" do
    test "creates key with atom key type" do
      expect_post(200, %{}, fn url, body, _opts ->
        assert String.contains?(url, "transit/keys/my-key")
        assert body["type"] == "aes256-gcm96"
      end)

      assert :ok = Transit.create_key("my-key", :aes256_gcm96)
    end

    test "creates key with string key type" do
      expect_post(200, %{}, fn url, body, _opts ->
        assert String.contains?(url, "transit/keys/my-key")
        assert body["type"] == "ed25519"
      end)

      assert :ok = Transit.create_key("my-key", "ed25519")
    end

    test "normalizes all supported atom key types" do
      key_type_mappings = [
        {:aes128_gcm96, "aes128-gcm96"},
        {:aes256_gcm96, "aes256-gcm96"},
        {:chacha20_poly1305, "chacha20-poly1305"},
        {:rsa_2048, "rsa-2048"},
        {:rsa_3072, "rsa-3072"},
        {:rsa_4096, "rsa-4096"},
        {:ecdsa_p256, "ecdsa-p256"},
        {:ecdsa_p384, "ecdsa-p384"},
        {:ecdsa_p521, "ecdsa-p521"},
        {:ed25519, "ed25519"},
        {:hmac, "hmac"},
        {:managed_key, "managed_key"}
      ]

      for {atom_type, string_type} <- key_type_mappings do
        expect_post(200, %{}, fn url, body, _opts ->
          assert String.contains?(url, "transit/keys/test-key")
          assert body["type"] == string_type
        end)

        assert :ok = Transit.create_key("test-key", atom_type)
      end
    end

    test "handles unknown atom key type" do
      expect_post(200, %{}, fn url, body, _opts ->
        assert String.contains?(url, "transit/keys/my-key")
        assert body["type"] == "unknown_type"
      end)

      assert :ok = Transit.create_key("my-key", :unknown_type)
    end
  end

  describe "key management delegation" do
    test "read_key delegates to Keys module" do
      key_data = %{
        "name" => "my-key",
        "type" => "aes256-gcm96",
        "supports_encryption" => true
      }

      expect_get(200, %{"data" => key_data})

      assert {:ok, key_info} = Transit.read_key("my-key")
      assert key_info.name == "my-key"
      assert key_info.type == "aes256-gcm96"
    end

    test "update_key_config delegates to Keys module" do
      expect_post(200, %{})

      assert :ok = Transit.update_key_config("my-key", %{"deletion_allowed" => true})
    end

    test "rotate_key delegates to Keys module" do
      expect_post(200, %{})

      assert :ok = Transit.rotate_key("my-key")
    end

    test "delete_key delegates to Keys module" do
      expect_delete(200, %{})

      assert :ok = Transit.delete_key("my-key")
    end

    test "list_keys delegates to Keys module" do
      expect_get(200, %{"data" => %{"keys" => ["key1", "key2"]}})

      assert {:ok, keys} = Transit.list_keys()
      assert keys == ["key1", "key2"]
    end
  end

  describe "encryption delegation" do
    test "encrypt delegates to Encryption module" do
      response_data = %{
        "ciphertext" => "vault:v1:encrypted",
        "key_version" => 1
      }

      expect_post(200, %{"data" => response_data})

      assert {:ok, result} = Transit.encrypt("my-key", "dGVzdA==")
      assert result.ciphertext == "vault:v1:encrypted"
    end

    test "decrypt delegates to Encryption module" do
      response_data = %{
        "plaintext" => "dGVzdA==",
        "key_version" => 1
      }

      expect_post(200, %{"data" => response_data})

      assert {:ok, result} = Transit.decrypt("my-key", "vault:v1:encrypted")
      assert result.plaintext == "dGVzdA=="
    end

    test "rewrap delegates to Encryption module" do
      response_data = %{
        "ciphertext" => "vault:v2:rewrapped",
        "key_version" => 2
      }

      expect_post(200, %{"data" => response_data})

      assert {:ok, result} = Transit.rewrap("my-key", "vault:v1:old")
      assert result.ciphertext == "vault:v2:rewrapped"
    end

    test "batch_encrypt delegates to Encryption module" do
      batch_results = [
        %{"ciphertext" => "vault:v1:encrypted1", "key_version" => 1}
      ]

      expect_post(200, %{"data" => %{"batch_results" => batch_results}})

      batch_items = [%{plaintext: "dGVzdA=="}]
      assert {:ok, results} = Transit.batch_encrypt("my-key", batch_items)
      assert length(results) == 1
    end
  end

  describe "sign/3" do
    test "signs data successfully" do
      response_data = %{
        "signature" => "vault:v1:signature-data",
        "key_version" => 1
      }

      expect_post(200, %{"data" => response_data}, fn url, body, _opts ->
        assert String.contains?(url, "transit/sign/signing-key")
        assert body["input"] == "dGVzdCBkYXRh"
      end)

      assert {:ok, result} = Transit.sign("signing-key", "dGVzdCBkYXRh")
      assert result.signature == "vault:v1:signature-data"
      assert result.key_version == 1
    end

    test "signs data with options" do
      response_data = %{
        "signature" => "vault:v1:signature-with-options",
        "key_version" => 1
      }

      expect_post(200, %{"data" => response_data}, fn url, body, _opts ->
        assert String.contains?(url, "transit/sign/signing-key")
        assert body["input"] == "dGVzdCBkYXRh"
        assert body["hash_algorithm"] == "sha2-256"
        assert body["signature_algorithm"] == "pss"
        assert body["prehashed"] == true
        assert body["context"] == "Y29udGV4dA=="
      end)

      assert {:ok, result} =
               Transit.sign("signing-key", "dGVzdCBkYXRh",
                 hash_algorithm: "sha2-256",
                 signature_algorithm: "pss",
                 prehashed: true,
                 context: "Y29udGV4dA=="
               )

      assert result.signature == "vault:v1:signature-with-options"
    end

    test "signs data with custom mount path" do
      response_data = %{
        "signature" => "vault:v1:custom-mount-signature",
        "key_version" => 1
      }

      expect_post(200, %{"data" => response_data}, fn url, body, _opts ->
        assert String.contains?(url, "encryption/sign/signing-key")
        assert body["input"] == "dGVzdCBkYXRh"
      end)

      assert {:ok, result} = Transit.sign("signing-key", "dGVzdCBkYXRh", mount_path: "encryption")
      assert result.signature == "vault:v1:custom-mount-signature"
    end

    test "handles key not found for signing" do
      expect_post(404, %{"errors" => ["key not found"]})

      assert {:error, %Error{type: :key_not_found}} = Transit.sign("nonexistent-key", "dGVzdA==")
    end

    test "handles signing failure" do
      expect_post(400, %{"errors" => ["signing failed"]})

      assert {:error, %Error{}} = Transit.sign("signing-key", "invalid-data")
    end

    test "handles malformed signing response" do
      expect_post(200, %{"data" => "invalid"})

      assert {:ok, result} = Transit.sign("signing-key", "dGVzdA==")
      assert result.signature == ""
      assert result.key_version == 1
    end

    test "handles network error" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{type: :network_error}} = Transit.sign("signing-key", "dGVzdA==")
    end

    test "ignores invalid signing options" do
      response_data = %{
        "signature" => "vault:v1:signature",
        "key_version" => 1
      }

      expect_post(200, %{"data" => response_data}, fn url, body, _opts ->
        assert String.contains?(url, "transit/sign/signing-key")
        assert body["input"] == "dGVzdA=="
        # Invalid options should be filtered out
        refute Map.has_key?(body, "invalid_option")
        refute Map.has_key?(body, "another_invalid")
      end)

      assert {:ok, _result} =
               Transit.sign("signing-key", "dGVzdA==",
                 invalid_option: "should be ignored",
                 another_invalid: 123
               )
    end

    test "ignores invalid option types in signing" do
      response_data = %{
        "signature" => "vault:v1:signature",
        "key_version" => 1
      }

      expect_post(200, %{"data" => response_data}, fn url, body, _opts ->
        assert String.contains?(url, "transit/sign/signing-key")
        assert body["input"] == "dGVzdA=="
        # Invalid option types should be filtered out
        refute Map.has_key?(body, "hash_algorithm")
        refute Map.has_key?(body, "signature_algorithm")
        refute Map.has_key?(body, "prehashed")
      end)

      # Test with invalid option types to cover the catch-all cases
      assert {:ok, _result} =
               Transit.sign("signing-key", "dGVzdA==",
                 # invalid type
                 hash_algorithm: 123,
                 # invalid type
                 signature_algorithm: [],
                 # invalid type
                 prehashed: "invalid",
                 # invalid type
                 context: %{},
                 # invalid type
                 key_version: []
               )
    end
  end

  describe "verify/4" do
    test "verifies signature successfully" do
      expect_post(200, %{"data" => %{"valid" => true}}, fn url, body, _opts ->
        assert String.contains?(url, "transit/verify/signing-key")
        assert body["input"] == "dGVzdCBkYXRh"
        assert body["signature"] == "vault:v1:signature-data"
      end)

      assert {:ok, valid} =
               Transit.verify("signing-key", "dGVzdCBkYXRh", "vault:v1:signature-data")

      assert valid == true
    end

    test "verifies invalid signature" do
      expect_post(200, %{"data" => %{"valid" => false}}, fn url, body, _opts ->
        assert String.contains?(url, "transit/verify/signing-key")
        assert body["input"] == "dGVzdCBkYXRh"
        assert body["signature"] == "vault:v1:invalid-signature"
      end)

      assert {:ok, valid} =
               Transit.verify("signing-key", "dGVzdCBkYXRh", "vault:v1:invalid-signature")

      assert valid == false
    end

    test "verifies signature with options" do
      expect_post(200, %{"data" => %{"valid" => true}}, fn url, body, _opts ->
        assert String.contains?(url, "transit/verify/signing-key")
        assert body["input"] == "dGVzdCBkYXRh"
        assert body["signature"] == "vault:v1:signature"
        assert body["hash_algorithm"] == "sha2-256"
        assert body["signature_algorithm"] == "pss"
        assert body["prehashed"] == true
        assert body["context"] == "Y29udGV4dA=="
      end)

      assert {:ok, valid} =
               Transit.verify("signing-key", "dGVzdCBkYXRh", "vault:v1:signature",
                 hash_algorithm: "sha2-256",
                 signature_algorithm: "pss",
                 prehashed: true,
                 context: "Y29udGV4dA=="
               )

      assert valid == true
    end

    test "handles key not found for verification" do
      expect_post(404, %{"errors" => ["key not found"]})

      assert {:error, %Error{type: :key_not_found}} =
               Transit.verify("nonexistent-key", "dGVzdA==", "sig")
    end

    test "handles verification failure" do
      expect_post(400, %{"errors" => ["verification failed"]})

      assert {:error, %Error{}} = Transit.verify("signing-key", "dGVzdA==", "invalid-signature")
    end

    test "handles missing valid field in response" do
      expect_post(200, %{"data" => %{}})

      assert {:ok, valid} = Transit.verify("signing-key", "dGVzdA==", "vault:v1:signature")
      assert valid == false
    end

    test "ignores invalid option types in verify" do
      expect_post(200, %{"data" => %{"valid" => true}}, fn url, body, _opts ->
        assert String.contains?(url, "transit/verify/signing-key")
        assert body["input"] == "dGVzdA=="
        assert body["signature"] == "vault:v1:signature"
        # Invalid option types should be filtered out
        refute Map.has_key?(body, "hash_algorithm")
        refute Map.has_key?(body, "signature_algorithm")
        refute Map.has_key?(body, "prehashed")
      end)

      # Test with invalid option types to cover the catch-all cases
      assert {:ok, valid} =
               Transit.verify("signing-key", "dGVzdA==", "vault:v1:signature",
                 # invalid type
                 hash_algorithm: 123,
                 # invalid type
                 signature_algorithm: [],
                 # invalid type
                 prehashed: "invalid",
                 # invalid type
                 context: %{},
                 # invalid type
                 key_version: []
               )

      assert valid == true
    end

    test "handles network error" do
      stub_request_raw(:post, %Req.TransportError{reason: :econnrefused})

      assert {:error, %Error{type: :network_error}} =
               Transit.verify("signing-key", "dGVzdA==", "sig")
    end
  end

  describe "hmac/3" do
    test "generates HMAC successfully" do
      response_data = %{
        "hmac" => "vault:v1:hmac-data",
        "key_version" => 1
      }

      expect_post(200, %{"data" => response_data}, fn url, body, _opts ->
        assert String.contains?(url, "transit/hmac/hmac-key")
        assert body["input"] == "dGVzdCBkYXRh"
      end)

      assert {:ok, result} = Transit.hmac("hmac-key", "dGVzdCBkYXRh")
      assert result.hmac == "vault:v1:hmac-data"
      assert result.key_version == 1
    end

    test "generates HMAC with options" do
      response_data = %{
        "hmac" => "vault:v2:hmac-with-options",
        "key_version" => 2
      }

      expect_post(200, %{"data" => response_data}, fn url, body, _opts ->
        assert String.contains?(url, "transit/hmac/hmac-key")
        assert body["input"] == "dGVzdCBkYXRh"
        assert body["hash_algorithm"] == "sha2-256"
        assert body["key_version"] == 2
      end)

      assert {:ok, result} =
               Transit.hmac("hmac-key", "dGVzdCBkYXRh",
                 hash_algorithm: "sha2-256",
                 key_version: 2
               )

      assert result.hmac == "vault:v2:hmac-with-options"
      assert result.key_version == 2
    end

    test "handles key not found for HMAC" do
      expect_post(404, %{"errors" => ["key not found"]})

      assert {:error, %Error{type: :key_not_found}} = Transit.hmac("nonexistent-key", "dGVzdA==")
    end

    test "handles HMAC generation failure" do
      expect_post(400, %{"errors" => ["HMAC generation failed"]})

      assert {:error, %Error{}} = Transit.hmac("hmac-key", "invalid-data")
    end

    test "handles malformed HMAC response" do
      expect_post(200, %{"data" => "invalid"})

      assert {:ok, result} = Transit.hmac("hmac-key", "dGVzdA==")
      assert result.hmac == ""
      assert result.key_version == 1
    end

    test "ignores invalid option types in HMAC" do
      response_data = %{
        "hmac" => "vault:v1:hmac-data",
        "key_version" => 1
      }

      expect_post(200, %{"data" => response_data}, fn url, body, _opts ->
        assert String.contains?(url, "transit/hmac/hmac-key")
        assert body["input"] == "dGVzdA=="
        # Invalid option types should be filtered out
        refute Map.has_key?(body, "hash_algorithm")
        refute Map.has_key?(body, "key_version")
      end)

      # Test with invalid option types to cover the catch-all cases
      assert {:ok, result} =
               Transit.hmac("hmac-key", "dGVzdA==",
                 # invalid type
                 hash_algorithm: 123,
                 # invalid type
                 key_version: "invalid"
               )

      assert result.hmac == "vault:v1:hmac-data"
    end

    test "ignores unrecognized HMAC options" do
      response_data = %{
        "hmac" => "vault:v1:hmac-data",
        "key_version" => 1
      }

      expect_post(200, %{"data" => response_data}, fn url, body, _opts ->
        assert String.contains?(url, "transit/hmac/hmac-key")
        assert body["input"] == "dGVzdA=="
        # Unrecognized options should be ignored (covers the _other, acc -> acc case)
        refute Map.has_key?(body, "unrecognized_option")
        refute Map.has_key?(body, "unknown_key")
      end)

      # Test with unrecognized options to trigger the catch-all case
      assert {:ok, result} =
               Transit.hmac("hmac-key", "dGVzdA==",
                 unrecognized_option: "should be ignored",
                 unknown_key: 456
               )

      assert result.hmac == "vault:v1:hmac-data"
    end

    test "handles network error" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{type: :network_error}} = Transit.hmac("hmac-key", "dGVzdA==")
    end
  end

  describe "verify_hmac/4" do
    test "verifies HMAC successfully" do
      expect_post(200, %{"data" => %{"valid" => true}}, fn url, body, _opts ->
        assert String.contains?(url, "transit/verify/hmac-key")
        assert body["input"] == "dGVzdCBkYXRh"
        assert body["hmac"] == "vault:v1:hmac-data"
      end)

      assert {:ok, valid} = Transit.verify_hmac("hmac-key", "dGVzdCBkYXRh", "vault:v1:hmac-data")
      assert valid == true
    end

    test "verifies invalid HMAC" do
      expect_post(200, %{"data" => %{"valid" => false}}, fn url, body, _opts ->
        assert String.contains?(url, "transit/verify/hmac-key")
        assert body["input"] == "dGVzdCBkYXRh"
        assert body["hmac"] == "vault:v1:invalid-hmac"
      end)

      assert {:ok, valid} =
               Transit.verify_hmac("hmac-key", "dGVzdCBkYXRh", "vault:v1:invalid-hmac")

      assert valid == false
    end

    test "verifies HMAC with options" do
      expect_post(200, %{"data" => %{"valid" => true}}, fn url, body, _opts ->
        assert String.contains?(url, "transit/verify/hmac-key")
        assert body["input"] == "dGVzdCBkYXRh"
        assert body["hmac"] == "vault:v1:hmac"
        assert body["hash_algorithm"] == "sha2-256"
      end)

      assert {:ok, valid} =
               Transit.verify_hmac("hmac-key", "dGVzdCBkYXRh", "vault:v1:hmac",
                 hash_algorithm: "sha2-256"
               )

      assert valid == true
    end

    test "handles key not found for HMAC verification" do
      expect_post(404, %{"errors" => ["key not found"]})

      assert {:error, %Error{type: :key_not_found}} =
               Transit.verify_hmac("nonexistent-key", "dGVzdA==", "hmac")
    end

    test "handles HMAC verification failure" do
      expect_post(400, %{"errors" => ["HMAC verification failed"]})

      assert {:error, %Error{}} = Transit.verify_hmac("hmac-key", "dGVzdA==", "invalid-hmac")
    end

    test "handles missing valid field in HMAC response" do
      expect_post(200, %{"data" => %{}})

      assert {:ok, valid} = Transit.verify_hmac("hmac-key", "dGVzdA==", "vault:v1:hmac")
      assert valid == false
    end

    test "ignores unrecognized HMAC verification options" do
      expect_post(200, %{"data" => %{"valid" => true}}, fn url, body, _opts ->
        assert String.contains?(url, "transit/verify/hmac-key")
        assert body["input"] == "dGVzdA=="
        assert body["hmac"] == "vault:v1:hmac"
        # Unrecognized options should be ignored (covers the _other, acc -> acc case)
        refute Map.has_key?(body, "unrecognized_option")
        refute Map.has_key?(body, "unknown_key")
      end)

      # Test with unrecognized options to trigger the catch-all case in build_verify_hmac_payload
      assert {:ok, valid} =
               Transit.verify_hmac("hmac-key", "dGVzdA==", "vault:v1:hmac",
                 unrecognized_option: "should be ignored",
                 unknown_key: 456
               )

      assert valid == true
    end

    test "handles network error" do
      stub_request_raw(:post, %Req.TransportError{reason: :econnrefused})

      assert {:error, %Error{type: :network_error}} =
               Transit.verify_hmac("hmac-key", "dGVzdA==", "hmac")
    end
  end

  describe "generate_random/2" do
    test "generates random data successfully" do
      response_data = %{
        "random_bytes" => "base64-encoded-random-data"
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.contains?(url, "transit/random/32")
      end)

      assert {:ok, result} = Transit.generate_random(32)
      assert result.random_bytes == "base64-encoded-random-data"
    end

    test "generates random data with custom format" do
      response_data = %{
        "random_bytes" => "hex-encoded-random-data"
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.contains?(url, "transit/random/16")
      end)

      assert {:ok, result} = Transit.generate_random(16, format: "hex")
      assert result.random_bytes == "hex-encoded-random-data"
    end

    test "generates random data with custom mount path" do
      response_data = %{
        "random_bytes" => "custom-mount-random-data"
      }

      expect_get(200, %{"data" => response_data}, fn url, _body, _opts ->
        assert String.contains?(url, "encryption/random/64")
      end)

      assert {:ok, result} = Transit.generate_random(64, mount_path: "encryption")
      assert result.random_bytes == "custom-mount-random-data"
    end

    test "handles random generation failure" do
      expect_get(400, %{"errors" => ["random generation failed"]})

      assert {:error, %Error{}} = Transit.generate_random(32)
    end

    test "handles malformed random response" do
      expect_get(200, %{"data" => "invalid"})

      assert {:ok, result} = Transit.generate_random(32)
      assert result.random_bytes == ""
    end

    test "handles missing data field in random response" do
      expect_get(200, %{})

      assert {:ok, result} = Transit.generate_random(32)
      assert result.random_bytes == ""
    end

    test "handles network error" do
      stub_request_raw(:get, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{type: :network_error}} = Transit.generate_random(32)
    end
  end
end
