defmodule Vaultx.Secrets.Transit.EncryptionTest do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Secrets.Transit.Encryption
  alias Vaultx.Base.Error

  describe "encrypt/3" do
    test "encrypts data successfully" do
      response_data = %{
        "ciphertext" => "vault:v1:8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM13ok481zoCmHnSeDX9vyf7w==",
        "key_version" => 1
      }

      expect_post(200, %{"data" => response_data}, fn url, body, _opts ->
        assert String.contains?(url, "transit/encrypt/my-key")
        assert body["plaintext"] == "dGVzdCBkYXRh"
      end)

      assert {:ok, result} = Encryption.encrypt("my-key", "dGVzdCBkYXRh")

      assert result.ciphertext ==
               "vault:v1:8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM13ok481zoCmHnSeDX9vyf7w=="

      assert result.key_version == 1
    end

    test "encrypts data with context" do
      response_data = %{
        "ciphertext" => "vault:v1:context-encrypted-data",
        "key_version" => 1
      }

      expect_post(200, %{"data" => response_data}, fn url, body, _opts ->
        assert String.contains?(url, "transit/encrypt/derived-key")
        assert body["plaintext"] == "dGVzdCBkYXRh"
        assert body["context"] == "Y29udGV4dA=="
      end)

      assert {:ok, result} =
               Encryption.encrypt("derived-key", "dGVzdCBkYXRh", context: "Y29udGV4dA==")

      assert result.ciphertext == "vault:v1:context-encrypted-data"
      assert result.key_version == 1
    end

    test "encrypts data with all options" do
      response_data = %{
        "ciphertext" => "vault:v2:full-options-encrypted",
        "key_version" => 2
      }

      expect_post(200, %{"data" => response_data}, fn url, body, _opts ->
        assert String.contains?(url, "transit/encrypt/my-key")
        assert body["plaintext"] == "dGVzdCBkYXRh"
        assert body["context"] == "Y29udGV4dA=="
        assert body["nonce"] == "bm9uY2U="
        assert body["key_version"] == 2
        assert body["associated_data"] == "YWRhdGE="
        assert body["type"] == "aead"
      end)

      assert {:ok, result} =
               Encryption.encrypt("my-key", "dGVzdCBkYXRh",
                 context: "Y29udGV4dA==",
                 nonce: "bm9uY2U=",
                 key_version: 2,
                 associated_data: "YWRhdGE=",
                 type: "aead"
               )

      assert result.key_version == 2
    end

    test "encrypts data with custom mount path" do
      response_data = %{
        "ciphertext" => "vault:v1:custom-mount-encrypted",
        "key_version" => 1
      }

      expect_post(200, %{"data" => response_data}, fn url, body, _opts ->
        assert String.contains?(url, "encryption/encrypt/my-key")
        assert body["plaintext"] == "dGVzdCBkYXRh"
      end)

      assert {:ok, result} =
               Encryption.encrypt("my-key", "dGVzdCBkYXRh", mount_path: "encryption")

      assert result.ciphertext == "vault:v1:custom-mount-encrypted"
    end

    test "handles key not found" do
      expect_post(404, %{"errors" => ["key not found"]})

      assert {:error, %Error{type: :key_not_found}} =
               Encryption.encrypt("nonexistent-key", "dGVzdA==")
    end

    test "handles encryption failure" do
      expect_post(400, %{"errors" => ["encryption failed"]})

      assert {:error, %Error{}} = Encryption.encrypt("my-key", "invalid-data")
    end

    test "handles malformed response" do
      expect_post(200, %{"data" => "invalid"})

      assert {:ok, result} = Encryption.encrypt("my-key", "dGVzdA==")
      assert result.ciphertext == ""
      assert result.key_version == 1
    end

    test "handles missing data field" do
      expect_post(200, %{})

      assert {:ok, result} = Encryption.encrypt("my-key", "dGVzdA==")
      assert result.ciphertext == ""
      assert result.key_version == 1
    end

    test "handles network error" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{type: :network_error}} = Encryption.encrypt("my-key", "dGVzdA==")
    end

    test "ignores invalid options" do
      response_data = %{
        "ciphertext" => "vault:v1:encrypted",
        "key_version" => 1
      }

      expect_post(200, %{"data" => response_data}, fn url, body, _opts ->
        assert String.contains?(url, "transit/encrypt/my-key")
        assert body["plaintext"] == "dGVzdA=="
        # Invalid options should be filtered out
        refute Map.has_key?(body, "invalid_option")
        refute Map.has_key?(body, "another_invalid")
      end)

      assert {:ok, _result} =
               Encryption.encrypt("my-key", "dGVzdA==",
                 invalid_option: "should be ignored",
                 another_invalid: 123
               )
    end
  end

  describe "decrypt/3" do
    test "decrypts data successfully" do
      response_data = %{
        "plaintext" => "dGVzdCBkYXRh",
        "key_version" => 1
      }

      expect_post(200, %{"data" => response_data}, fn url, body, _opts ->
        assert String.contains?(url, "transit/decrypt/my-key")

        assert body["ciphertext"] ==
                 "vault:v1:8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM13ok481zoCmHnSeDX9vyf7w=="
      end)

      ciphertext = "vault:v1:8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM13ok481zoCmHnSeDX9vyf7w=="
      assert {:ok, result} = Encryption.decrypt("my-key", ciphertext)
      assert result.plaintext == "dGVzdCBkYXRh"
      assert result.key_version == 1
    end

    test "decrypts data with context" do
      response_data = %{
        "plaintext" => "dGVzdCBkYXRh",
        "key_version" => 1
      }

      expect_post(200, %{"data" => response_data}, fn url, body, _opts ->
        assert String.contains?(url, "transit/decrypt/derived-key")
        assert body["ciphertext"] == "vault:v1:context-encrypted-data"
        assert body["context"] == "Y29udGV4dA=="
      end)

      assert {:ok, result} =
               Encryption.decrypt("derived-key", "vault:v1:context-encrypted-data",
                 context: "Y29udGV4dA=="
               )

      assert result.plaintext == "dGVzdCBkYXRh"
    end

    test "decrypts data with all options" do
      response_data = %{
        "plaintext" => "dGVzdCBkYXRh",
        "key_version" => 2
      }

      expect_post(200, %{"data" => response_data}, fn url, body, _opts ->
        assert String.contains?(url, "transit/decrypt/my-key")
        assert body["ciphertext"] == "vault:v2:full-options-encrypted"
        assert body["context"] == "Y29udGV4dA=="
        assert body["nonce"] == "bm9uY2U="
        assert body["associated_data"] == "YWRhdGE="
      end)

      assert {:ok, result} =
               Encryption.decrypt("my-key", "vault:v2:full-options-encrypted",
                 context: "Y29udGV4dA==",
                 nonce: "bm9uY2U=",
                 associated_data: "YWRhdGE="
               )

      assert result.key_version == 2
    end

    test "decrypts data with custom mount path" do
      response_data = %{
        "plaintext" => "dGVzdCBkYXRh",
        "key_version" => 1
      }

      expect_post(200, %{"data" => response_data}, fn url, body, _opts ->
        assert String.contains?(url, "encryption/decrypt/my-key")
        assert body["ciphertext"] == "vault:v1:custom-mount-encrypted"
      end)

      assert {:ok, result} =
               Encryption.decrypt("my-key", "vault:v1:custom-mount-encrypted",
                 mount_path: "encryption"
               )

      assert result.plaintext == "dGVzdCBkYXRh"
    end

    test "handles key not found" do
      expect_post(404, %{"errors" => ["key not found"]})

      assert {:error, %Error{type: :key_not_found}} =
               Encryption.decrypt("nonexistent-key", "vault:v1:data")
    end

    test "handles decryption failure" do
      expect_post(400, %{"errors" => ["decryption failed"]})

      assert {:error, %Error{}} = Encryption.decrypt("my-key", "invalid-ciphertext")
    end

    test "handles malformed response" do
      expect_post(200, %{"data" => "invalid"})

      assert {:ok, result} = Encryption.decrypt("my-key", "vault:v1:data")
      assert result.plaintext == ""
      assert result.key_version == 1
    end

    test "handles network error" do
      stub_request_raw(:post, %Req.TransportError{reason: :econnrefused})

      assert {:error, %Error{type: :network_error}} =
               Encryption.decrypt("my-key", "vault:v1:data")
    end
  end

  describe "rewrap/3" do
    test "rewraps data successfully" do
      response_data = %{
        "ciphertext" => "vault:v2:new-wrapped-data",
        "key_version" => 2
      }

      expect_post(200, %{"data" => response_data}, fn url, body, _opts ->
        assert String.contains?(url, "transit/rewrap/my-key")
        assert body["ciphertext"] == "vault:v1:old-wrapped-data"
      end)

      assert {:ok, result} = Encryption.rewrap("my-key", "vault:v1:old-wrapped-data")
      assert result.ciphertext == "vault:v2:new-wrapped-data"
      assert result.key_version == 2
    end

    test "rewraps data with context" do
      response_data = %{
        "ciphertext" => "vault:v2:context-rewrapped",
        "key_version" => 2
      }

      expect_post(200, %{"data" => response_data}, fn url, body, _opts ->
        assert String.contains?(url, "transit/rewrap/derived-key")
        assert body["ciphertext"] == "vault:v1:old-context-data"
        assert body["context"] == "Y29udGV4dA=="
      end)

      assert {:ok, result} =
               Encryption.rewrap("derived-key", "vault:v1:old-context-data",
                 context: "Y29udGV4dA=="
               )

      assert result.key_version == 2
    end

    test "rewraps data with all options" do
      response_data = %{
        "ciphertext" => "vault:v3:full-rewrapped",
        "key_version" => 3
      }

      expect_post(200, %{"data" => response_data}, fn url, body, _opts ->
        assert String.contains?(url, "transit/rewrap/my-key")
        assert body["ciphertext"] == "vault:v1:old-data"
        assert body["context"] == "Y29udGV4dA=="
        assert body["nonce"] == "bm9uY2U="
        assert body["key_version"] == 3
      end)

      assert {:ok, result} =
               Encryption.rewrap("my-key", "vault:v1:old-data",
                 context: "Y29udGV4dA==",
                 nonce: "bm9uY2U=",
                 key_version: 3
               )

      assert result.key_version == 3
    end

    test "handles key not found" do
      expect_post(404, %{"errors" => ["key not found"]})

      assert {:error, %Error{type: :key_not_found}} =
               Encryption.rewrap("nonexistent-key", "vault:v1:data")
    end

    test "handles rewrap failure" do
      expect_post(400, %{"errors" => ["rewrap failed"]})

      assert {:error, %Error{}} = Encryption.rewrap("my-key", "invalid-ciphertext")
    end

    test "ignores unrecognized rewrap options" do
      response_data = %{
        "ciphertext" => "vault:v2:rewrapped",
        "key_version" => 2
      }

      expect_post(200, %{"data" => response_data}, fn url, body, _opts ->
        assert String.contains?(url, "transit/rewrap/my-key")
        assert body["ciphertext"] == "vault:v1:old"
        # Unrecognized options should be ignored (covers the _other, acc -> acc case)
        refute Map.has_key?(body, "unrecognized_option")
        refute Map.has_key?(body, "unknown_key")
      end)

      # Test with unrecognized options to trigger the catch-all case in build_rewrap_payload
      assert {:ok, result} =
               Encryption.rewrap("my-key", "vault:v1:old",
                 unrecognized_option: "should be ignored",
                 unknown_key: 456
               )

      assert result.ciphertext == "vault:v2:rewrapped"
    end

    test "handles network error" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{type: :network_error}} = Encryption.rewrap("my-key", "vault:v1:data")
    end
  end

  describe "batch_encrypt/3" do
    test "batch encrypts data successfully" do
      batch_results = [
        %{"ciphertext" => "vault:v1:encrypted1", "key_version" => 1},
        %{"ciphertext" => "vault:v1:encrypted2", "key_version" => 1}
      ]

      response_data = %{"batch_results" => batch_results}

      expect_post(200, %{"data" => response_data}, fn url, body, _opts ->
        assert String.contains?(url, "transit/encrypt/my-key")
        batch_input = body["batch_input"]
        assert is_list(batch_input)
        assert length(batch_input) == 2
      end)

      batch_items = [
        %{plaintext: "dGVzdDE="},
        %{plaintext: "dGVzdDI=", context: "Y29udGV4dA=="}
      ]

      assert {:ok, results} = Encryption.batch_encrypt("my-key", batch_items)
      assert length(results) == 2
      assert Enum.at(results, 0).ciphertext == "vault:v1:encrypted1"
      assert Enum.at(results, 1).ciphertext == "vault:v1:encrypted2"
    end

    test "handles empty batch results" do
      expect_post(200, %{"data" => %{}})

      batch_items = [%{plaintext: "dGVzdA=="}]
      assert {:ok, results} = Encryption.batch_encrypt("my-key", batch_items)
      assert results == []
    end

    test "handles malformed batch results" do
      expect_post(200, %{"data" => %{"batch_results" => "invalid"}})

      batch_items = [%{plaintext: "dGVzdA=="}]
      assert {:ok, results} = Encryption.batch_encrypt("my-key", batch_items)
      assert results == []
    end

    test "handles key not found for batch encryption" do
      expect_post(404, %{"errors" => ["key not found"]})

      batch_items = [%{plaintext: "dGVzdA=="}]

      assert {:error, %Error{type: :key_not_found}} =
               Encryption.batch_encrypt("nonexistent-key", batch_items)
    end

    test "handles batch encryption failure" do
      expect_post(400, %{"errors" => ["batch encryption failed"]})

      batch_items = [%{plaintext: "dGVzdA=="}]
      assert {:error, %Error{}} = Encryption.batch_encrypt("my-key", batch_items)
    end

    test "handles network error" do
      stub_request_raw(:post, %Req.TransportError{reason: :econnrefused})

      batch_items = [%{plaintext: "dGVzdA=="}]

      assert {:error, %Error{type: :network_error}} =
               Encryption.batch_encrypt("my-key", batch_items)
    end
  end

  describe "build_encrypt_payload/2 edge cases" do
    test "ignores invalid option types" do
      response_data = %{
        "ciphertext" => "vault:v1:encrypted",
        "key_version" => 1
      }

      expect_post(200, %{"data" => response_data}, fn url, body, _opts ->
        assert String.contains?(url, "transit/encrypt/my-key")
        assert body["plaintext"] == "dGVzdA=="
        # Invalid options should be filtered out
        refute Map.has_key?(body, "invalid_context")
        refute Map.has_key?(body, "invalid_nonce")
        refute Map.has_key?(body, "invalid_key_version")
      end)

      # Test with invalid option types to cover the catch-all case in build_encrypt_payload
      assert {:ok, _result} =
               Encryption.encrypt("my-key", "dGVzdA==",
                 # invalid type
                 context: 123,
                 # invalid type
                 nonce: [],
                 # invalid type
                 key_version: "invalid",
                 # invalid type
                 associated_data: %{},
                 # invalid type
                 type: 456
               )
    end

    test "handles unknown option keys" do
      response_data = %{
        "ciphertext" => "vault:v1:encrypted",
        "key_version" => 1
      }

      expect_post(200, %{"data" => response_data}, fn url, body, _opts ->
        assert String.contains?(url, "transit/encrypt/my-key")
        assert body["plaintext"] == "dGVzdA=="
        # Unknown options should be ignored
        refute Map.has_key?(body, "unknown_option")
        refute Map.has_key?(body, "random_key")
      end)

      # Test with unknown option keys to cover the catch-all case
      assert {:ok, _result} =
               Encryption.encrypt("my-key", "dGVzdA==",
                 unknown_option: "value",
                 random_key: 123,
                 another_unknown: []
               )
    end

    test "ignores unrecognized option tuples" do
      response_data = %{
        "ciphertext" => "vault:v1:encrypted",
        "key_version" => 1
      }

      expect_post(200, %{"data" => response_data}, fn url, body, _opts ->
        assert String.contains?(url, "transit/encrypt/my-key")
        assert body["plaintext"] == "dGVzdA=="
        # Unrecognized options should be ignored (covers the _other, acc -> acc case)
        refute Map.has_key?(body, "unrecognized_key")
      end)

      # Test with an option that doesn't match any known pattern to trigger the catch-all
      assert {:ok, _result} =
               Encryption.encrypt("my-key", "dGVzdA==", unrecognized_key: "should be ignored")
    end
  end

  describe "parse_batch_encrypt_response/1 edge cases" do
    test "handles non-map data" do
      expect_post(200, %{"data" => "not a map"})

      batch_items = [%{plaintext: "dGVzdA=="}]
      assert {:ok, results} = Encryption.batch_encrypt("my-key", batch_items)
      assert results == []
    end
  end
end
