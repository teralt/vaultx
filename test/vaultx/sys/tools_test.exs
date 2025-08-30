defmodule Vaultx.Sys.ToolsTest do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Sys.Tools
  alias Vaultx.Base.Error

  # Sample API responses
  @random_response %{
    "data" => %{
      "random_bytes" => "dGVzdCByYW5kb20gZGF0YQ=="
    }
  }

  @hash_response %{
    "data" => %{
      "sum" => "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
    }
  }

  describe "generate_random/1" do
    test "generates random bytes with default parameters" do
      expect_post(200, @random_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/tools/random/platform/32")
        assert body["format"] == "base64"
      end)

      assert {:ok, result} = Tools.generate_random()
      assert result.random_bytes == "dGVzdCByYW5kb20gZGF0YQ=="
    end

    test "generates random bytes with custom parameters" do
      expect_post(200, @random_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/tools/random/seal/64")
        assert body["format"] == "hex"
      end)

      assert {:ok, result} =
               Tools.generate_random(
                 bytes: 64,
                 format: "hex",
                 source: "seal"
               )

      assert result.random_bytes == "dGVzdCByYW5kb20gZGF0YQ=="
    end

    test "validates byte count parameter" do
      assert {:error, %Error{} = error} = Tools.generate_random(bytes: 0)
      assert error.type == :invalid_parameter
      assert String.contains?(error.message, "Invalid byte count: 0")
      assert error.details.valid_range == "1-1024"
      assert error.details.provided == 0
    end

    test "validates byte count upper limit" do
      assert {:error, %Error{} = error} = Tools.generate_random(bytes: 2048)
      assert error.type == :invalid_parameter
      assert String.contains?(error.message, "Invalid byte count: 2048")
    end

    test "validates format parameter" do
      assert {:error, %Error{} = error} = Tools.generate_random(format: "invalid")
      assert error.type == :invalid_parameter
      assert String.contains?(error.message, "Invalid format: invalid")
      assert error.details.valid_formats == ~w(base64 hex)
      assert error.details.provided == "invalid"
    end

    test "validates source parameter" do
      assert {:error, %Error{} = error} = Tools.generate_random(source: "invalid")
      assert error.type == :invalid_parameter
      assert String.contains?(error.message, "Invalid source: invalid")
      assert error.details.valid_sources == ~w(platform seal all)
      assert error.details.provided == "invalid"
    end

    test "handles server errors" do
      expect_post(500, %{"errors" => ["internal server error"]})

      assert {:error, %Error{} = error} = Tools.generate_random()
      assert error.type == :server_error
      assert String.contains?(error.message, "Failed to generate random bytes")
    end

    test "handles network errors" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{} = error} = Tools.generate_random()
      assert error.type == :unknown_error
    end

    test "passes custom options" do
      expect_post(200, @random_response, fn _url, _body, opts ->
        assert opts[:timeout] == 30_000
      end)

      assert {:ok, _result} = Tools.generate_random(timeout: 30_000)
    end
  end

  describe "hash_data/2" do
    test "hashes data with default parameters" do
      input = Base.encode64("test data")

      expect_post(200, @hash_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/tools/hash/sha2-256")
        assert body["input"] == input
        assert body["format"] == "hex"
      end)

      assert {:ok, result} = Tools.hash_data(input)
      assert result.sum == "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
    end

    test "hashes data with custom parameters" do
      input = Base.encode64("test data")

      expect_post(200, @hash_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/tools/hash/sha2-512")
        assert body["input"] == input
        assert body["format"] == "base64"
      end)

      assert {:ok, result} = Tools.hash_data(input, algorithm: "sha2-512", format: "base64")
      assert result.sum == "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
    end

    test "validates algorithm parameter" do
      input = Base.encode64("test")

      assert {:error, %Error{} = error} = Tools.hash_data(input, algorithm: "invalid")
      assert error.type == :invalid_parameter
      assert String.contains?(error.message, "Invalid algorithm: invalid")
      assert "sha2-256" in error.details.valid_algorithms
      assert error.details.provided == "invalid"
    end

    test "validates format parameter" do
      input = Base.encode64("test")

      assert {:error, %Error{} = error} = Tools.hash_data(input, format: "invalid")
      assert error.type == :invalid_parameter
      assert String.contains?(error.message, "Invalid format: invalid")
      assert error.details.valid_formats == ~w(base64 hex)
    end

    test "validates base64 input" do
      assert {:error, %Error{} = error} = Tools.hash_data("invalid base64!")
      assert error.type == :invalid_parameter
      assert String.contains?(error.message, "Input must be valid base64 encoded data")
    end

    test "handles server errors" do
      input = Base.encode64("test")
      expect_post(400, %{"errors" => ["bad request"]})

      assert {:error, %Error{} = error} = Tools.hash_data(input)
      assert error.type == :server_error
      assert String.contains?(error.message, "Failed to hash data")
    end

    test "handles network errors" do
      input = Base.encode64("test")
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{} = error} = Tools.hash_data(input)
      assert error.type == :unknown_error
    end
  end

  describe "generate_token/2" do
    test "generates token with default size" do
      expect_post(200, @random_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/tools/random/platform/32")
        assert body["format"] == "base64"
      end)

      assert {:ok, token} = Tools.generate_token()
      assert token == "dGVzdCByYW5kb20gZGF0YQ=="
    end

    test "generates token with custom size" do
      expect_post(200, @random_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/tools/random/platform/64")
        assert body["format"] == "base64"
      end)

      assert {:ok, token} = Tools.generate_token(64)
      assert token == "dGVzdCByYW5kb20gZGF0YQ=="
    end

    test "passes additional options" do
      expect_post(200, @random_response, fn url, body, opts ->
        assert String.contains?(url, "sys/tools/random/seal/128")
        assert body["format"] == "base64"
        assert opts[:timeout] == 15_000
      end)

      assert {:ok, token} = Tools.generate_token(128, source: "seal", timeout: 15_000)
      assert token == "dGVzdCByYW5kb20gZGF0YQ=="
    end

    test "handles errors from generate_random" do
      assert {:error, %Error{} = error} = Tools.generate_token(0)
      assert error.type == :invalid_parameter
      assert String.contains?(error.message, "Invalid byte count")
    end
  end

  describe "hash_string/2" do
    test "hashes string with automatic base64 encoding" do
      test_string = "Hello, World!"
      expected_input = Base.encode64(test_string)

      expect_post(200, @hash_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/tools/hash/sha2-256")
        assert body["input"] == expected_input
        assert body["format"] == "hex"
      end)

      assert {:ok, hash} = Tools.hash_string(test_string)
      assert hash == "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
    end

    test "hashes string with custom algorithm" do
      test_string = "test data"
      expected_input = Base.encode64(test_string)

      expect_post(200, @hash_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/tools/hash/sha3-256")
        assert body["input"] == expected_input
        assert body["format"] == "hex"
      end)

      assert {:ok, hash} = Tools.hash_string(test_string, algorithm: "sha3-256")
      assert hash == "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
    end

    test "handles unicode strings" do
      unicode_string = "测试数据🔐"
      expected_input = Base.encode64(unicode_string)

      expect_post(200, @hash_response, fn _url, body, _opts ->
        assert body["input"] == expected_input
      end)

      assert {:ok, hash} = Tools.hash_string(unicode_string)
      assert hash == "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
    end

    test "handles empty strings" do
      empty_string = ""
      expected_input = Base.encode64(empty_string)

      expect_post(200, @hash_response, fn _url, body, _opts ->
        assert body["input"] == expected_input
      end)

      assert {:ok, hash} = Tools.hash_string(empty_string)
      assert hash == "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
    end

    test "passes options to hash_data" do
      test_string = "test"

      expect_post(200, @hash_response, fn url, body, opts ->
        assert String.contains?(url, "sys/tools/hash/sha2-512")
        assert body["format"] == "base64"
        assert opts[:timeout] == 20_000
      end)

      assert {:ok, hash} =
               Tools.hash_string(
                 test_string,
                 algorithm: "sha2-512",
                 format: "base64",
                 timeout: 20_000
               )

      assert hash == "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
    end

    test "handles errors from hash_data" do
      assert {:error, %Error{} = error} = Tools.hash_string("test", algorithm: "invalid")
      assert error.type == :invalid_parameter
      assert String.contains?(error.message, "Invalid algorithm")
    end
  end

  describe "parameter validation edge cases" do
    test "validates all supported algorithms" do
      valid_algorithms =
        ~w(sha2-224 sha2-256 sha2-384 sha2-512 sha3-224 sha3-256 sha3-384 sha3-512)

      input = Base.encode64("test")

      Enum.each(valid_algorithms, fn algorithm ->
        expect_post(200, @hash_response, fn url, _body, _opts ->
          assert String.contains?(url, "sys/tools/hash/#{algorithm}")
        end)

        assert {:ok, _result} = Tools.hash_data(input, algorithm: algorithm)
      end)
    end

    test "validates all supported sources" do
      valid_sources = ~w(platform seal all)

      Enum.each(valid_sources, fn source ->
        expect_post(200, @random_response, fn url, _body, _opts ->
          assert String.contains?(url, "sys/tools/random/#{source}/32")
        end)

        assert {:ok, _result} = Tools.generate_random(source: source)
      end)
    end

    test "validates all supported formats" do
      valid_formats = ~w(base64 hex)

      # Test with random generation
      Enum.each(valid_formats, fn format ->
        expect_post(200, @random_response, fn _url, body, _opts ->
          assert body["format"] == format
        end)

        assert {:ok, _result} = Tools.generate_random(format: format)
      end)

      # Test with hashing
      input = Base.encode64("test")

      Enum.each(valid_formats, fn format ->
        expect_post(200, @hash_response, fn _url, body, _opts ->
          assert body["format"] == format
        end)

        assert {:ok, _result} = Tools.hash_data(input, format: format)
      end)
    end

    test "handles boundary byte counts" do
      # Test minimum valid byte count
      expect_post(200, @random_response, fn url, _body, _opts ->
        assert String.contains?(url, "sys/tools/random/platform/1")
      end)

      assert {:ok, _result} = Tools.generate_random(bytes: 1)

      # Test maximum valid byte count
      expect_post(200, @random_response, fn url, _body, _opts ->
        assert String.contains?(url, "sys/tools/random/platform/1024")
      end)

      assert {:ok, _result} = Tools.generate_random(bytes: 1024)
    end

    test "handles various invalid base64 inputs" do
      invalid_inputs = [
        "not base64!",
        "invalid==",
        "spaces in base64",
        "123",
        "!@#$%^&*()"
      ]

      Enum.each(invalid_inputs, fn invalid_input ->
        assert {:error, %Error{type: :invalid_parameter}} = Tools.hash_data(invalid_input)
      end)
    end
  end

  describe "integration scenarios" do
    test "complete random generation workflow" do
      # Generate token for different use cases
      expect_post(200, @random_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/tools/random/platform/32")
        assert body["format"] == "base64"
      end)

      assert {:ok, session_token} = Tools.generate_token()
      assert is_binary(session_token)

      expect_post(200, @random_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/tools/random/seal/64")
        assert body["format"] == "base64"
      end)

      assert {:ok, api_key} = Tools.generate_token(64, source: "seal")
      assert is_binary(api_key)
    end

    test "complete hashing workflow" do
      # Hash password
      password = "secure-password-123"
      expected_input = Base.encode64(password)

      expect_post(200, @hash_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/tools/hash/sha2-256")
        assert body["input"] == expected_input
        assert body["format"] == "hex"
      end)

      assert {:ok, password_hash} = Tools.hash_string(password)
      assert is_binary(password_hash)

      # Hash sensitive data with stronger algorithm
      sensitive_data = "confidential information"
      expected_sensitive_input = Base.encode64(sensitive_data)

      expect_post(200, @hash_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/tools/hash/sha2-512")
        assert body["input"] == expected_sensitive_input
        assert body["format"] == "hex"
      end)

      assert {:ok, data_hash} = Tools.hash_string(sensitive_data, algorithm: "sha2-512")
      assert is_binary(data_hash)
    end

    test "error handling across all functions" do
      # All functions should handle validation errors consistently
      assert {:error, %Error{type: :invalid_parameter}} = Tools.generate_random(bytes: -1)
      assert {:error, %Error{type: :invalid_parameter}} = Tools.generate_token(-1)
      assert {:error, %Error{type: :invalid_parameter}} = Tools.hash_data("invalid")

      assert {:error, %Error{type: :invalid_parameter}} =
               Tools.hash_string("test", algorithm: "invalid")
    end
  end
end
