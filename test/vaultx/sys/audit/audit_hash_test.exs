defmodule Vaultx.Sys.AuditHashTest do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Sys.AuditHash
  alias Vaultx.Base.Error

  # Sample hash response
  @hash_response %{
    "hash" => "hmac-sha256:08ba35a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234"
  }

  # Different hash for different input
  @different_hash_response %{
    "hash" => "hmac-sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
  }

  describe "calculate/3" do
    test "calculates hash for simple string successfully" do
      expect_post(200, @hash_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/audit-hash/file-audit")
        assert body["input"] == "my-secret-value"
      end)

      assert {:ok, result} = AuditHash.calculate("file-audit", "my-secret-value")

      assert result.hash ==
               "hmac-sha256:08ba35a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234"
    end

    test "calculates hash for token accessor" do
      expect_post(200, @hash_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/audit-hash/syslog-audit")
        assert body["input"] == "accessor_12345"
      end)

      assert {:ok, result} = AuditHash.calculate("syslog-audit", "accessor_12345")
      assert String.starts_with?(result.hash, "hmac-sha256:")
    end

    test "calculates hash for base64-encoded binary data" do
      binary_data = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10>>
      base64_data = Base.encode64(binary_data)

      expect_post(200, @hash_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/audit-hash/file-audit")
        assert body["input"] == base64_data
      end)

      assert {:ok, result} = AuditHash.calculate("file-audit", base64_data)
      assert String.starts_with?(result.hash, "hmac-sha256:")
    end

    test "handles different audit device paths" do
      audit_paths = ["file-audit", "syslog-audit", "socket-audit", "custom_audit_123"]

      Enum.each(audit_paths, fn audit_path ->
        expect_post(200, @hash_response, fn url, body, _opts ->
          assert String.contains?(url, "sys/audit-hash/#{audit_path}")
          assert body["input"] == "test-input"
        end)

        assert {:ok, result} = AuditHash.calculate(audit_path, "test-input")
        assert String.starts_with?(result.hash, "hmac-sha256:")
      end)
    end

    test "handles empty input string" do
      expect_post(200, @hash_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/audit-hash/file-audit")
        assert body["input"] == ""
      end)

      assert {:ok, result} = AuditHash.calculate("file-audit", "")
      assert String.starts_with?(result.hash, "hmac-sha256:")
    end

    test "handles unicode characters in input" do
      unicode_input = "测试数据🔐"

      expect_post(200, @hash_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/audit-hash/file-audit")
        assert body["input"] == unicode_input
      end)

      assert {:ok, result} = AuditHash.calculate("file-audit", unicode_input)
      assert String.starts_with?(result.hash, "hmac-sha256:")
    end

    test "handles short hash values" do
      short_hash_response = %{"hash" => "hmac-sha256:abc123"}

      expect_post(200, short_hash_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/audit-hash/file-audit")
        assert body["input"] == "short-test"
      end)

      assert {:ok, result} = AuditHash.calculate("file-audit", "short-test")
      assert result.hash == "hmac-sha256:abc123"
    end

    test "handles server errors" do
      expect_post(404, %{"errors" => ["audit device not found"]})

      assert {:error, %Error{} = error} = AuditHash.calculate("nonexistent-audit", "test")
      assert error.type == :server_error
      assert String.contains?(error.message, "Failed to calculate audit hash")
    end

    test "handles network errors" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{} = error} = AuditHash.calculate("file-audit", "test")
      assert error.type == :unknown_error
    end

    test "handles invalid response format" do
      expect_post(200, %{"invalid" => "response"})

      assert {:error, %Error{} = error} = AuditHash.calculate("file-audit", "test")
      assert error.type == :server_error
    end

    test "handles malformed hash response" do
      expect_post(200, %{"hash" => nil})

      assert {:error, %Error{} = error} = AuditHash.calculate("file-audit", "test")
      assert error.type == :server_error
    end
  end

  describe "calculate_batch/3" do
    test "calculates hashes for multiple inputs successfully" do
      inputs = ["secret1", "secret2", "token_123"]

      # Mock responses for each input
      Enum.each(inputs, fn input ->
        hash_value =
          "hmac-sha256:#{String.slice(Base.encode16(:crypto.hash(:sha256, input)), 0, 64)}"

        response = %{"hash" => hash_value}

        expect_post(200, response, fn url, body, _opts ->
          assert String.contains?(url, "sys/audit-hash/file-audit")
          assert body["input"] == input
        end)
      end)

      assert {:ok, results} = AuditHash.calculate_batch("file-audit", inputs)
      assert length(results) == 3

      Enum.each(results, fn result ->
        assert String.starts_with?(result.hash, "hmac-sha256:")
      end)
    end

    test "handles empty input list" do
      assert {:ok, results} = AuditHash.calculate_batch("file-audit", [])
      assert results == []
    end

    test "handles single input in batch" do
      expect_post(200, @hash_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/audit-hash/file-audit")
        assert body["input"] == "single-input"
      end)

      assert {:ok, results} = AuditHash.calculate_batch("file-audit", ["single-input"])
      assert length(results) == 1
      assert hd(results).hash == @hash_response["hash"]
    end

    test "stops on first error in batch" do
      inputs = ["success1", "failure", "success2"]

      # First request succeeds
      expect_post(200, @hash_response, fn _url, body, _opts ->
        assert body["input"] == "success1"
      end)

      # Second request fails
      expect_post(404, %{"errors" => ["audit device not found"]}, fn _url, body, _opts ->
        assert body["input"] == "failure"
      end)

      # Third request should not be made due to early termination

      assert {:error, %Error{} = error} = AuditHash.calculate_batch("file-audit", inputs)
      assert error.type == :server_error
    end

    test "handles large batch efficiently" do
      large_inputs = Enum.map(1..10, fn i -> "input_#{i}" end)

      Enum.each(large_inputs, fn input ->
        expect_post(200, @hash_response, fn _url, body, _opts ->
          assert body["input"] == input
        end)
      end)

      assert {:ok, results} = AuditHash.calculate_batch("file-audit", large_inputs)
      assert length(results) == 10
    end
  end

  describe "validate_audit_device/2" do
    test "validates accessible audit device successfully" do
      expect_post(200, @hash_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/audit-hash/file-audit")
        assert String.contains?(body["input"], "vaultx-audit-test-")
      end)

      assert :ok = AuditHash.validate_audit_device("file-audit")
    end

    test "validates audit device with non-standard hash format" do
      # Test with a hash that doesn't match the expected pattern but is still valid
      custom_hash_response = %{"hash" => "custom-format:validhash"}

      expect_post(200, custom_hash_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/audit-hash/test-audit")
        assert String.contains?(body["input"], "vaultx-audit-test-")
      end)

      assert :ok = AuditHash.validate_audit_device("test-audit")
    end

    test "handles inaccessible audit device" do
      expect_post(404, %{"errors" => ["audit device not found"]})

      assert {:error, %Error{} = error} = AuditHash.validate_audit_device("nonexistent-audit")
      assert error.type == :server_error
    end

    test "handles invalid hash response during validation" do
      expect_post(200, %{"hash" => ""})

      assert {:error, %Error{} = error} = AuditHash.validate_audit_device("file-audit")
      assert error.type == :server_error
      assert String.contains?(error.message, "Invalid hash response")
    end

    test "handles null hash response during validation" do
      expect_post(200, %{"hash" => nil})

      assert {:error, %Error{} = error} = AuditHash.validate_audit_device("file-audit")
      assert error.type == :server_error
      assert String.contains?(error.message, "Invalid hash response")
    end

    test "handles network errors during validation" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{} = error} = AuditHash.validate_audit_device("file-audit")
      assert error.type == :unknown_error
    end
  end

  describe "edge cases and special scenarios" do
    test "handles very long input strings" do
      long_input = String.duplicate("a", 10000)

      expect_post(200, @hash_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/audit-hash/file-audit")
        assert body["input"] == long_input
      end)

      assert {:ok, result} = AuditHash.calculate("file-audit", long_input)
      assert String.starts_with?(result.hash, "hmac-sha256:")
    end

    test "handles special characters and symbols" do
      special_input = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~"

      expect_post(200, @hash_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/audit-hash/file-audit")
        assert body["input"] == special_input
      end)

      assert {:ok, result} = AuditHash.calculate("file-audit", special_input)
      assert String.starts_with?(result.hash, "hmac-sha256:")
    end

    test "handles newlines and whitespace in input" do
      whitespace_input = "line1\nline2\r\nline3\ttab\s\s  spaces"

      expect_post(200, @hash_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/audit-hash/file-audit")
        assert body["input"] == whitespace_input
      end)

      assert {:ok, result} = AuditHash.calculate("file-audit", whitespace_input)
      assert String.starts_with?(result.hash, "hmac-sha256:")
    end

    test "handles JSON-like strings in input" do
      json_input = "{\"key\": \"value\", \"number\": 123, \"boolean\": true}"

      expect_post(200, @hash_response, fn url, body, _opts ->
        assert String.contains?(url, "sys/audit-hash/file-audit")
        assert body["input"] == json_input
      end)

      assert {:ok, result} = AuditHash.calculate("file-audit", json_input)
      assert String.starts_with?(result.hash, "hmac-sha256:")
    end

    test "different inputs produce different hashes" do
      # First input
      expect_post(200, @hash_response, fn _url, body, _opts ->
        assert body["input"] == "input1"
      end)

      # Second input with different hash
      expect_post(200, @different_hash_response, fn _url, body, _opts ->
        assert body["input"] == "input2"
      end)

      assert {:ok, result1} = AuditHash.calculate("file-audit", "input1")
      assert {:ok, result2} = AuditHash.calculate("file-audit", "input2")

      assert result1.hash != result2.hash
      assert String.starts_with?(result1.hash, "hmac-sha256:")
      assert String.starts_with?(result2.hash, "hmac-sha256:")
    end
  end

  describe "integration scenarios" do
    test "complete audit log correlation workflow" do
      # Step 1: Calculate hash for known value
      secret_value = "user-token-abc123"

      expect_post(200, @hash_response, fn _url, body, _opts ->
        assert body["input"] == secret_value
      end)

      assert {:ok, result} = AuditHash.calculate("file-audit", secret_value)
      calculated_hash = result.hash

      # Step 2: Validate the hash format
      assert String.starts_with?(calculated_hash, "hmac-sha256:")
      # Reasonable hash length
      assert String.length(calculated_hash) > 20

      # Step 3: Verify hash consistency (same input should produce same hash)
      expect_post(200, @hash_response, fn _url, body, _opts ->
        assert body["input"] == secret_value
      end)

      assert {:ok, result2} = AuditHash.calculate("file-audit", secret_value)
      assert result2.hash == calculated_hash
    end

    test "batch processing for multiple token accessors" do
      token_accessors = [
        "accessor_user1_12345",
        "accessor_admin_67890",
        "accessor_service_abcdef"
      ]

      # Mock responses for each accessor
      Enum.with_index(token_accessors, fn accessor, index ->
        hash_suffix = String.pad_leading(Integer.to_string(index), 64, "0")
        response = %{"hash" => "hmac-sha256:#{hash_suffix}"}

        expect_post(200, response, fn _url, body, _opts ->
          assert body["input"] == accessor
        end)
      end)

      assert {:ok, results} = AuditHash.calculate_batch("syslog-audit", token_accessors)
      assert length(results) == 3

      # Verify each result has a unique hash
      hashes = Enum.map(results, & &1.hash)
      assert length(Enum.uniq(hashes)) == 3
    end

    test "audit device validation before hash calculation" do
      # Step 1: Validate audit device
      expect_post(200, @hash_response, fn _url, body, _opts ->
        assert String.contains?(body["input"], "vaultx-audit-test-")
      end)

      assert :ok = AuditHash.validate_audit_device("file-audit")

      # Step 2: Calculate actual hash
      expect_post(200, @hash_response, fn _url, body, _opts ->
        assert body["input"] == "actual-secret"
      end)

      assert {:ok, result} = AuditHash.calculate("file-audit", "actual-secret")
      assert String.starts_with?(result.hash, "hmac-sha256:")
    end
  end
end
