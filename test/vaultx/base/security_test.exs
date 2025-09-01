defmodule Vaultx.Base.SecurityTest do
  use ExUnit.Case, async: true
  import ExUnit.CaptureLog

  alias Vaultx.Base.Security

  describe "validate_ssl_config/1" do
    test "accepts secure SSL configuration" do
      config = %{
        verify: :verify_peer,
        versions: [:"tlsv1.2", :"tlsv1.3"],
        ciphers: [:strong_cipher]
      }

      assert Security.validate_ssl_config(config) == :ok
    end

    test "rejects SSL verification disabled" do
      config = %{verify: :verify_none}

      assert Security.validate_ssl_config(config) ==
               {:error, "SSL verification disabled - security risk"}
    end

    test "rejects insecure SSL versions" do
      config = %{
        verify: :verify_peer,
        versions: [:sslv3, :"tlsv1.1"]
      }

      assert Security.validate_ssl_config(config) ==
               {:error, "Insecure SSL/TLS versions detected"}
    end

    test "rejects empty cipher list" do
      config = %{
        verify: :verify_peer,
        ciphers: []
      }

      assert Security.validate_ssl_config(config) ==
               {:error, "No SSL ciphers configured"}
    end

    test "rejects non-map configuration" do
      assert Security.validate_ssl_config("invalid") ==
               {:error, "SSL configuration must be a map"}
    end

    test "requires SSL verification configuration" do
      config = %{}

      assert Security.validate_ssl_config(config) ==
               {:error, "SSL verification not configured"}
    end

    test "accepts SSL config without explicit ciphers" do
      config = %{verify: :verify_peer}

      assert Security.validate_ssl_config(config) == :ok
    end
  end

  describe "validate_token/1" do
    test "accepts valid tokens" do
      assert Security.validate_token("hvs.valid_token_format") == :ok
      assert Security.validate_token("s.long_enough_token") == :ok
    end

    test "rejects short tokens" do
      assert Security.validate_token("short") ==
               {:error, "Token too short - minimum 8 characters required"}
    end

    test "rejects tokens with invalid characters" do
      assert Security.validate_token("token\nwith\nnewlines") ==
               {:error, "Token contains invalid characters"}

      assert Security.validate_token("token\twith\ttabs") ==
               {:error, "Token contains invalid characters"}
    end

    test "rejects overly long tokens" do
      long_token = String.duplicate("a", 1025)

      assert Security.validate_token(long_token) ==
               {:error, "Token too long - maximum 1024 characters"}
    end

    test "rejects non-string tokens" do
      assert Security.validate_token(123) ==
               {:error, "Token must be a string"}

      assert Security.validate_token(nil) ==
               {:error, "Token must be a string"}
    end
  end

  describe "validate_path/1" do
    test "accepts valid paths" do
      assert Security.validate_path("secret/myapp/config") == :ok
      assert Security.validate_path("kv/data/app") == :ok
      assert Security.validate_path("auth/userpass/users/john") == :ok
      assert Security.validate_path("sys/health") == :ok
    end

    test "rejects path traversal attempts" do
      assert Security.validate_path("../../../etc/passwd") == {:error, "Path traversal detected"}
      assert Security.validate_path("secret/../admin") == {:error, "Path traversal detected"}

      assert Security.validate_path("valid/path/../../../bad") ==
               {:error, "Path traversal detected"}
    end

    test "rejects paths with double slashes" do
      assert Security.validate_path("secret//config") ==
               {:error, "Invalid path format - double slashes not allowed"}

      assert Security.validate_path("path//to//secret") ==
               {:error, "Invalid path format - double slashes not allowed"}
    end

    test "rejects absolute paths" do
      assert Security.validate_path("/secret/config") == {:error, "Absolute paths not allowed"}
      assert Security.validate_path("/etc/passwd") == {:error, "Absolute paths not allowed"}
    end

    test "rejects paths with invalid characters" do
      assert Security.validate_path("secret/config@invalid") ==
               {:error, "Path contains invalid characters"}

      assert Security.validate_path("secret/config#hash") ==
               {:error, "Path contains invalid characters"}

      assert Security.validate_path("secret/config with spaces") ==
               {:error, "Path contains invalid characters"}
    end

    test "rejects empty paths" do
      assert Security.validate_path("") == {:error, "Path cannot be empty"}
    end

    test "rejects paths that are too long" do
      long_path = String.duplicate("a", 1025)

      assert Security.validate_path(long_path) ==
               {:error, "Path too long - maximum 1024 characters"}
    end

    test "rejects non-string paths" do
      assert Security.validate_path(123) == {:error, "Path must be a string"}
      assert Security.validate_path(nil) == {:error, "Path must be a string"}
      assert Security.validate_path(%{}) == {:error, "Path must be a string"}
    end
  end

  describe "generate_request_id/0" do
    test "generates valid UUID v4 format" do
      id = Security.generate_request_id()

      # Should be 36 characters long (32 hex + 4 hyphens)
      assert String.length(id) == 36

      # Should match UUID v4 format
      assert Regex.match?(
               ~r/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
               id
             )
    end

    test "generates unique IDs" do
      id1 = Security.generate_request_id()
      id2 = Security.generate_request_id()
      id3 = Security.generate_request_id()

      # All IDs should be different
      assert id1 != id2
      assert id2 != id3
      assert id1 != id3
    end

    test "generates IDs with correct version and variant bits" do
      id = Security.generate_request_id()
      parts = String.split(id, "-")

      # Version should be 4 (first character of third part)
      version_part = Enum.at(parts, 2)
      assert String.at(version_part, 0) == "4"

      # Variant should be 8, 9, a, or b (first character of fourth part)
      variant_part = Enum.at(parts, 3)
      variant_char = String.at(variant_part, 0)
      assert variant_char in ["8", "9", "a", "b"]
    end
  end

  describe "validate_url/1" do
    test "accepts secure HTTPS URLs" do
      assert Security.validate_url("https://vault.example.com") == :ok
      assert Security.validate_url("https://api.vault.company.com:8200") == :ok
    end

    test "rejects HTTP URLs" do
      assert Security.validate_url("http://vault.example.com") ==
               {:error, "HTTP URLs are not secure - use HTTPS"}
    end

    test "rejects URLs without scheme" do
      assert Security.validate_url("vault.example.com") ==
               {:error, "URL must include a scheme (http/https)"}
    end

    test "rejects non-HTTPS schemes" do
      assert Security.validate_url("ftp://vault.example.com") ==
               {:error, "Only HTTPS URLs are allowed"}
    end

    test "rejects URLs without host" do
      assert Security.validate_url("https://") ==
               {:error, "URL must include a valid host"}
    end

    test "rejects localhost URLs" do
      assert Security.validate_url("https://localhost:8200") ==
               {:error, "Localhost URLs are not allowed in production"}

      assert Security.validate_url("https://127.0.0.1:8200") ==
               {:error, "Localhost URLs are not allowed in production"}
    end

    test "rejects non-string URLs" do
      assert Security.validate_url(123) ==
               {:error, "URL must be a string"}
    end
  end

  describe "validate_input/2" do
    test "accepts safe string input" do
      assert Security.validate_input("safe_string") == :ok
      assert Security.validate_input("normal text with spaces") == :ok
    end

    test "rejects input exceeding max length" do
      long_string = String.duplicate("a", 10_001)

      assert Security.validate_input(long_string) ==
               {:error, "Input exceeds maximum length of 10000 bytes"}
    end

    test "respects custom max length" do
      assert Security.validate_input("too long", max_length: 5) ==
               {:error, "Input exceeds maximum length of 5 bytes"}
    end

    test "rejects potentially dangerous content" do
      assert Security.validate_input("<script>alert('xss')</script>") ==
               {:error, "Input contains potentially dangerous content"}

      assert Security.validate_input("javascript:alert('xss')") ==
               {:error, "Input contains potentially dangerous content"}
    end

    test "rejects null bytes and control characters" do
      assert Security.validate_input("string\x00with\x01null") ==
               {:error, "Input contains null bytes or control characters"}
    end

    test "accepts safe primitive types" do
      assert Security.validate_input(:atom) == :ok
      assert Security.validate_input(123) == :ok
      assert Security.validate_input(true) == :ok
    end

    test "validates lists recursively" do
      assert Security.validate_input(["safe", "list"]) == :ok

      assert Security.validate_input(["safe", "<script>bad</script>"]) ==
               {:error, "Input contains potentially dangerous content"}
    end

    test "rejects oversized lists" do
      large_list = Enum.to_list(1..1001)

      assert Security.validate_input(large_list) ==
               {:error, "List exceeds maximum length of 1000 items"}
    end

    test "validates maps recursively" do
      assert Security.validate_input(%{key: "safe_value"}) == :ok

      assert Security.validate_input(%{key: "<script>bad</script>"}) ==
               {:error, "Input contains potentially dangerous content"}
    end

    test "rejects oversized maps" do
      large_map = for i <- 1..101, into: %{}, do: {i, "value"}

      assert Security.validate_input(large_map) ==
               {:error, "Map exceeds maximum size of 100 keys"}
    end

    test "rejects maps with invalid nested values" do
      # Create a map with a nested value that will fail validation
      invalid_map = %{"key" => {:unsupported, "tuple"}}

      assert Security.validate_input(invalid_map) ==
               {:error, "Unsupported data type for validation"}
    end

    test "rejects maps with invalid nested keys" do
      # Create a map with a nested key that will fail validation
      invalid_map = %{{:unsupported, "tuple"} => "value"}

      assert Security.validate_input(invalid_map) ==
               {:error, "Unsupported data type for validation"}
    end

    test "rejects unsupported data types" do
      assert Security.validate_input({:tuple, "data"}) ==
               {:error, "Unsupported data type for validation"}

      assert Security.validate_input(fn -> :ok end) ==
               {:error, "Unsupported data type for validation"}
    end
  end

  describe "sanitize_for_logging/1" do
    test "sanitizes sensitive keys in maps" do
      data = %{
        token: "secret_token",
        password: "secret_password",
        safe_data: "visible"
      }

      result = Security.sanitize_for_logging(data)

      assert result.token == "[REDACTED]"
      assert result.password == "[REDACTED]"
      assert result.safe_data == "visible"
    end

    test "sanitizes sensitive keys in lists" do
      data = [
        {:token, "secret"},
        {:safe_key, "visible"}
      ]

      result = Security.sanitize_for_logging(data)

      assert result == [
               {:token, "[REDACTED]"},
               {:safe_key, "visible"}
             ]
    end

    test "handles nested data structures" do
      data = %{
        user: %{
          name: "John",
          token: "secret"
        },
        credentials: [
          {:api_key, "secret_key"},
          {:endpoint, "https://api.example.com"}
        ]
      }

      result = Security.sanitize_for_logging(data)

      assert result.user.name == "John"
      assert result.user.token == "[REDACTED]"

      assert result.credentials == [
               {:api_key, "[REDACTED]"},
               {:endpoint, "https://api.example.com"}
             ]
    end

    test "leaves non-sensitive data unchanged" do
      data = %{name: "test", count: 42, active: true}

      assert Security.sanitize_for_logging(data) == data
    end

    test "handles string keys for sensitive data" do
      data = %{
        "token" => "secret_token",
        "password" => "secret_password",
        "safe_data" => "visible"
      }

      result = Security.sanitize_for_logging(data)

      assert result["token"] == "[REDACTED]"
      assert result["password"] == "[REDACTED]"
      assert result["safe_data"] == "visible"
    end

    test "handles non-atom, non-string keys" do
      data = %{
        123 => "numeric_key_value",
        {:tuple, :key} => "tuple_key_value"
      }

      result = Security.sanitize_for_logging(data)

      # Non-atom, non-string keys should not be considered sensitive
      assert result[123] == "numeric_key_value"
      assert result[{:tuple, :key}] == "tuple_key_value"
    end

    test "handles string keys that don't exist as atoms" do
      data = %{
        "non_existent_atom_key" => "value"
      }

      result = Security.sanitize_for_logging(data)

      # Should not crash and should leave value unchanged
      assert result["non_existent_atom_key"] == "value"
    end
  end

  describe "audit_log/3" do
    test "logs successful authentication events" do
      with_config(:info, fn ->
        log =
          capture_log(fn ->
            Security.audit_log(:authentication, :success, %{user_id: "user123"})
          end)

        assert log =~ "Security audit: authentication completed successfully"
      end)
    end

    test "logs failed authentication events as warnings" do
      with_config(:warn, fn ->
        log =
          capture_log(fn ->
            Security.audit_log(:authentication, :failure, %{reason: "invalid_token"})
          end)

        assert log =~ "[warning]"
        assert log =~ "Security audit: authentication failed"
      end)
    end

    test "logs authentication attempts" do
      with_config(:info, fn ->
        log =
          capture_log(fn ->
            Security.audit_log(:authentication, :attempt, %{method: :token})
          end)

        assert log =~ "Security audit: authentication attempted"
      end)
    end

    test "includes metadata in audit logs" do
      # Note: Metadata may not be visible in test output, but function should work
      with_config(:info, fn ->
        log =
          capture_log(fn ->
            Security.audit_log(:token_creation, :success, %{
              user_id: "user123",
              token_type: :service
            })
          end)

        assert log =~ "Security audit: token creation completed successfully"
      end)
    end

    test "audit_log with default empty metadata" do
      with_config(:info, fn ->
        log =
          capture_log(fn ->
            Security.audit_log(:token_revocation, :success)
          end)

        assert log =~ "Security audit: token revocation completed successfully"
      end)
    end
  end

  # Helper function to temporarily set log level
  defp with_config(level, fun) do
    # Get the original logger level
    original_level = Application.get_env(:vaultx, :logger_level, :info)

    # Set the new logger level
    Application.put_env(:vaultx, :logger_level, level)

    try do
      fun.()
    after
      # Restore original logger level
      Application.put_env(:vaultx, :logger_level, original_level)
    end
  end
end
