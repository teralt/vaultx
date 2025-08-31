defmodule Vaultx.Base.ErrorTest do
  use ExUnit.Case, async: true

  alias Vaultx.Base.Error

  describe "new/3" do
    test "creates error with required fields" do
      error = Error.new(:authentication_failed, "Invalid token")

      assert error.type == :authentication_failed
      assert error.message == "Invalid token"
      assert error.details == %{}
      assert error.vault_errors == []
      assert error.http_status == nil
      assert error.request_id == nil
      assert error.recoverable == false
      assert error.retry_after == nil
    end

    test "creates error with all optional fields" do
      error =
        Error.new(:server_error, "Internal error",
          details: %{code: 500},
          vault_errors: ["server unavailable"],
          http_status: 500,
          request_id: "req-123",
          recoverable: true,
          retry_after: 30
        )

      assert error.type == :server_error
      assert error.message == "Internal error"
      assert error.details == %{code: 500}
      assert error.vault_errors == ["server unavailable"]
      assert error.http_status == 500
      assert error.request_id == "req-123"
      assert error.recoverable == true
      assert error.retry_after == 30
    end
  end

  describe "from_http_response/2" do
    test "creates error from HTTP response with vault errors" do
      error = Error.from_http_response(404, %{"errors" => ["path not found"]})

      assert error.type == :not_found
      assert error.http_status == 404
      assert error.vault_errors == ["path not found"]
      assert error.message == "path not found"
    end

    test "handles various HTTP status codes" do
      status_type_pairs = [
        {400, :invalid_request},
        {401, :authentication_failed},
        {403, :authorization_denied},
        {404, :not_found},
        {429, :rate_limited},
        {500, :server_error},
        {502, :server_error},
        {503, :server_error}
      ]

      for {status, expected_type} <- status_type_pairs do
        error = Error.from_http_response(status, %{"errors" => ["test error"]})
        assert error.type == expected_type
        assert error.http_status == status
      end

      # Test unknown status code (999 >= 500, so it's server_error)
      error = Error.from_http_response(999, %{"errors" => ["test error"]})
      assert error.type == :server_error
      assert error.http_status == 999

      # Test truly unknown status code (< 500 and not in specific mappings)
      error = Error.from_http_response(418, %{"errors" => ["test error"]})
      assert error.type == :unknown_error
      assert error.http_status == 418
    end

    test "handles empty vault errors" do
      error = Error.from_http_response(400, %{"errors" => []})
      assert error.type == :invalid_request
      assert error.vault_errors == []
      assert String.contains?(error.message, "Bad request")
    end

    test "handles missing errors field" do
      error = Error.from_http_response(500, %{})
      assert error.type == :server_error
      assert error.vault_errors == []
    end
  end

  describe "from_exception/2" do
    test "creates error from generic exception" do
      exception = %RuntimeError{message: "something went wrong"}
      error = Error.from_exception(exception)

      assert error.type == :unknown_error
      assert error.message == "something went wrong"
      assert error.details.original_exception == exception
      assert error.recoverable == false
    end

    test "handles exceptions with custom context" do
      exception = %RuntimeError{message: "test error"}
      error = Error.from_exception(exception, details: %{operation: "test_op"})

      assert error.type == :unknown_error
      assert error.details.operation == "test_op"
      assert error.details.original_exception == exception
    end

    test "handles exceptions with nil message" do
      exception = %RuntimeError{message: nil}
      error = Error.from_exception(exception)

      assert error.type == :unknown_error
      assert String.contains?(error.message, "RuntimeError")
    end

    test "handles Mint transport errors" do
      exception = %{__struct__: Mint.TransportError, __exception__: true, reason: :timeout}
      error = Error.from_exception(exception)

      assert error.type == :network_error
      assert error.message == "timeout"
      assert error.recoverable == true
    end

    test "handles Mint HTTP errors" do
      exception = %{__struct__: Mint.HTTPError, __exception__: true, reason: :invalid_response}
      error = Error.from_exception(exception)

      assert error.type == :network_error
      assert String.contains?(error.message, "FunctionClauseError")
      assert error.recoverable == true
    end
  end

  describe "user_message/1" do
    test "returns original message for configuration errors" do
      error = Error.new(:configuration_error, "Invalid URL format")
      assert Error.user_message(error) == "Configuration error: Invalid URL format"
    end

    test "returns first vault error when available" do
      error =
        Error.new(:authentication_failed, "Token invalid",
          vault_errors: ["Invalid token", "Expired"]
        )

      assert Error.user_message(error) == "Invalid token"
    end

    test "covers user_message with non-empty message" do
      error = Error.new(:unknown_error, "Custom error message")
      message = Error.user_message(error)
      assert message == "Custom error message"
    end

    test "covers default messages for error types with empty messages" do
      error_types = [
        :invalid_request,
        :server_error,
        :network_error,
        :json_decode_error,
        :json_encode_error,
        :ssl_error,
        :rate_limited,
        :http_error
      ]

      for error_type <- error_types do
        error = Error.new(error_type, "")
        message = Error.user_message(error)

        assert is_binary(message) and String.length(message) > 0,
               "Expected non-empty message for #{error_type}, got: #{inspect(message)}"
      end
    end

    test "covers HTTP status code to message mapping" do
      status_codes = [400, 401, 403, 404, 429, 500, 502, 503, 999]

      for status <- status_codes do
        error = Error.from_http_response(status, %{})

        assert %Error{} = error
        assert error.http_status == status

        message = error.message
        assert is_binary(message) and String.length(message) > 0
      end
    end
  end

  describe "recoverable?/1" do
    test "returns recoverable status" do
      recoverable_error = Error.new(:network_error, "Connection failed", recoverable: true)
      assert Error.recoverable?(recoverable_error) == true

      non_recoverable_error =
        Error.new(:authentication_failed, "Invalid token", recoverable: false)

      assert Error.recoverable?(non_recoverable_error) == false
    end

    test "returns correct recoverable status for error types" do
      # Test new error types
      assert Error.recoverable?(:not_implemented) == false
      assert Error.recoverable?(:connection_error) == true
      assert Error.recoverable?(:permission_denied) == false

      # Test existing types for completeness
      assert Error.recoverable?(:timeout) == true
      assert Error.recoverable?(:network_error) == true
      assert Error.recoverable?(:authentication_failed) == false
    end
  end

  describe "user_message/1 specific error types" do
    test "covers specific error type messages" do
      # Test authentication_failed with empty vault_errors
      error = Error.new(:authentication_failed, "", vault_errors: [])
      message = Error.user_message(error)
      assert String.contains?(message, "Authentication failed")

      # Test authorization_denied with empty vault_errors
      error = Error.new(:authorization_denied, "", vault_errors: [])
      message = Error.user_message(error)
      assert String.contains?(message, "Access denied")

      # Test not_found with empty vault_errors
      error = Error.new(:not_found, "", vault_errors: [])
      message = Error.user_message(error)
      assert String.contains?(message, "not found")

      # Test timeout with empty vault_errors
      error = Error.new(:timeout, "", vault_errors: [])
      message = Error.user_message(error)
      assert String.contains?(message, "timed out")
    end
  end

  describe "from_http_response/2 with request_id and retry_after" do
    test "extracts request_id from response" do
      response = %{"errors" => ["test error"], "request_id" => "req-123"}
      error = Error.from_http_response(400, response)

      assert error.request_id == "req-123"
    end

    test "extracts retry_after from response" do
      response = %{"errors" => ["rate limited"], "retry_after" => 60}
      error = Error.from_http_response(429, response)

      assert error.retry_after == 60
    end
  end

  describe "Jason error handling" do
    test "handles Jason decode errors" do
      # Create a mock Jason.DecodeError
      exception = %{__struct__: Jason.DecodeError, __exception__: true, data: "invalid"}
      error = Error.from_exception(exception)

      assert error.type == :json_decode_error
    end

    test "handles Jason encode errors" do
      # Create a mock Jason.EncodeError
      exception = %{__struct__: Jason.EncodeError, __exception__: true, value: %{invalid: true}}
      error = Error.from_exception(exception)

      assert error.type == :json_encode_error
    end
  end

  describe "debug_info/1" do
    test "returns comprehensive debug information" do
      error =
        Error.new(:server_error, "Internal error",
          details: %{code: 500},
          vault_errors: ["server unavailable"],
          http_status: 500,
          request_id: "req-789",
          recoverable: true,
          retry_after: 30
        )

      info = Error.debug_info(error)

      assert info.type == :server_error
      assert info.message == "Internal error"
      assert info.details == %{code: 500}
      assert info.vault_errors == ["server unavailable"]
      assert info.http_status == 500
      assert info.request_id == "req-789"
      assert info.recoverable == true
      assert info.retry_after == 30
    end
  end
end
