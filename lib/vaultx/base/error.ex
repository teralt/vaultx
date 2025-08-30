defmodule Vaultx.Base.Error do
  @moduledoc """
  Comprehensive error handling for Vaultx HashiCorp Vault client.

  This module provides a unified error type and utilities for consistent,
  safe error handling throughout the Vaultx library. All errors are
  structured, recoverable, and provide both technical and user-friendly
  information.

  ## Design Principles

  - Consistency: All errors use the same `%Vaultx.Base.Error{}` structure
  - Safety: User-friendly messages that don't leak sensitive information
  - Recoverability: Clear indication of whether operations should be retried
  - Context: Rich error context for debugging and monitoring
  - Standards: HTTP status codes and Vault error conventions

  ## Error Categories

  - `:authentication_failed` - Authentication with Vault failed
  - `:authorization_denied` - Access denied for the requested operation
  - `:not_found` - Requested resource was not found
  - `:invalid_request` - Request was malformed or invalid
  - `:server_error` - Vault server encountered an error
  - `:network_error` - Network connectivity issues
  - `:timeout` - Request timed out
  - `:configuration_error` - Invalid configuration
  - `:json_decode_error` - Failed to parse JSON response
  - `:json_encode_error` - Failed to encode JSON request
  - `:ssl_error` - SSL/TLS related errors
  - `:rate_limited` - Request was rate limited
  - `:connection_error` - Connection-related errors
  - `:permission_denied` - Permission denied for the operation
  - `:not_implemented` - Feature not yet implemented
  - `:http_error` - HTTP protocol errors
  - `:unknown_error` - Unexpected error occurred

  ## Examples

      # Create a new error
      error = Vaultx.Base.Error.new(:not_found, "Secret not found at path")

      # Create from HTTP response
      error = Vaultx.Base.Error.from_http_response(404, %{"errors" => ["path not found"]})

      # Create from exception
      error = Vaultx.Base.Error.from_exception(%Jason.DecodeError{})

      # Check if error is recoverable
      if Vaultx.Base.Error.recoverable?(error) do
        # Retry the operation
      end

      # Get user-friendly message
      message = Vaultx.Base.Error.user_message(error)
  """

  @type error_type ::
          :authentication_failed
          | :authorization_denied
          | :not_found
          | :invalid_request
          | :server_error
          | :network_error
          | :timeout
          | :configuration_error
          | :json_decode_error
          | :json_encode_error
          | :ssl_error
          | :rate_limited
          | :connection_error
          | :permission_denied
          | :not_implemented
          | :http_error
          | :unknown_error

  @type t :: %__MODULE__{
          type: error_type(),
          message: String.t(),
          details: map(),
          vault_errors: [String.t()],
          http_status: integer() | nil,
          request_id: String.t() | nil,
          recoverable: boolean(),
          retry_after: integer() | nil
        }

  defexception [
    :type,
    :message,
    :details,
    :vault_errors,
    :http_status,
    :request_id,
    :recoverable,
    :retry_after
  ]

  @doc """
  Creates a new error with the specified type and message.

  ## Examples

      iex> error = Vaultx.Base.Error.new(:not_found, "Secret not found")
      iex> error.type
      :not_found

  """
  @spec new(error_type(), String.t(), keyword()) :: t()
  def new(type, message, opts \\ []) do
    %__MODULE__{
      type: type,
      message: message,
      details: Keyword.get(opts, :details, %{}),
      vault_errors: Keyword.get(opts, :vault_errors, []),
      http_status: Keyword.get(opts, :http_status),
      request_id: Keyword.get(opts, :request_id),
      recoverable: Keyword.get(opts, :recoverable, recoverable?(type)),
      retry_after: Keyword.get(opts, :retry_after)
    }
  end

  @doc """
  Creates an error from an HTTP response.

  ## Examples

      iex> error = Vaultx.Base.Error.from_http_response(404, %{"errors" => ["not found"]})
      iex> error.type
      :not_found

  """
  @spec from_http_response(integer(), map(), keyword()) :: t()
  def from_http_response(status, body, opts \\ []) do
    type = http_status_to_error_type(status)
    vault_errors = extract_vault_errors(body)
    message = format_http_error_message(status, vault_errors)

    new(type, message,
      http_status: status,
      vault_errors: vault_errors,
      request_id: extract_request_id(body),
      retry_after: extract_retry_after(body),
      details: Keyword.get(opts, :details, %{})
    )
  end

  @doc """
  Creates an error from an exception.

  ## Examples

      iex> error = Vaultx.Base.Error.from_exception(%Jason.DecodeError{})
      iex> error.type
      :json_decode_error

  """
  @spec from_exception(Exception.t(), keyword()) :: t()
  def from_exception(exception, opts \\ []) do
    type = exception_to_error_type(exception)
    message = Exception.message(exception)

    new(type, message,
      details: Map.merge(%{original_exception: exception}, Keyword.get(opts, :details, %{})),
      recoverable: Keyword.get(opts, :recoverable, recoverable?(type))
    )
  end

  @doc """
  Checks if an error is recoverable (can be retried).

  ## Examples

      iex> error = Vaultx.Base.Error.new(:timeout, "Request timed out")
      iex> Vaultx.Base.Error.recoverable?(error)
      true

      iex> error = Vaultx.Base.Error.new(:authentication_failed, "Invalid token")
      iex> Vaultx.Base.Error.recoverable?(error)
      false

  """
  @spec recoverable?(t() | error_type()) :: boolean()
  def recoverable?(%__MODULE__{recoverable: recoverable}), do: recoverable

  def recoverable?(type) when is_atom(type) do
    case type do
      :timeout -> true
      :network_error -> true
      :server_error -> true
      :rate_limited -> true
      :ssl_error -> false
      :authentication_failed -> false
      :authorization_denied -> false
      :not_found -> false
      :invalid_request -> false
      :configuration_error -> false
      :not_implemented -> false
      :connection_error -> true
      :permission_denied -> false
      :json_decode_error -> false
      :json_encode_error -> false
      :http_error -> true
      :unknown_error -> false
      _ -> false
    end
  end

  @doc """
  Returns a user-friendly error message.

  ## Examples

      iex> error = Vaultx.Base.Error.new(:not_found, "Secret not found at path")
      iex> Vaultx.Base.Error.user_message(error)
      "The requested resource was not found"

  """
  @spec user_message(t()) :: String.t()
  def user_message(%__MODULE__{type: type, message: message, vault_errors: vault_errors}) do
    case {type, vault_errors} do
      {:authentication_failed, []} ->
        "Authentication failed. Please check your credentials."

      {:authorization_denied, []} ->
        "Access denied. You don't have permission to perform this operation."

      {:not_found, []} ->
        "The requested resource was not found."

      {:invalid_request, []} ->
        "The request was invalid. Please check your parameters."

      {:server_error, []} ->
        "The server encountered an error. Please try again later."

      {:network_error, []} ->
        "Network error occurred. Please check your connection."

      {:timeout, []} ->
        "The request timed out. Please try again."

      {:configuration_error, []} ->
        "Configuration error: #{message}"

      {:json_decode_error, []} ->
        "Failed to parse server response."

      {:json_encode_error, []} ->
        "Failed to encode request data."

      {:ssl_error, []} ->
        "SSL/TLS error occurred. Please check your certificate configuration."

      {:rate_limited, []} ->
        "Request rate limited. Please wait before retrying."

      {:http_error, []} ->
        "HTTP protocol error occurred."

      {_, [error | _]} ->
        error

      _ ->
        message
    end
  end

  @doc """
  Returns detailed error information for debugging.

  ## Examples

      iex> error = Vaultx.Base.Error.new(:not_found, "Secret not found")
      iex> info = Vaultx.Base.Error.debug_info(error)
      iex> info.type
      :not_found

  """
  @spec debug_info(t()) :: map()
  def debug_info(%__MODULE__{} = error) do
    %{
      type: error.type,
      message: error.message,
      details: error.details,
      vault_errors: error.vault_errors,
      http_status: error.http_status,
      request_id: error.request_id,
      recoverable: error.recoverable,
      retry_after: error.retry_after
    }
  end

  # Private functions

  defp http_status_to_error_type(status) do
    case status do
      400 -> :invalid_request
      401 -> :authentication_failed
      403 -> :authorization_denied
      404 -> :not_found
      429 -> :rate_limited
      status when status >= 500 -> :server_error
      _ -> :unknown_error
    end
  end

  defp exception_to_error_type(exception) do
    case exception do
      %Jason.DecodeError{} -> :json_decode_error
      %Jason.EncodeError{} -> :json_encode_error
      %Mint.TransportError{} -> :network_error
      %Mint.HTTPError{} -> :network_error
      _ -> :unknown_error
    end
  end

  defp extract_vault_errors(%{"errors" => errors}) when is_list(errors), do: errors
  defp extract_vault_errors(_), do: []

  defp extract_request_id(%{"request_id" => request_id}), do: request_id
  defp extract_request_id(_), do: nil

  defp extract_retry_after(%{"retry_after" => retry_after}) when is_integer(retry_after),
    do: retry_after

  defp extract_retry_after(_), do: nil

  defp format_http_error_message(status, []) do
    case status do
      400 ->
        "Bad request"

      401 ->
        "Authentication failed"

      403 ->
        "Access denied"

      404 ->
        "Not found"

      429 ->
        "Rate limited"

      status when status >= 500 ->
        "Server error"

      # coveralls-ignore-start
      _ ->
        "HTTP error #{status}"
        # coveralls-ignore-stop
    end
  end

  defp format_http_error_message(_status, [error | _]), do: error
end
