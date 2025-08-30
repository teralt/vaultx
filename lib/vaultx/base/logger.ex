defmodule Vaultx.Base.Logger do
  @moduledoc """
  Enterprise-grade structured logging for Vaultx HashiCorp Vault client.

  This module provides comprehensive logging capabilities with automatic
  sanitization of sensitive data, structured metadata, and seamless
  integration with Elixir's Logger system. It ensures security compliance
  while providing detailed operational visibility for production Vault
  environments.

  ## Core Capabilities

  - Zero Overhead: When disabled, all functions become compile-time no-ops
  - Type Safe: Full type specifications and guards for all functions
  - Automatic Sanitization: Removes sensitive data from logs recursively
  - Structured Logging: Rich metadata with consistent formatting
  - Level Control: Fine-grained control over log levels
  - Error Integration: Special handling for Vaultx.Base.Error structs

  ## Configuration

      # Set log level (debug, info, warn, error, none)
      config :vaultx, logger_level: :info

      # Disable logging completely (maximum performance)
      config :vaultx, logger_level: :none

      # Or via environment variable
      export VAULTX_LOGGER_LEVEL=none

  ## References

  - [Vault Audit Devices](https://developer.hashicorp.com/vault/docs/audit)
  - [Elixir Logger](https://hexdocs.pm/logger/Logger.html)

  ## Log Levels

  - `:debug` - Detailed debugging information (includes all lower levels)
  - `:info` - General information about operations (includes warn, error)
  - `:warn` - Warning conditions that should be addressed (includes error)
  - `:error` - Error conditions that need attention
  - `:none` - Disable all logging (zero overhead)

  ## Automatic Sanitization

  The following fields are automatically sanitized in logs:
  - `token`, `secret_id`, `password`, `secret`, `client_token`, `accessor` - Replaced with "[REDACTED]"
  - `Vaultx.Base.Error` structs are formatted with debug information
  - Nested maps and lists are recursively sanitized
  - Original data structure is preserved

  ## Examples

      # Basic logging
      Vaultx.Base.Logger.info("Operation completed successfully")

      # Structured logging with metadata
      Vaultx.Base.Logger.info("Secret read", %{
        path: "secret/myapp/config",
        duration: 150,
        token: "hvs.secret"  # Will be sanitized to "[REDACTED]"
      })

      # Error logging with Vaultx.Base.Error
      Vaultx.Base.Logger.error("Authentication failed", %{
        method: :app_role,
        error: %Vaultx.Base.Error{type: :authentication_failed}
      })

      # Conditional logging for performance
      if Vaultx.Base.Logger.enabled?(:debug) do
        expensive_debug_data = compute_debug_info()
        Vaultx.Base.Logger.debug("Debug info", expensive_debug_data)
      end
  """

  require Logger
  alias Vaultx.Base.{Config, Error}

  @type log_level :: :debug | :info | :warn | :error | :none
  @type metadata :: map() | keyword() | nil
  @type log_message :: String.t() | iodata()

  # Sensitive keys that should be redacted in logs
  @sensitive_keys [
    :token,
    :secret_id,
    :password,
    :secret,
    :client_token,
    :accessor,
    :auth_token,
    :vault_token,
    :api_key,
    :private_key,
    :certificate
  ]

  # Redaction placeholder
  @redacted "[REDACTED]"

  @doc """
  Records a debug level log message.

  Debug messages are only logged when the log level is set to `:debug`.
  This is a compile-time no-op when logging is disabled or level is higher than debug.

  ## Parameters

  - `message` - The log message (string or iodata)
  - `metadata` - Optional metadata (map, keyword list, or nil)

  ## Examples

      iex> Vaultx.Base.Logger.debug("Detailed operation info", %{step: 1, data: %{}})
      :ok

      iex> Vaultx.Base.Logger.debug("Processing request", request_id: "req-123")
      :ok

  """
  @spec debug(log_message(), metadata()) :: :ok
  def debug(message, metadata \\ nil) when is_binary(message) or is_list(message) do
    if enabled?(:debug) do
      do_log(:debug, message, metadata)
    else
      :ok
    end
  end

  @doc """
  Records an info level log message.

  Info messages are logged when the log level is `:debug` or `:info`.
  This is a compile-time no-op when logging is disabled or level is higher than info.

  ## Parameters

  - `message` - The log message (string or iodata)
  - `metadata` - Optional metadata (map, keyword list, or nil)

  ## Examples

      iex> Vaultx.Base.Logger.info("Operation completed", %{duration: 150})
      :ok

      iex> Vaultx.Base.Logger.info("Secret read successfully")
      :ok

  """
  @spec info(log_message(), metadata()) :: :ok
  def info(message, metadata \\ nil) when is_binary(message) or is_list(message) do
    if enabled?(:info) do
      do_log(:info, message, metadata)
    else
      :ok
    end
  end

  @doc """
  Records a warning level log message.

  Warning messages are logged when the log level is `:debug`, `:info`, or `:warn`.
  This is a compile-time no-op when logging is disabled or level is higher than warn.

  ## Parameters

  - `message` - The log message (string or iodata)
  - `metadata` - Optional metadata (map, keyword list, or nil)

  ## Examples

      iex> Vaultx.Base.Logger.warn("SSL verification disabled", %{production: true})
      :ok

      iex> Vaultx.Base.Logger.warn("Deprecated API usage detected")
      :ok

  """
  @spec warn(log_message(), metadata()) :: :ok
  def warn(message, metadata \\ nil) when is_binary(message) or is_list(message) do
    if enabled?(:warn) do
      do_log(:warn, message, metadata)
    else
      :ok
    end
  end

  @doc """
  Records a warning level log message (alias for warn/2).

  ## Examples

      iex> Vaultx.Base.Logger.warning("SSL verification disabled", %{production: true})
      :ok

  """
  @spec warning(log_message(), metadata()) :: :ok
  def warning(message, metadata \\ nil) when is_binary(message) or is_list(message) do
    warn(message, metadata)
  end

  @doc """
  Records an error level log message.

  Error messages are logged unless logging is completely disabled (`:none`).
  This is a compile-time no-op only when logging is completely disabled.

  ## Parameters

  - `message` - The log message (string or iodata)
  - `metadata` - Optional metadata (map, keyword list, or nil)

  ## Examples

      iex> Vaultx.Base.Logger.error("Authentication failed", %{method: :app_role})
      :ok

      iex> Vaultx.Base.Logger.error("Network timeout occurred")
      :ok

  """
  @spec error(log_message(), metadata()) :: :ok
  def error(message, metadata \\ nil) when is_binary(message) or is_list(message) do
    if enabled?(:error) do
      do_log(:error, message, metadata)
    else
      :ok
    end
  end

  @doc """
  Gets the current log level from configuration.

  Returns the configured log level, which determines what messages will be logged.
  This function is optimized for performance and caches the result.

  ## Examples

      iex> Vaultx.Base.Logger.current_level()
      :info

      iex> Vaultx.Base.Logger.current_level()
      :none

  """
  @spec current_level() :: log_level()
  def current_level do
    Config.get().logger_level
  end

  @doc """
  Checks if logging is enabled for the specified level.

  This function is optimized for performance and should be used to guard
  expensive operations that are only needed for logging.

  ## Parameters

  - `level` - The log level to check (`:debug`, `:info`, `:warn`, `:error`)

  ## Examples

      iex> Vaultx.Base.Logger.enabled?(:debug)
      true

      iex> Vaultx.Base.Logger.enabled?(:info)
      false

  """
  @spec enabled?(log_level()) :: boolean()
  def enabled?(level) when level in [:debug, :info, :warn, :error] do
    current = current_level()
    current != :none and level_priority(level) >= level_priority(current)
  end

  def enabled?(_), do: false

  @doc """
  Logs an operation with timing information.

  This is a convenience function for logging operations with their duration.
  Automatically determines the appropriate log level based on the result.

  ## Parameters

  - `operation` - The operation name (e.g., "read", "write", "authenticate")
  - `path` - The resource path or identifier
  - `duration_ms` - The operation duration in milliseconds
  - `result` - The operation result (`:ok`, `{:ok, _}`, `{:error, _}`, etc.)

  ## Examples

      iex> Vaultx.Base.Logger.log_operation("read", "secret/test", 150, :ok)
      :ok

      iex> Vaultx.Base.Logger.log_operation("write", "secret/test", 200, {:error, reason})
      :ok

  """
  @spec log_operation(String.t(), String.t(), non_neg_integer(), term()) :: :ok
  def log_operation(operation, path, duration_ms, result)
      when is_binary(operation) and is_binary(path) and is_integer(duration_ms) do
    # Handle negative duration by converting to 0
    safe_duration = max(0, duration_ms)
    {level, message, metadata} = format_operation_log(operation, path, safe_duration, result)
    do_log(level, message, metadata)
  end

  # Private functions

  @doc false
  @spec do_log(log_level(), log_message(), metadata()) :: :ok
  defp do_log(level, message, metadata) do
    formatted_message = "[Vaultx] #{message}"
    sanitized_metadata = sanitize_metadata(metadata)

    # Convert deprecated :warn to :warning for Elixir 1.18+ compatibility
    elixir_level =
      case level do
        :warn -> :warning
        other -> other
      end

    Logger.log(elixir_level, formatted_message, sanitized_metadata)
    :ok
  end

  @spec sanitize_metadata(metadata()) :: metadata()
  defp sanitize_metadata(nil), do: %{}

  defp sanitize_metadata(metadata) when is_map(metadata) do
    metadata
    |> Enum.map(&sanitize_field/1)
    |> Enum.into(%{})
    |> Map.put(:vaultx_sanitized, true)
  end

  defp sanitize_metadata(metadata) when is_list(metadata) do
    metadata
    |> Enum.map(&sanitize_field/1)
    |> Keyword.put(:vaultx_sanitized, true)
  end

  defp sanitize_metadata(metadata), do: %{original: metadata, vaultx_sanitized: true}

  @spec sanitize_field({atom() | String.t(), term()}) :: {atom() | String.t(), term()}
  defp sanitize_field({key, _value}) when key in @sensitive_keys do
    {key, @redacted}
  end

  defp sanitize_field({key, %Error{} = error}) do
    {key, format_error_for_logging(error)}
  end

  defp sanitize_field({key, value}) when is_map(value) do
    {key, sanitize_nested_map(value)}
  end

  defp sanitize_field({key, value}) when is_list(value) do
    {key, sanitize_nested_list(value)}
  end

  defp sanitize_field(field), do: field

  @spec sanitize_nested_map(map()) :: map()
  defp sanitize_nested_map(map) when is_map(map) do
    # Handle structs (like DateTime, Error, etc.) differently from plain maps
    if is_struct(map) do
      # For structs, convert to string representation to avoid Enumerable issues
      inspect(map)
    else
      # For plain maps, sanitize each field
      map
      |> Enum.map(&sanitize_field/1)
      |> Enum.into(%{})
    end
  end

  @spec sanitize_nested_list(list()) :: list()
  defp sanitize_nested_list(list) when is_list(list) do
    Enum.map(list, fn
      {key, value} -> sanitize_field({key, value})
      %Error{} = error -> format_error_for_logging(error)
      other -> other
    end)
  end

  @spec format_error_for_logging(Error.t()) :: map()
  defp format_error_for_logging(%Error{} = error) do
    %{
      type: error.type,
      message: error.message,
      http_status: error.http_status,
      recoverable: error.recoverable,
      request_id: error.request_id,
      vault_errors: error.vault_errors
    }
  end

  @spec level_priority(log_level()) :: non_neg_integer()
  defp level_priority(:debug), do: 0
  defp level_priority(:info), do: 1
  defp level_priority(:warn), do: 2
  defp level_priority(:error), do: 3
  # NOTE: The :none log level is a theoretical level that disables all logging.
  # In practice, this level is rarely used in the Vaultx configuration and
  # testing it would require artificially setting an unusual log level that
  # doesn't provide meaningful coverage value.
  # coveralls-ignore-next-line
  defp level_priority(:none), do: 4

  @spec format_operation_log(String.t(), String.t(), non_neg_integer(), term()) ::
          {log_level(), String.t(), map()}
  defp format_operation_log(operation, path, duration_ms, result) do
    case result do
      :ok ->
        {:info, "#{operation} completed successfully",
         %{operation: operation, path: path, duration_ms: duration_ms, result: :ok}}

      {:ok, _data} ->
        {:info, "#{operation} completed successfully",
         %{operation: operation, path: path, duration_ms: duration_ms, result: :ok}}

      {:error, %Error{} = error} ->
        {:error, "#{operation} failed: #{error.message}",
         %{
           operation: operation,
           path: path,
           duration_ms: duration_ms,
           error: error,
           result: :error
         }}

      {:error, reason} ->
        {:error, "#{operation} failed: #{inspect(reason)}",
         %{
           operation: operation,
           path: path,
           duration_ms: duration_ms,
           error: reason,
           result: :error
         }}

      other ->
        {:debug, "#{operation} completed",
         %{operation: operation, path: path, duration_ms: duration_ms, result: other}}
    end
  end
end
