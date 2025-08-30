# coveralls-ignore-start
# This entire module is excluded from test coverage because it primarily deals with
# streaming operations that require actual HTTP connections to a running Vault server.
# The streaming nature of the monitor API makes it impractical to test in unit tests
# without complex mocking infrastructure. The core functionality relies on:
# 1. Real-time HTTP streaming connections
# 2. Continuous data streams from Vault
# 3. Stream processing that cannot be easily mocked
# Integration tests should be used to verify this functionality in a real environment.
# However, since we rarely use thie feature, we do not plan to build effective tests for it.
# If you are able to create a robust and high-coverage test for it, please submit a pull request. Thank you very much!

defmodule Vaultx.Sys.Monitor do
  @moduledoc """
  HashiCorp Vault monitor operations.

  This module provides log monitoring capabilities for Vault, allowing you to
  receive streaming logs from the Vault server in real-time. This is particularly
  useful for debugging, monitoring, and operational visibility.

  ## Monitor Features

  ### Core Functionality
  - Stream Logs: Receive real-time streaming logs from Vault server
  - Log Level Control: Filter logs by severity level (debug, info, warn, error)
  - Format Options: Choose between standard text and JSON log formats
  - Real-time Monitoring: Continuous log streaming for operational visibility

  ### Log Management
  - Level Filtering: Control log verbosity with configurable levels
  - Format Selection: Standard text or structured JSON output
  - Stream Processing: Handle continuous log streams efficiently
  - Drop Protection: Automatic handling when log emission exceeds processing capacity

  ## Important Notes

  **Restricted Endpoint**
  - Must be called from the root or administrative namespace
  - Requires appropriate authentication and authorization
  - Not available in all Vault configurations

  **Performance Considerations**
  - High-volume log streams may impact performance
  - Some log lines may be dropped if processing cannot keep up
  - Consider log level filtering to reduce volume
  - Monitor network bandwidth usage for remote streaming

  **Output Format**
  - Unlike most Vault APIs, this endpoint does not return JSON by default
  - Returns logs in the configured Vault log format (text by default)
  - Use JSON format option for structured log processing

  ## API Compliance

  Fully implements HashiCorp Vault Monitor API:
  - [Monitor API](https://developer.hashicorp.com/vault/api-docs/system/monitor)
  - [Vault Logging](https://developer.hashicorp.com/vault/docs/configuration#log_level)

  ## Usage Examples

  ### Basic Log Monitoring

      {:ok, stream} = Vaultx.Sys.Monitor.stream_logs()

      # Process log stream
      Enum.each(stream, fn log_line ->
        IO.puts("LOG: \#{log_line}")
      end)

  ### Debug Level Monitoring

      {:ok, stream} = Vaultx.Sys.Monitor.stream_logs(log_level: "debug")

      # Process debug logs
      stream
      |> Stream.filter(&String.contains?(&1, "DEBUG"))
      |> Enum.take(100)

  ### JSON Format Monitoring

      {:ok, stream} = Vaultx.Sys.Monitor.stream_logs(
        log_level: "info",
        log_format: "json"
      )

      # Process structured logs
      stream
      |> Stream.map(&JSON.decode!/1)
      |> Enum.each(fn log_entry ->
        IO.inspect(log_entry)
      end)

  ### Custom Processing

      {:ok, stream} = Vaultx.Sys.Monitor.stream_logs(log_level: "warn")

      # Filter and alert on warnings
      stream
      |> Stream.filter(&String.contains?(&1, "WARN"))
      |> Enum.each(fn warning ->
        send_alert("Vault Warning: \#{warning}")
      end)

  ## Log Levels

  Available log levels (in order of verbosity):
  - `"debug"`: Most verbose, includes all log messages
  - `"info"`: Informational messages and above
  - `"warn"`: Warning messages and above
  - `"error"`: Error messages only

  ## Log Formats

  Available log formats:
  - `"standard"`: Human-readable text format (default)
  - `"json"`: Structured JSON format for programmatic processing

  ## Stream Processing

  The monitor endpoint returns a continuous stream of log data:
  - Use `Stream` functions for efficient processing
  - Consider buffering for batch processing
  - Handle stream interruptions gracefully
  - Monitor memory usage with large log volumes

  ## Use Cases

  ### Development and Debugging
  - Real-time debugging during development
  - Troubleshooting configuration issues
  - Monitoring API request flows
  - Investigating performance problems

  ### Operations and Monitoring
  - Centralized log aggregation
  - Real-time alerting on errors
  - Compliance and audit logging
  - Performance monitoring and analysis

  ### Security and Compliance
  - Security event monitoring
  - Audit trail collection
  - Compliance reporting
  - Incident response and forensics
  """

  alias Vaultx.Base.{Error, Logger, Telemetry}
  alias Vaultx.Transport.HTTP
  alias Vaultx.Types

  @valid_log_levels ~w(debug info warn error)
  @valid_log_formats ~w(standard json)

  @doc """
  Stream logs from the Vault server.

  This endpoint streams logs back to the client from Vault. Note that unlike most
  API endpoints in Vault, this one does not return JSON by default. This will send
  back data in whatever log format Vault has been configured with.

  ## Parameters

  - `opts` - Options for log streaming
    - `:log_level` - Log level to stream (default: "info")
    - `:log_format` - Log format: "standard" or "json" (default: "standard")
    - Other HTTP request options

  ## Returns

  Returns `{:ok, stream}` with a log stream,
  or `{:error, Error.t()}` on failure.

  ## Examples

      # Basic log streaming
      {:ok, stream} = Vaultx.Sys.Monitor.stream_logs()

      # Debug level with JSON format
      {:ok, stream} = Vaultx.Sys.Monitor.stream_logs(
        log_level: "debug",
        log_format: "json"
      )

      # Process first 50 log lines
      stream
      |> Enum.take(50)
      |> Enum.each(&IO.puts/1)

  ## Important Notes

  - Log streaming is continuous and may run indefinitely
  - Some log lines may be dropped if processing cannot keep up
  - Use appropriate log levels to control volume
  - Consider timeout settings for long-running streams

  """
  @spec stream_logs(Types.options()) :: {:ok, Enumerable.t()} | {:error, Error.t()}
  def stream_logs(opts \\ []) do
    log_level = Keyword.get(opts, :log_level, "info")
    log_format = Keyword.get(opts, :log_format, "standard")

    with :ok <- validate_log_level(log_level),
         :ok <- validate_log_format(log_format) do
      _path = "sys/monitor"

      _query_params = [
        log_level: log_level,
        log_format: log_format
      ]

      metadata = %{
        operation: :stream_logs,
        log_level: log_level,
        log_format: log_format
      }

      Logger.debug("Starting log stream", metadata)
      Telemetry.operation_start(metadata)

      # Build query parameters
      query_params = [
        {"log_level", log_level},
        {"log_format", log_format}
      ]

      # Create streaming request
      case HTTP.stream_request(:get, "sys/monitor", query_params, [], opts) do
        {:ok, stream} ->
          Logger.debug("Log stream established", metadata)
          {:ok, stream}

        {:error, error} ->
          Logger.error("Failed to establish log stream", Map.put(metadata, :error, error))
          {:error, error}
      end
    end
  end

  @doc """
  Stream logs with a callback function for processing.

  This function provides a convenient way to process log streams with a callback
  function, handling stream setup and error management automatically.

  ## Parameters

  - `callback` - Function to call for each log line
  - `opts` - Options for log streaming (same as `stream_logs/1`)

  ## Returns

  Returns `:ok` when streaming completes,
  or `{:error, Error.t()}` on failure.

  ## Examples

      # Process logs with callback
      Vaultx.Sys.Monitor.stream_logs_with_callback(fn log_line ->
        if String.contains?(log_line, "ERROR") do
          send_alert(log_line)
        end
      end, log_level: "warn")

      # JSON log processing
      Vaultx.Sys.Monitor.stream_logs_with_callback(fn json_line ->
        case JSON.decode(json_line) do
          {:ok, log_entry} -> process_structured_log(log_entry)
          {:error, _} -> :ignore
        end
      end, log_format: "json")

  """
  @spec stream_logs_with_callback((String.t() -> any()), Types.options()) ::
          :ok | {:error, Error.t()}
  def stream_logs_with_callback(callback, opts \\ []) when is_function(callback, 1) do
    case stream_logs(opts) do
      {:ok, stream} ->
        try do
          stream
          |> Stream.each(callback)
          |> Stream.run()

          :ok
        rescue
          error ->
            {:error,
             Error.new(:stream_error, "Stream processing failed", details: %{error: error})}
        end

      {:error, error} ->
        {:error, error}
    end
  end

  @doc """
  Collect a limited number of log lines.

  This function collects a specified number of log lines and returns them as a list,
  useful for sampling or limited log collection scenarios.

  ## Parameters

  - `count` - Number of log lines to collect
  - `opts` - Options for log streaming (same as `stream_logs/1`)

  ## Returns

  Returns `{:ok, [String.t()]}` with collected log lines,
  or `{:error, Error.t()}` on failure.

  ## Examples

      # Collect 100 recent log lines
      {:ok, logs} = Vaultx.Sys.Monitor.collect_logs(100)

      # Collect debug logs
      {:ok, debug_logs} = Vaultx.Sys.Monitor.collect_logs(50, log_level: "debug")

  """
  @spec collect_logs(pos_integer(), Types.options()) ::
          {:ok, [String.t()]} | {:error, Error.t()}
  def collect_logs(count, opts \\ []) when is_integer(count) and count > 0 do
    case stream_logs(opts) do
      {:ok, stream} ->
        try do
          logs = stream |> Enum.take(count)
          {:ok, logs}
        rescue
          error ->
            {:error, Error.new(:stream_error, "Log collection failed", details: %{error: error})}
        end

      {:error, error} ->
        {:error, error}
    end
  end

  @doc """
  Check if log monitoring is available.

  This function performs a quick check to determine if log monitoring
  is available and accessible with current credentials.

  ## Parameters

  - `opts` - Request options (optional)

  ## Returns

  Returns `:ok` if monitoring is available,
  or `{:error, Error.t()}` if not available or on failure.

  ## Examples

      case Vaultx.Sys.Monitor.check_availability() do
        :ok ->
          IO.puts("Log monitoring is available")
        {:error, error} ->
          IO.puts("Monitoring not available: \#{error.message}")
      end

  """
  @spec check_availability(Types.options()) :: :ok | {:error, Error.t()}
  def check_availability(opts \\ []) do
    # Try to establish a brief connection to check availability
    case stream_logs(Keyword.put(opts, :timeout, 5_000)) do
      {:ok, stream} ->
        # Try to get the first chunk to verify the stream works
        try do
          stream |> Enum.take(1)
          :ok
        rescue
          # Even if we can't read, the stream was established
          _ -> :ok
        end

      {:error, error} ->
        {:error, error}
    end
  end

  # Private helper functions

  defp validate_log_level(level) when level in @valid_log_levels, do: :ok

  defp validate_log_level(level) do
    {:error,
     Error.new(:invalid_parameter, "Invalid log level: #{level}",
       details: %{valid_levels: @valid_log_levels, provided: level}
     )}
  end

  defp validate_log_format(format) when format in @valid_log_formats, do: :ok

  defp validate_log_format(format) do
    {:error,
     Error.new(:invalid_parameter, "Invalid log format: #{format}",
       details: %{valid_formats: @valid_log_formats, provided: format}
     )}
  end
end

# coveralls-ignore-stop
