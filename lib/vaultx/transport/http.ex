defmodule Vaultx.Transport.HTTP do
  @behaviour Vaultx.Transport.HTTPBehaviour

  @moduledoc """
  High-performance HTTP transport for HashiCorp Vault communication.

  This module provides the core HTTP transport layer for Vaultx, implementing
  enterprise-grade features including connection pooling, automatic retries,
  comprehensive security, and detailed observability. It's optimized for
  production workloads with Vault clusters.

  ## Enterprise Features

  - High Performance: Built on Req and Finch for maximum throughput
  - Connection Pooling: Efficient connection reuse and lifecycle management
  - Intelligent Retries: Exponential backoff with jitter for resilience
  - Security First: SSL/TLS validation, secure header management
  - Full Observability: Telemetry, structured logging, and metrics
  - Error Recovery: Detailed error classification and recovery strategies

  ## Configuration

  Configure through the main Vaultx configuration:

      config :vaultx,
        url: "https://vault.example.com:8200",
        timeout: 30_000,
        retry_attempts: 3,
        retry_delay: 1_000,
        ssl_verify: true,
        pool_size: 10

  ## Usage Examples

      # Simple GET request
      {:ok, response} = Vaultx.Transport.HTTP.get("sys/health")

      # POST with authentication
      {:ok, response} = Vaultx.Transport.HTTP.post("auth/approle/login", %{
        role_id: "app-role-id",
        secret_id: "secret-id"
      })

      # Advanced request with custom options
      {:ok, response} = Vaultx.Transport.HTTP.request(:get, "secret/data/app", nil, [], [
        timeout: 60_000,
        retry_attempts: 5,
        token: "vault-token"
      ])

  ## API Compliance

  Fully implements HashiCorp Vault HTTP API requirements:
  - [Vault HTTP API](https://developer.hashicorp.com/vault/api-docs)
  - [API Response Format](https://developer.hashicorp.com/vault/api-docs#response-format)
  """

  alias Vaultx.Base.{Config, Error, JSON, Logger, Security, Telemetry}
  alias Vaultx.Types

  @default_headers [
    {"content-type", "application/json"},
    {"accept", "application/json"},
    {"user-agent", "Vaultx/#{Application.spec(:vaultx, :vsn)}"}
  ]

  @doc """
  Performs a GET request to the specified path.

  ## Examples

      iex> Vaultx.Transport.HTTP.get("sys/health")
      {:ok, %{status: 200, body: %{"initialized" => true}}}

  """
  @spec get(String.t(), Types.options()) :: Types.http_result()
  def get(path, opts \\ []) do
    request(:get, path, nil, [], opts)
  end

  @doc """
  Performs a POST request with the specified data.

  ## Examples

      iex> Vaultx.Transport.HTTP.post("auth/approle/login", %{role_id: "...", secret_id: "..."})
      {:ok, %{status: 200, body: %{"auth" => %{"client_token" => "..."}}}}

  """
  @spec post(String.t(), Types.body(), Types.options()) :: Types.http_result()
  def post(path, body, opts \\ []) do
    request(:post, path, body, [], opts)
  end

  @doc """
  Performs a PUT request with the specified data.

  ## Examples

      iex> Vaultx.Transport.HTTP.put("secret/data/test", %{data: %{key: "value"}})
      {:ok, %{status: 200, body: %{}}}

  """
  @spec put(String.t(), Types.body(), Types.options()) :: Types.http_result()
  def put(path, body, opts \\ []) do
    request(:put, path, body, [], opts)
  end

  @doc """
  Performs a DELETE request to the specified path.

  ## Examples

      iex> Vaultx.Transport.HTTP.delete("secret/data/test")
      {:ok, %{status: 204, body: nil}}

  """
  @spec delete(String.t(), Types.options()) :: Types.http_result()
  def delete(path, opts \\ []) do
    request(:delete, path, nil, [], opts)
  end

  @doc """
  Performs a PATCH request with the specified data.

  ## Examples

      iex> Vaultx.Transport.HTTP.patch("secret/data/test", %{data: %{key: "new_value"}})
      {:ok, %{status: 200, body: %{}}}

  """
  @spec patch(String.t(), Types.body(), Types.options()) :: Types.http_result()
  def patch(path, body, opts \\ []) do
    request(:patch, path, body, [], opts)
  end

  @doc """
  Performs an HTTP request with full control over method, path, body, headers, and options.

  ## Options

    * `:timeout` - Request timeout in milliseconds
    * `:retry_attempts` - Number of retry attempts
    * `:retry_delay` - Base delay between retries in milliseconds
    * `:headers` - Additional headers to include
    * `:token` - Vault token to use for authentication

  ## Examples

      iex> Vaultx.Transport.HTTP.request(:get, "secret/data/test", nil, [], timeout: 60_000)
      {:ok, %{status: 200, body: %{"data" => %{"data" => %{"key" => "value"}}}}}

  """
  @spec request(Types.http_method(), String.t(), Types.body(), Types.headers(), Types.options()) ::
          Types.http_result()
  def request(method, path, body, headers, opts) do
    config = Config.get()
    request_opts = build_request_options(config, opts)

    # Simple client-side rate limiting (average spacing) when enabled
    if request_opts.rate_limit_enabled and request_opts.rate_limit_requests > 0 do
      spacing = max(div(1000, request_opts.rate_limit_requests), 0)
      if spacing > 0, do: Process.sleep(spacing)
    end

    url = build_url(config.url, path)
    final_headers = build_headers(headers, request_opts, config)
    final_body = encode_body(body)

    request_id = Security.generate_request_id()

    metadata = %{
      method: method,
      path: path,
      url: url,
      request_id: request_id,
      has_body: body != nil
    }

    if request_opts.audit_enabled do
      Security.audit_log(:http, :attempt, metadata)
    end

    Logger.debug("HTTP request starting", metadata)
    if request_opts.metrics_enabled, do: Telemetry.http_request_start(metadata)

    start_time = System.monotonic_time()

    # Rate limit: consume token (blocks if needed), per-bucket by host|namespace
    if request_opts.rate_limit_enabled and request_opts.rate_limit_requests > 0 do
      host = URI.parse(url).host || "default"
      ns = get_namespace_from_headers(final_headers) || (config.namespace || "default")
      bucket_key = host <> "|" <> ns

      Vaultx.Base.RateLimiter.consume(
        bucket_key,
        request_opts.rate_limit_requests,
        request_opts.rate_limit_burst
      )
    end

    result =
      if request_opts.retry_attempts > 0 do
        perform_request_with_retry(method, url, final_body, final_headers, request_opts, metadata)
      else
        perform_request(method, url, final_body, final_headers, request_opts)
      end

    duration = System.monotonic_time() - start_time

    case result do
      {:ok, response} ->
        Logger.debug(
          "HTTP request completed successfully",
          Map.put(metadata, :status, response.status)
        )

        if request_opts.metrics_enabled do
          Telemetry.http_request_stop(duration, Map.put(metadata, :status, response.status))
        end

        if request_opts.audit_enabled do
          Security.audit_log(:http, :success, Map.put(metadata, :status, response.status))
        end

        # Optional basic security header validation (non-fatal)
        if request_opts.security_headers_enabled do
          validate_security_headers(response)
        end

        {:ok, response}

      {:error, error} ->
        Logger.error(
          "HTTP request failed",
          Map.merge(metadata, %{
            error: error,
            duration_ms: System.convert_time_unit(duration, :native, :millisecond)
          })
        )

        if request_opts.metrics_enabled do
          Telemetry.http_request_exception(duration, Map.put(metadata, :error, error))
        end

        if request_opts.audit_enabled do
          Security.audit_log(:http, :failure, Map.put(metadata, :error, error.type))
        end

        {:error, error}
    end
  end

  defp validate_security_headers(%{headers: headers}) do
    # Non-fatal checks; log warnings if missing common security headers from Vault
    headers = Enum.into(headers, %{}, fn {k, v} -> {String.downcase(k), v} end)
    required = ["content-type"]

    Enum.each(required, fn h ->
      unless Map.has_key?(headers, h) do
        Logger.warn("Missing response header", %{header: h})
      end
    end)

    :ok
  end

  # Private functions

  # coveralls-ignore-start
  # NOTE: Excluded from unit coverage because it depends on filesystem layout and certificate files.
  # It is exercised implicitly in integration environments via Req TLS options, but not deterministically
  # unit-testable across OS/filesystem variations.
  # If you find some bugs in this function, we need you help to create a PR with a deterministic test :).
  defp load_cacerts_from_dir(dir) do
    case File.ls(dir) do
      {:ok, files} ->
        files
        |> Enum.filter(&String.ends_with?(&1, [".pem", ".crt"]))
        |> Enum.map(&Path.join(dir, &1))
        |> Enum.flat_map(fn path ->
          case File.read(path) do
            {:ok, pem} ->
              :public_key.pem_decode(pem)
              |> Enum.flat_map(fn
                {:Certificate, der, _} -> [der]
                {:cert, der, _} -> [der]
                _ -> []
              end)

            _ ->
              []
          end
        end)

      _ ->
        []
        # coveralls-ignore-stop
    end
  end

  defp build_request_options(config, opts) do
    base_opts = %{
      timeout: Keyword.get(opts, :timeout, config.timeout),
      connect_timeout: Keyword.get(opts, :connect_timeout, config.connect_timeout),
      retry_attempts: Keyword.get(opts, :retry_attempts, config.retry_attempts),
      retry_delay: Keyword.get(opts, :retry_delay, config.retry_delay),
      retry_backoff: Keyword.get(opts, :retry_backoff, config.retry_backoff),
      max_retry_delay: Keyword.get(opts, :max_retry_delay, config.max_retry_delay),
      rate_limit_enabled: Keyword.get(opts, :rate_limit_enabled, config.rate_limit_enabled),
      rate_limit_requests: Keyword.get(opts, :rate_limit_requests, config.rate_limit_requests),
      rate_limit_burst: Keyword.get(opts, :rate_limit_burst, config.rate_limit_burst),
      audit_enabled: Keyword.get(opts, :audit_enabled, config.audit_enabled),
      metrics_enabled: Keyword.get(opts, :metrics_enabled, config.metrics_enabled),
      security_headers_enabled:
        Keyword.get(opts, :security_headers_enabled, config.security_headers_enabled),
      token: Keyword.get(opts, :token, config.token),
      ssl_verify: config.ssl_verify,
      cacert: config.cacert,
      cacerts_dir: config.cacerts_dir,
      client_cert: config.client_cert,
      client_key: config.client_key,
      tls_server_name: config.tls_server_name,
      tls_min_version: config.tls_min_version
    }

    # Add method if specified (for LIST operations)
    case Keyword.get(opts, :method) do
      nil -> base_opts
      method -> Map.put(base_opts, :method, method)
    end
  end

  defp build_url(base_url, path) do
    base_url = String.trim_trailing(base_url, "/")
    path = String.trim_leading(path, "/")
    "#{base_url}/v1/#{path}"
  end

  defp build_headers(additional_headers, opts, config) do
    headers = @default_headers ++ additional_headers

    headers =
      if opts.token do
        [{"x-vault-token", opts.token} | headers]
      else
        headers
      end

    headers =
      if config.namespace do
        [{"x-vault-namespace", config.namespace} | headers]
      else
        headers
      end

    # Add request ID for tracing
    request_id = Security.generate_request_id()
    [{"x-vault-request", request_id} | headers]
  end

  defp get_namespace_from_headers(headers) do
    case Enum.find(headers, fn {k, _v} -> String.downcase(k) == "x-vault-namespace" end) do
      {_, v} -> v
      # Fallback when namespace header is not found - defensive programming
      # coveralls-ignore-next-line
      _ -> nil
    end
  end

  defp encode_body(nil), do: ""
  defp encode_body(body) when is_binary(body), do: body

  defp encode_body(body) when is_map(body) do
    {:ok, json} = JSON.encode(body)
    json
  end

  defp perform_request_with_retry(method, url, body, headers, opts, metadata, attempt \\ 1) do
    case perform_request(method, url, body, headers, opts) do
      {:ok, response} ->
        {:ok, response}

      {:error, error} ->
        if Error.recoverable?(error) and attempt <= opts.retry_attempts do
          delay = calculate_retry_delay_with_backoff(opts, attempt)

          Logger.debug(
            "Retrying HTTP request",
            Map.merge(metadata, %{
              attempt: attempt,
              max_attempts: opts.retry_attempts,
              delay_ms: delay,
              error: error.type
            })
          )

          Process.sleep(delay)
          perform_request_with_retry(method, url, body, headers, opts, metadata, attempt + 1)
        else
          {:error, error}
        end
    end
  end

  defp calculate_retry_delay_with_backoff(opts, attempt) do
    base = opts.retry_delay

    delay =
      case opts.retry_backoff do
        :linear ->
          base * attempt

        :exponential ->
          base * :math.pow(2, attempt - 1)

        # coveralls-ignore-start
        # Default case for unknown backoff strategies - defensive programming
        _ ->
          base * :math.pow(2, attempt - 1)
          # coveralls-ignore-stop
      end

    delay = round(delay)
    delay = if opts.max_retry_delay, do: min(delay, opts.max_retry_delay), else: delay
    # jitter 0-250ms
    delay + :rand.uniform(250)
  end

  defp perform_request(method, url, body, headers, opts) do
    # Use configurable HTTP client for testing
    http_client = Application.get_env(:vaultx, :http_client, :req)

    case http_client do
      :req ->
        # coveralls-ignore-start
        perform_req_request(method, url, body, headers, opts)

      # coveralls-ignore-stop

      client_module ->
        case client_module.request(method, url, body, headers, opts) do
          {:ok, response} ->
            {:ok, response}

          {:error, %Error{} = error} ->
            {:error, error}

          {:error, error} when is_atom(error) ->
            {:error, Error.new(:network_error, "HTTP request failed: #{error}")}

          {:error, error} ->
            {:error, Error.from_exception(error)}
        end
    end
  end

  # coveralls-ignore-start
  defp perform_req_request(method, url, body, headers, opts) do
    # TLS / SSL options
    connect_transport_opts =
      if opts.ssl_verify do
        # Build transport opts from config
        base = []
        base = if opts.cacert, do: [{:cacertfile, opts.cacert} | base], else: base

        base =
          if opts.cacerts_dir do
            cacerts = load_cacerts_from_dir(opts.cacerts_dir)
            if cacerts != [], do: [{:cacerts, cacerts} | base], else: base
          else
            base
          end

        base = if opts.client_cert, do: [{:certfile, opts.client_cert} | base], else: base
        base = if opts.client_key, do: [{:keyfile, opts.client_key} | base], else: base

        base =
          if opts.tls_server_name,
            do: [{:server_name_indication, to_charlist(opts.tls_server_name)} | base],
            else: base

        min_ver =
          case opts.tls_min_version do
            "1.3" -> :tlsv1_3
            _ -> :tlsv1_2
          end

        [{:versions, [min_ver]} | base]
      else
        [verify: :verify_none]
      end

    connect_options = [
      transport_opts: connect_transport_opts,
      timeout: opts.connect_timeout
    ]

    req_opts = [
      method: method,
      url: url,
      body: body,
      headers: headers,
      connect_options: connect_options,
      receive_timeout: opts.timeout
    ]

    case Req.request(req_opts) do
      {:ok, %Req.Response{status: status, headers: response_headers, body: response_body}} ->
        parsed_body = parse_response_body(response_body, response_headers)

        response = %{
          status: status,
          headers: Enum.to_list(response_headers),
          body: parsed_body
        }

        if status >= 400 do
          {:error, Error.from_http_response(status, parsed_body)}
        else
          {:ok, response}
        end

      {:error, %Req.TransportError{} = error} ->
        {:error, Error.from_exception(error)}

      {:error, error} ->
        {:error, Error.from_exception(error)}
    end
  end

  defp parse_response_body("", _headers), do: nil
  defp parse_response_body(body, _headers) when not is_binary(body), do: body

  defp parse_response_body(body, headers) do
    content_type = get_header_value(headers, "content-type")

    if String.contains?(content_type || "", "application/json") do
      case JSON.decode(body) do
        {:ok, parsed} -> parsed
        {:error, _} -> body
      end
    else
      body
    end
  end

  defp get_header_value(headers, name) do
    headers
    |> Enum.find(fn {key, _value} -> String.downcase(key) == String.downcase(name) end)
    |> case do
      {_key, value} -> value
      nil -> nil
    end
  end

  # coveralls-ignore-stop

  @doc """
  Performs a streaming HTTP request to the Vault API.

  This function creates a stream for long-running requests like log monitoring.
  It returns a stream that yields chunks of data as they arrive.

  ## Parameters

  - `method` - HTTP method (`:get`, `:post`, etc.)
  - `path` - API path relative to `/v1/`
  - `query_params` - Query parameters as list of tuples
  - `headers` - Additional headers
  - `opts` - Request options

  ## Returns

  Returns `{:ok, Enumerable.t()}` on success or `{:error, Error.t()}` on failure.

  ## Examples

      {:ok, stream} = HTTP.stream_request(:get, "sys/monitor", [{"log_level", "info"}], [], [])

      stream
      |> Stream.each(&IO.puts/1)
      |> Stream.run()

  """
  @spec stream_request(
          Types.http_method(),
          String.t(),
          [{String.t(), String.t()}],
          Types.headers(),
          Types.options()
        ) ::
          {:ok, Enumerable.t()} | {:error, Error.t()}
  # coveralls-ignore-start
  # Stream request function is difficult to test in unit tests as it requires
  # actual streaming HTTP connections and message passing
  def stream_request(method, path, query_params \\ [], headers \\ [], opts \\ []) do
    config = Config.get()
    request_opts = build_request_options(config, opts)

    url = build_url_with_query(config.url, path, query_params)
    final_headers = build_headers(headers, request_opts, config)

    # Create streaming request using Req
    req_opts = [
      method: method,
      url: url,
      headers: final_headers,
      receive_timeout: request_opts.timeout,
      finch: Vaultx.Finch,
      into: :self
    ]

    case Req.request(req_opts) do
      {:ok, %Req.Response{status: status}} when status in 200..299 ->
        # Create a stream that receives chunks
        stream =
          Stream.unfold(:start, fn
            :start ->
              receive do
                {:req_chunk, chunk} -> {chunk, :continue}
                {:req_done} -> nil
              after
                request_opts.timeout -> nil
              end

            :continue ->
              receive do
                {:req_chunk, chunk} -> {chunk, :continue}
                {:req_done} -> nil
              after
                request_opts.timeout -> nil
              end
          end)

        {:ok, stream}

      {:ok, %Req.Response{status: status, body: body}} ->
        {:error, Error.from_http_response(status, body)}

      {:error, error} ->
        {:error, Error.new(:network_error, "Stream request failed", details: %{error: error})}
    end
  end

  # coveralls-ignore-stop

  # coveralls-ignore-start
  # This function is only used by stream_request which is already ignored from coverage
  # Stream operations require actual HTTP streaming connections which are not testable in unit tests
  defp build_url_with_query(base_url, path, query_params) do
    base_url = String.trim_trailing(base_url, "/")
    path = String.trim_leading(path, "/")
    url = "#{base_url}/v1/#{path}"

    if query_params != [] do
      query_string = URI.encode_query(query_params)
      "#{url}?#{query_string}"
    else
      url
    end
  end

  # coveralls-ignore-stop
end
