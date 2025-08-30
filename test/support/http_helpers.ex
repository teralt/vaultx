defmodule Vaultx.Test.HTTPHelpers do
  @moduledoc """
  Comprehensive HTTP mocking utilities for Vaultx testing.

  This module provides a unified, consistent interface for mocking HTTP
  interactions in Vaultx tests. It supports all HTTP methods, automatic
  JSON handling, flexible assertions, and both single-use expectations
  and reusable stubs.

  ## Key Features

  - Method Coverage: Support for all HTTP methods (GET, POST, PUT, PATCH, DELETE)
  - JSON Handling: Automatic JSON encoding/decoding with configurable options
  - Flexible Assertions: URL, body, and options validation with custom functions
  - Error Simulation: Both structured Vaultx errors and raw error conditions
  - Response Patterns: Standard and enveloped response formats
  - Test Isolation: Single-use expectations and reusable stubs

  ## Usage Patterns

      # Simple GET expectation
      expect_get(200, %{"data" => "value"})

      # POST with body validation
      expect_post(201, %{"id" => 123}, fn _url, body, _opts ->
        assert body["name"] == "test"
      end)

      # Error simulation
      stub_request(:get, :not_found, "Secret not found")

  ## References

  - [Mox Documentation](https://hexdocs.pm/mox/) - Underlying mock library
  - [ExUnit.Assertions](https://hexdocs.pm/ex_unit/ExUnit.Assertions.html) - Assertion helpers
  """

  import Mox
  import ExUnit.Assertions
  alias Vaultx.Base.{Error, JSON}

  # Core response builders
  @doc "Return a standard successful HTTP tuple"
  def ok_resp(status, body), do: {:ok, %{status: status, body: body, headers: []}}

  @doc "Return an enveloped response with data wrapper"
  def ok_resp_enveloped(status, inner_data), do: ok_resp(status, %{"data" => inner_data})

  # Body processing
  defp maybe_decode(req_body, decode) do
    case decode do
      true ->
        JSON.decode!(req_body)

      false ->
        req_body

      :auto ->
        case JSON.decode(req_body) do
          {:ok, decoded} -> decoded
          _ -> req_body
        end
    end
  end

  # Generic expect/stub builders
  defp do_expect(method, status, body, assert_fn, decode) do
    Vaultx.HTTPClientMock
    |> expect(:request, fn req_method, url, req_body, _headers, opts when req_method == method ->
      processed_body = maybe_decode(req_body, decode)
      if assert_fn, do: assert_fn.(url, processed_body, opts)
      ok_resp(status, body)
    end)
  end

  defp do_stub(method, status, body, assert_fn, decode) do
    Vaultx.HTTPClientMock
    |> stub(:request, fn req_method, url, req_body, _headers, opts when req_method == method ->
      processed_body = maybe_decode(req_body, decode)
      if assert_fn, do: assert_fn.(url, processed_body, opts)
      ok_resp(status, body)
    end)
  end

  # Generic expect/stub builders with headers support
  defp do_expect_with_headers(method, status, body, assert_fn, decode) do
    Vaultx.HTTPClientMock
    |> expect(:request, fn req_method, url, req_body, headers, opts when req_method == method ->
      processed_body = maybe_decode(req_body, decode)
      if assert_fn, do: assert_fn.(url, processed_body, headers, opts)
      ok_resp(status, body)
    end)
  end

  defp do_stub_with_headers(method, status, body, assert_fn, decode) do
    Vaultx.HTTPClientMock
    |> stub(:request, fn req_method, url, req_body, headers, opts when req_method == method ->
      processed_body = maybe_decode(req_body, decode)
      if assert_fn, do: assert_fn.(url, processed_body, headers, opts)
      ok_resp(status, body)
    end)
  end

  # Expect methods (for single-use assertions)
  @doc "Expect a GET request"
  def expect_get(status, body, assert_fn \\ fn _url, _body, _opts -> :ok end) do
    do_expect(:get, status, body, assert_fn, false)
  end

  @doc "Expect a POST request with optional JSON decode"
  def expect_post(status, body, assert_fn \\ fn _url, _body, _opts -> :ok end, opts \\ []) do
    decode = Keyword.get(opts, :decode, :auto)
    do_expect(:post, status, body, assert_fn, decode)
  end

  @doc "Expect a PUT request with optional JSON decode"
  def expect_put(status, body, assert_fn \\ fn _url, _body, _opts -> :ok end, opts \\ []) do
    decode = Keyword.get(opts, :decode, :auto)
    do_expect(:put, status, body, assert_fn, decode)
  end

  @doc "Expect a PATCH request with optional JSON decode"
  def expect_patch(status, body, assert_fn \\ fn _url, _body, _opts -> :ok end, opts \\ []) do
    decode = Keyword.get(opts, :decode, :auto)
    do_expect(:patch, status, body, assert_fn, decode)
  end

  @doc "Expect a DELETE request"
  def expect_delete(status, body, assert_fn \\ fn _url, _body, _opts -> :ok end) do
    do_expect(:delete, status, body, assert_fn, false)
  end

  @doc "Expect any method with simple response (fallback)"
  def expect_any(method, status, body, assert_fn \\ fn _url, _body, _opts -> :ok end) do
    decode = if method in [:post, :put, :patch], do: :auto, else: false
    do_expect(method, status, body, assert_fn, decode)
  end

  # Expect methods with headers support (for tests that need to check headers)
  @doc "Expect a GET request with headers access"
  def expect_get_with_headers(
        status,
        body,
        assert_fn \\ fn _url, _body, _headers, _opts -> :ok end
      ) do
    do_expect_with_headers(:get, status, body, assert_fn, false)
  end

  @doc "Expect a POST request with headers access and optional JSON decode"
  def expect_post_with_headers(
        status,
        body,
        assert_fn \\ fn _url, _body, _headers, _opts -> :ok end,
        opts \\ []
      ) do
    decode = Keyword.get(opts, :decode, :auto)
    do_expect_with_headers(:post, status, body, assert_fn, decode)
  end

  @doc "Expect a PUT request with headers access and optional JSON decode"
  def expect_put_with_headers(
        status,
        body,
        assert_fn \\ fn _url, _body, _headers, _opts -> :ok end,
        opts \\ []
      ) do
    decode = Keyword.get(opts, :decode, :auto)
    do_expect_with_headers(:put, status, body, assert_fn, decode)
  end

  @doc "Expect a PATCH request with headers access and optional JSON decode"
  def expect_patch_with_headers(
        status,
        body,
        assert_fn \\ fn _url, _body, _headers, _opts -> :ok end,
        opts \\ []
      ) do
    decode = Keyword.get(opts, :decode, :auto)
    do_expect_with_headers(:patch, status, body, assert_fn, decode)
  end

  @doc "Expect a DELETE request with headers access"
  def expect_delete_with_headers(
        status,
        body,
        assert_fn \\ fn _url, _body, _headers, _opts -> :ok end
      ) do
    do_expect_with_headers(:delete, status, body, assert_fn, false)
  end

  # Stub methods (for repeated use/retries)
  @doc "Stub any method with success response"
  def stub_ok(method, status, body, assert_fn \\ fn _url, _body, _opts -> :ok end, opts \\ []) do
    decode = Keyword.get(opts, :decode, false)
    do_stub(method, status, body, assert_fn, decode)
  end

  @doc "Stub any method with Vaultx.Base.Error"
  def stub_request(method, type, message) do
    Vaultx.HTTPClientMock
    |> stub(:request, fn ^method, _url, _body, _headers, _opts ->
      {:error, Error.new(type, message)}
    end)
  end

  @doc "Stub any method with raw error"
  def stub_request_raw(_method, reason) do
    Vaultx.HTTPClientMock
    |> stub(:request, fn _method, _url, _body, _headers, _opts -> {:error, reason} end)
  end

  # Stub methods with headers support
  @doc "Stub any method with success response and headers access"
  def stub_ok_with_headers(
        method,
        status,
        body,
        assert_fn \\ fn _url, _body, _headers, _opts -> :ok end,
        opts \\ []
      ) do
    decode = Keyword.get(opts, :decode, false)
    do_stub_with_headers(method, status, body, assert_fn, decode)
  end

  # Convenience helpers
  @doc "Expect GET with enveloped data response"
  def expect_get_enveloped(status, inner_data, assert_fn \\ fn _url, _body, _opts -> :ok end) do
    expect_get(status, %{"data" => inner_data}, assert_fn)
  end

  @doc "Assert LIST method in opts"
  def assert_list_method(_url, _body, opts) do
    assert opts[:method] == "LIST"
  end

  @doc "Assert URL contains fragment"
  def assert_url_contains(fragment) do
    fn url, _body, _opts -> assert String.contains?(url, fragment) end
  end

  @doc "Assert error type and call function"
  def assert_error(expected_type, fun) do
    assert {:error, %Error{type: ^expected_type}} = fun.()
  end
end
