defmodule Vaultx.Transport.HTTPBehaviour do
  @moduledoc """
  Behaviour definition for HashiCorp Vault HTTP transport implementations.

  This behaviour defines the comprehensive interface that HTTP transport
  implementations must implement for secure, reliable communication with
  Vault servers. It ensures consistency across different HTTP client
  implementations and testing scenarios.

  ## Design Requirements

  - Type Safety: All operations use well-defined types
  - Error Handling: Structured error responses with context
  - Security: Support for authentication and SSL/TLS
  - Performance: Efficient request/response handling
  - Testability: Easy mocking and testing support

  ## Implementation Guidelines

  HTTP transport implementations should:
  - Handle all standard HTTP methods (GET, POST, PUT, DELETE, PATCH)
  - Support request/response body encoding/decoding
  - Implement proper error handling and classification
  - Provide detailed error context for debugging
  - Support authentication headers and tokens

  ## References

  - [Vault HTTP API](https://developer.hashicorp.com/vault/api-docs)
  - [HTTP Client Best Practices](https://developer.hashicorp.com/vault/docs/concepts/client-count)
  """

  alias Vaultx.Types

  @doc """
  Makes an HTTP request to the specified URL.

  ## Parameters

    * `method` - HTTP method (:get, :post, :put, :patch, :delete)
    * `url` - Full URL to make the request to
    * `body` - Request body (map, string, or nil)
    * `headers` - List of HTTP headers as tuples
    * `opts` - Additional options for the request

  ## Returns

    * `{:ok, response}` - Successful response with status, body, and headers
    * `{:error, %Vaultx.Base.Error{}}` - Request failed with detailed error

  ## Examples

      iex> HTTPClient.request(:get, "https://vault.example.com/v1/sys/health", nil, [], [])
      {:ok, %{status: 200, body: %{"initialized" => true}, headers: []}}

      iex> HTTPClient.request(:post, "https://vault.example.com/v1/auth/token/create", %{}, [], [])
      {:ok, %{status: 200, body: %{"auth" => %{"client_token" => "hvs.123"}}, headers: []}}

  """
  @callback request(
              Types.http_method(),
              String.t(),
              Types.body(),
              Types.headers(),
              Types.options()
            ) :: Types.http_result()
end
