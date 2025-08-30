defmodule Vaultx.Test.Mocks do
  @moduledoc """
  Centralized mock definitions for comprehensive Vaultx testing.

  This module defines and manages all mocks used throughout the Vaultx test
  suite, providing consistent, reliable interfaces for testing HTTP clients,
  authentication methods, and external dependencies. It ensures test isolation
  and predictable behavior across the entire test suite.

  ## Mock Architecture

  - HTTP Client Mock: Complete HTTP transport layer mocking
  - Authentication Mocks: Various auth method implementations
  - External Service Mocks: Third-party service integrations
  - Global Configuration: Consistent mock setup across tests

  ## Usage

      # In test_helper.exs
      Vaultx.Test.Mocks.setup_mocks()

      # In individual tests
      import Vaultx.Test.HTTPHelpers
      expect_get(200, %{"data" => "test"})

  ## References

  - [Mox Library](https://hexdocs.pm/mox/) - Mock and stub library
  - [Testing Guide](https://hexdocs.pm/elixir/testing.html) - Elixir testing best practices
  """

  # HTTP Client Mock
  Mox.defmock(Vaultx.HTTPClientMock, for: Vaultx.Transport.HTTPBehaviour)

  @doc """
  Sets up all mocks for testing.
  """
  def setup_mocks do
    # Set global mode for all mocks
    Mox.set_mox_global()

    # Stub default behaviors
    stub_http_client()
  end

  @doc """
  Verifies all mocks have been called as expected.
  """
  def verify_mocks do
    Mox.verify!()
  end

  # Private functions

  defp stub_http_client do
    # Provide default stub for HTTP client - using import from HTTPHelpers
    import Vaultx.Test.HTTPHelpers
    stub_ok(:get, 200, %{})
  end
end
