defmodule Vaultx.Types do
  @moduledoc """
  Comprehensive type definitions for Vaultx HashiCorp Vault client.

  This module centralizes all type definitions used throughout the Vaultx
  library, providing type safety, documentation, and consistency across
  all modules and operations.

  ## Type Categories

  ### Core Types
  Basic types used throughout the library for options and results.

  ### HTTP Transport Types
  Types for HTTP communication with Vault servers.

  ## Usage

  These types are primarily used for:
  - Function specifications (`@spec`)
  - Documentation and IDE support
  - Runtime validation where appropriate
  - Dialyzer static analysis

  ## References

  - [Vault API Documentation](https://developer.hashicorp.com/vault/api-docs)
  - [Elixir Typespecs](https://hexdocs.pm/elixir/typespecs.html)
  """

  # Core types
  @type options :: keyword()
  @type result(success_type) :: {:ok, success_type} | {:error, Vaultx.Base.Error.t()}
  @type result :: result(term())

  # HTTP transport types
  @type http_method :: :get | :post | :put | :delete | :patch | :list
  @type headers :: [{String.t(), String.t()}]
  @type body :: map() | String.t() | nil
  @type response :: %{
          status: integer(),
          headers: headers(),
          body: term()
        }
  @type http_result :: result(response())
end
