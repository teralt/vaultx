defmodule Vaultx.Base.JSON do
  @moduledoc """
  Adaptive JSON processing for Vaultx HashiCorp Vault client.

  This module provides a unified JSON interface that automatically selects
  the best available JSON library for optimal performance and compatibility.
  It supports both modern Elixir built-in JSON and the popular Jason library.

  ## Library Selection Strategy

  1. Elixir 1.18+ built-in JSON - Preferred for maximum performance
  2. Jason - Fallback for compatibility with older Elixir versions

  ## Key Features

  - Automatic Detection: Intelligently selects the best available library
  - Performance Optimized: Leverages Elixir's native JSON for speed
  - Backward Compatible: Seamless fallback to Jason when needed
  - Configurable: Override selection via environment variables
  - Error Handling: Comprehensive error context and recovery
  - Type Safe: Full type specifications and validation

  ## Configuration Options

  Override automatic detection with environment variables:

      # Force Elixir built-in JSON (Elixir 1.18+)
      export VAULTX_JSON_LIBRARY="elixir"

      # Force Jason library
      export VAULTX_JSON_LIBRARY="jason"

  ## References

  - [Elixir JSON](https://hexdocs.pm/elixir/JSON.html) (Elixir 1.18+)
  - [Jason](https://hexdocs.pm/jason/) - High-performance JSON library

  ## Examples

      # Encoding
      {:ok, json} = Vaultx.Base.JSON.encode(%{"key" => "value"})
      json_string = Vaultx.Base.JSON.encode!(%{"key" => "value"})

      # Decoding
      {:ok, data} = Vaultx.Base.JSON.decode(~s({"key": "value"}))
      data = Vaultx.Base.JSON.decode!(~s({"key": "value"}))

      # Check current library
      library = Vaultx.Base.JSON.current_library()
      # Returns :elixir or :jason
  """

  alias Vaultx.Base.Error
  alias Vaultx.Types

  @type json_library :: :elixir | :jason
  @type encode_error :: Types.result(String.t())
  @type decode_error :: Types.result(term())

  @doc """
  Encodes a term to JSON string, raising on error.

  ## Examples

      iex> Vaultx.Base.JSON.encode!(%{"key" => "value"})
      ~s({"key":"value"})

      iex> Vaultx.Base.JSON.encode!({:invalid, :tuple})
       (Vaultx.Base.Error) JSON encoding failed

  """
  @spec encode!(term()) :: String.t()
  def encode!(term) do
    case encode(term) do
      {:ok, json} -> json
      {:error, error} -> raise error
    end
  end

  @doc """
  Safely encodes a term to JSON string.

  ## Examples

      iex> Vaultx.Base.JSON.encode(%{"key" => "value"})
      {:ok, ~s({"key":"value"})}

      iex> Vaultx.Base.JSON.encode({:invalid, :tuple})
      {:error, %Vaultx.Base.Error{type: :json_encode_error}}

  """
  @spec encode(term()) :: {:ok, String.t()} | encode_error()
  def encode(term) do
    try do
      json = json_library().encode!(term)
      {:ok, json}
    rescue
      error ->
        {:error,
         Error.new(:json_encode_error, "Failed to encode JSON",
           details: %{
             original_error: error,
             term: inspect(term, limit: 100),
             library: current_library()
           },
           recoverable: false
         )}
    end
  end

  @doc """
  Decodes a JSON string to term, raising on error.

  ## Examples

      iex> Vaultx.Base.JSON.decode!(~s({"key":"value"}))
      %{"key" => "value"}

      iex> Vaultx.Base.JSON.decode!("invalid json")
       (Vaultx.Base.Error) JSON decoding failed

  """
  @spec decode!(String.t()) :: term()
  def decode!(json) do
    case decode(json) do
      {:ok, term} -> term
      {:error, error} -> raise error
    end
  end

  @doc """
  Safely decodes a JSON string to term.

  ## Examples

      iex> Vaultx.Base.JSON.decode(~s({"key":"value"}))
      {:ok, %{"key" => "value"}}

      iex> Vaultx.Base.JSON.decode("invalid json")
      {:error, %Vaultx.Base.Error{type: :json_decode_error}}

  """
  @spec decode(String.t()) :: {:ok, term()} | decode_error()
  def decode(json) do
    try do
      term = json_library().decode!(json)
      {:ok, term}
    rescue
      error ->
        {:error,
         Error.new(:json_decode_error, "Failed to decode JSON",
           details: %{
             original_error: error,
             json: String.slice(json, 0, 200),
             library: current_library()
           },
           recoverable: false
         )}
    end
  end

  @doc """
  Returns the currently selected JSON library.

  ## Examples

      iex> Vaultx.Base.JSON.current_library()
      :elixir

  """
  @spec current_library() :: json_library()
  def current_library do
    case json_library() do
      JSON -> :elixir
      Jason -> :jason
    end
  end

  @doc """
  Checks if a specific JSON library is available.

  ## Examples

      iex> Vaultx.Base.JSON.library_available?(:elixir)
      true

      iex> Vaultx.Base.JSON.library_available?(:jason)
      true

  """
  @spec library_available?(json_library()) :: boolean()
  def library_available?(:elixir) do
    Code.ensure_loaded?(JSON)
  end

  def library_available?(:jason) do
    Code.ensure_loaded?(Jason)
  end

  @doc """
  Returns information about available JSON libraries.

  ## Examples

      iex> info = Vaultx.Base.JSON.library_info()
      iex> info.current
      :elixir

  """
  @spec library_info() :: %{
          current: json_library(),
          available: [json_library()],
          elixir_available: boolean(),
          jason_available: boolean()
        }
  def library_info do
    %{
      current: current_library(),
      available: available_libraries(),
      elixir_available: library_available?(:elixir),
      jason_available: library_available?(:jason)
    }
  end

  # Private functions

  defp json_library do
    case System.get_env("VAULTX_JSON_LIBRARY") do
      "elixir" -> JSON
      "jason" -> Jason
      _ -> detect_best_library()
    end
  end

  defp detect_best_library do
    cond do
      # coveralls-ignore-start
      library_available?(:elixir) ->
        JSON

      library_available?(:jason) ->
        Jason

      true ->
        raise_no_json_library_error()
        # coveralls-ignore-stop
    end
  end

  defp available_libraries do
    [:elixir, :jason]
    |> Enum.filter(&library_available?/1)
  end

  # coveralls-ignore-start
  defp raise_no_json_library_error do
    raise Error.new(
            :configuration_error,
            "No JSON library available. Please ensure either Elixir 1.18+ or Jason is available.",
            details: %{
              elixir_version: System.version(),
              jason_available: Code.ensure_loaded?(Jason)
            }
          )

    # coveralls-ignore-stop
  end
end
