defmodule Vaultx.Cache.Adapters do
  @moduledoc """
  Cache adapters for L2 distributed caching.

  This module provides a unified interface for different L2 cache adapters.
  Currently supported adapters:

  - `Memory` - In-memory ETS-based adapter (default, no external dependencies)
  - `Redis` - Redis-based distributed cache (requires Redis connection)
  - `Memcached` - Memcached-based cache (requires Memcached connection)

  ## Usage

      # Use default memory adapter
      config :vaultx, :cache,
        l2_adapter: Vaultx.Cache.Adapters.Memory

      # Use Redis adapter (requires additional setup)
      config :vaultx, :cache,
        l2_adapter: Vaultx.Cache.Adapters.Redis,
        l2_connection: [
          host: "localhost",
          port: 6379,
          database: 0
        ]

  ## Creating Custom Adapters

  To create a custom adapter, implement the `Vaultx.Cache.Adapters.Behaviour`:

      defmodule MyApp.CustomCacheAdapter do
        @behaviour Vaultx.Cache.Adapters.Behaviour

        @impl true
        def init(config) do
          # Initialize your adapter
          {:ok, adapter_state}
        end

        @impl true
        def get(key, state) do
          # Implement get logic
        end

        # ... implement other callbacks
      end

  """

  alias Vaultx.Cache.Adapters.Memory

  @doc """
  Get the default adapter.
  """
  def default_adapter, do: Memory

  @doc """
  List all available adapters.
  """
  def available_adapters do
    [
      %{
        module: Memory,
        name: "Memory",
        description: "In-memory ETS-based cache",
        dependencies: [],
        distributed: false
      }
      # Add more adapters here as they're implemented
      # %{
      #   module: Redis,
      #   name: "Redis",
      #   description: "Redis-based distributed cache",
      #   dependencies: [:redix],
      #   distributed: true
      # }
    ]
  end

  @doc """
  Validate adapter configuration.
  """
  def validate_adapter_config(adapter_module, config) do
    case adapter_module do
      Memory ->
        validate_memory_config(config)

      _ ->
        # For unknown adapters, assume they handle their own validation
        :ok
    end
  end

  defp validate_memory_config(config) do
    max_size = Map.get(config, :l2_max_size, 50_000)

    cond do
      not is_integer(max_size) ->
        {:error, "l2_max_size must be an integer"}

      max_size <= 0 ->
        {:error, "l2_max_size must be positive"}

      max_size > 1_000_000 ->
        {:warn, "l2_max_size is very large (#{max_size}), consider using a distributed adapter"}

      true ->
        :ok
    end
  end
end
