defmodule Vaultx.Cache.Adapters.Behaviour do
  @moduledoc """
  Behaviour for L2 cache adapters.

  This behaviour defines the interface that all L2 cache adapters must implement.
  Adapters can be for Redis, Memcached, or any other distributed caching system.
  """

  @type adapter_state :: term()
  @type cache_key :: String.t()
  @type cache_value :: term()
  @type ttl :: pos_integer()

  @doc """
  Initialize the adapter with the given configuration.
  """
  @callback init(config :: map()) :: {:ok, adapter_state()} | {:error, term()}

  @doc """
  Get a value from the cache.
  """
  @callback get(cache_key(), adapter_state()) ::
              {:ok, cache_value()} | {:error, :not_found} | {:error, term()}

  @doc """
  Put a value into the cache with TTL.
  """
  @callback put(cache_key(), cache_value(), ttl(), adapter_state()) ::
              :ok | {:error, term()}

  @doc """
  Delete a value from the cache.
  """
  @callback delete(cache_key(), adapter_state()) :: :ok | {:error, term()}

  @doc """
  Clear cache entries matching a pattern.
  """
  @callback clear(:all | String.t(), adapter_state()) :: :ok | {:error, term()}

  @doc """
  Perform cleanup operations (remove expired entries, etc.).
  """
  @callback cleanup(adapter_state()) :: :ok | {:error, term()}

  @doc """
  Get adapter statistics.
  """
  @callback stats(adapter_state()) :: {:ok, map()} | {:error, term()}
end
