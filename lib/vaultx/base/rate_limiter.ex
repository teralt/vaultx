defmodule Vaultx.Base.RateLimiter do
  @moduledoc """
  Token-bucket rate limiter for Vaultx HTTP requests with optional multi-bucket support.

  - Each bucket has capacity = rate + burst
  - Tokens refill at `rate` per second
  - consume blocks (sleep) until a token is available

  Agent state keeps multiple buckets, keyed by an identifier (e.g., host|namespace).
  If not started (feature disabled), calls become no-ops.
  """

  use Agent

  @type bucket :: %{
          rate: pos_integer(),
          burst: non_neg_integer(),
          capacity: pos_integer(),
          tokens: float(),
          last_refill: integer()
        }

  @type state :: %{
          buckets: %{optional(String.t()) => bucket},
          default_rate: pos_integer(),
          default_burst: non_neg_integer()
        }

  def start_link(opts) do
    default_rate = Keyword.fetch!(opts, :rate)
    default_burst = Keyword.get(opts, :burst, 0)

    Agent.start_link(
      fn ->
        %{
          buckets: %{},
          default_rate: default_rate,
          default_burst: default_burst
        }
      end,
      name: __MODULE__
    )
  end

  @doc """
  Consume 1 token from the default bucket ("default").
  """
  def consume, do: consume("default")

  @doc """
  Consume 1 token from a named bucket. Uses default rate/burst configured at start.
  """
  def consume(bucket_key) when is_binary(bucket_key) do
    case Process.whereis(__MODULE__) do
      nil -> :ok
      _pid -> do_consume(bucket_key, nil, nil)
    end
  end

  @doc """
  Consume 1 token from a named bucket with explicit rate and burst.
  Useful when per-request opts specify rate/burst.
  """
  def consume(bucket_key, rate, burst) when is_binary(bucket_key) do
    case Process.whereis(__MODULE__) do
      nil -> :ok
      _pid -> do_consume(bucket_key, rate, burst)
    end
  end

  defp ensure_bucket(%{buckets: buckets} = state, key, rate, burst) do
    case Map.fetch(buckets, key) do
      {:ok, b} ->
        {state, b}

      :error ->
        r = rate || state.default_rate
        b = burst || state.default_burst
        now = System.monotonic_time(:millisecond)
        bucket = %{rate: r, burst: b, capacity: r + b, tokens: r + b, last_refill: now}
        {put_in(state.buckets[key], bucket), bucket}
    end
  end

  defp do_consume(bucket_key, rate, burst) do
    need_sleep_ms =
      Agent.get_and_update(__MODULE__, fn state ->
        {state, bucket} = ensure_bucket(state, bucket_key, rate, burst)

        now = System.monotonic_time(:millisecond)
        elapsed_ms = max(now - bucket.last_refill, 0)
        refilled = bucket.tokens + bucket.rate * (elapsed_ms / 1000)
        tokens = min(refilled, bucket.capacity)

        if tokens >= 1 do
          {0, put_in(state.buckets[bucket_key], %{bucket | tokens: tokens - 1, last_refill: now})}
        else
          # compute time to wait to have 1 token
          missing = 1 - tokens
          wait_s = missing / bucket.rate
          wait_ms = max(round(wait_s * 1000), 1)

          {wait_ms,
           put_in(state.buckets[bucket_key], %{bucket | tokens: tokens, last_refill: now})}
        end
      end)

    if need_sleep_ms > 0 do
      Process.sleep(need_sleep_ms)
      do_consume(bucket_key, rate, burst)
    else
      :ok
    end
  end

  @doc false
  def get_buckets do
    case Process.whereis(__MODULE__) do
      nil -> []
      _pid -> Agent.get(__MODULE__, fn state -> Map.keys(state.buckets) end)
    end
  end
end
