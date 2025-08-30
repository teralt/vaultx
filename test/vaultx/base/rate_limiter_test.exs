defmodule Vaultx.Base.RateLimiterTest do
  use ExUnit.Case, async: false

  test "consumes tokens and blocks when exhausted" do
    # Stop existing process if running
    case Process.whereis(Vaultx.Base.RateLimiter) do
      nil -> :ok
      pid -> GenServer.stop(pid)
    end

    {:ok, _pid} = Vaultx.Base.RateLimiter.start_link(rate: 5, burst: 0)

    t0 = System.monotonic_time(:millisecond)
    # 5 immediate tokens in default bucket
    for _ <- 1..5, do: Vaultx.Base.RateLimiter.consume()

    # Next one should block about 200ms (approx)
    Vaultx.Base.RateLimiter.consume()
    t1 = System.monotonic_time(:millisecond)

    assert t1 - t0 >= 150

    # Different bucket is independent and should not block initially
    t2 = System.monotonic_time(:millisecond)
    for _ <- 1..5, do: Vaultx.Base.RateLimiter.consume("ns:dev")
    Vaultx.Base.RateLimiter.consume("ns:dev")
    t3 = System.monotonic_time(:millisecond)

    assert t3 - t2 >= 150
  end

  test "multi-bucket stores independent keys" do
    # Stop existing process if running
    case Process.whereis(Vaultx.Base.RateLimiter) do
      nil -> :ok
      pid -> GenServer.stop(pid)
    end

    {:ok, _pid} = Vaultx.Base.RateLimiter.start_link(rate: 1, burst: 0)
    :ok = Vaultx.Base.RateLimiter.consume("a|ns1")
    :ok = Vaultx.Base.RateLimiter.consume("b|ns2")

    keys = Vaultx.Base.RateLimiter.get_buckets()
    assert "a|ns1" in keys
    assert "b|ns2" in keys
  end

  test "handles calls when rate limiter not started" do
    # Ensure no rate limiter is running
    if pid = Process.whereis(Vaultx.Base.RateLimiter) do
      GenServer.stop(pid)
    end

    # Should return :ok without error when not started
    assert :ok = Vaultx.Base.RateLimiter.consume()
    assert :ok = Vaultx.Base.RateLimiter.consume("bucket")
    assert :ok = Vaultx.Base.RateLimiter.consume("bucket", 10, 5)
    assert [] = Vaultx.Base.RateLimiter.get_buckets()
  end

  test "reuses existing bucket" do
    # Stop existing process if running
    case Process.whereis(Vaultx.Base.RateLimiter) do
      nil -> :ok
      pid -> GenServer.stop(pid)
    end

    {:ok, _pid} = Vaultx.Base.RateLimiter.start_link(rate: 10, burst: 0)

    # First consume creates bucket
    :ok = Vaultx.Base.RateLimiter.consume("reuse_bucket")

    # Second consume reuses existing bucket (covers {:ok, b} branch in ensure_bucket)
    :ok = Vaultx.Base.RateLimiter.consume("reuse_bucket")

    keys = Vaultx.Base.RateLimiter.get_buckets()
    assert "reuse_bucket" in keys
  end
end
