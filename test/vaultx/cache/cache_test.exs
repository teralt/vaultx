defmodule Vaultx.CacheTest do
  use ExUnit.Case, async: false

  alias Vaultx.Cache

  # Manager and Metrics are both GenServers; Cache is merely a facade.
  # To avoid heavy dependencies, minimal testing verifies only the bypass behavior of get_or_compute's test mode
  # and that stats directly proxies Metrics' return structure.

  test "get_or_compute bypasses cache in test env" do
    val = Cache.get_or_compute("k", fn -> :computed end, ttl: 1000)
    assert val == :computed
  end

  test "stats returns {:ok, map} from Metrics" do
    pid = Process.whereis(Vaultx.Cache.Metrics)

    if not is_pid(pid) do
      {:ok, _pid} = Vaultx.Cache.Metrics.start_link()
    end

    assert {:ok, stats} = Cache.stats()
    assert is_map(stats)
  end
end
