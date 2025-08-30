defmodule Vaultx.Auth.TokenRenewalTest do
  use ExUnit.Case, async: true

  defmodule StubToken do
    def lookup_self(_opts), do: {:ok, %{ttl: 10, renewable: true}}

    def renew_token(_arg) do
      if pid = Application.get_env(:vaultx, :test_pid) do
        send(pid, :renew_called)
      end

      {:ok, %{}}
    end
  end

  defmodule StubTokenWithCreationTTL do
    def lookup_self(_opts), do: {:ok, %{ttl: 10, renewable: true, creation_ttl: 100}}

    def renew_token(_arg) do
      if pid = Application.get_env(:vaultx, :test_pid) do
        send(pid, :renew_called)
      end

      {:ok, %{}}
    end
  end

  defmodule StubTokenError do
    def lookup_self(_opts), do: {:error, :network_error}
    def renew_token(_arg), do: {:ok, %{}}
  end

  defmodule StubTokenZeroTTL do
    def lookup_self(_opts), do: {:ok, %{ttl: 0, renewable: true}}
    def renew_token(_arg), do: {:ok, %{}}
  end

  test "renews when ttl below threshold" do
    Application.put_env(:vaultx, :test_pid, self())

    {:ok, pid} = Vaultx.Auth.TokenRenewal.start_link(interval_ms: 10, token_module: StubToken)

    assert_receive :renew_called, 200

    GenServer.stop(pid)
    Application.delete_env(:vaultx, :test_pid)
  end

  test "caches initial creation_ttl and uses percentage calculation" do
    Application.put_env(:vaultx, :test_pid, self())

    {:ok, pid} =
      Vaultx.Auth.TokenRenewal.start_link(interval_ms: 10, token_module: StubTokenWithCreationTTL)

    assert_receive :renew_called, 200

    GenServer.stop(pid)
    Application.delete_env(:vaultx, :test_pid)
  end

  test "handles lookup errors gracefully" do
    {:ok, pid} =
      Vaultx.Auth.TokenRenewal.start_link(interval_ms: 10, token_module: StubTokenError)

    # Should not crash, just log debug and continue
    Process.sleep(50)
    assert Process.alive?(pid)

    GenServer.stop(pid)
  end

  test "handles zero ttl case" do
    {:ok, pid} =
      Vaultx.Auth.TokenRenewal.start_link(interval_ms: 10, token_module: StubTokenZeroTTL)

    # Should not crash with zero TTL
    Process.sleep(50)
    assert Process.alive?(pid)

    GenServer.stop(pid)
  end
end
