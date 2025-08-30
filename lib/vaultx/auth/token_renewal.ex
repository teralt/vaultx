defmodule Vaultx.Auth.TokenRenewal do
  @moduledoc """
  Background token renewal worker.

  Periodically checks the current client token TTL and renews it when the
  remaining TTL percentage drops below the configured threshold.

  This worker is started conditionally by the application when:
  - token_renewal_enabled is true
  - a token is configured
  - and we are not running in the test environment

  It uses Vaultx.Auth.Token.lookup_self/1 and renew_token/2 which already emit
  Telemetry and Audit events, so this worker only orchestrates timing.
  """

  use GenServer

  alias Vaultx.Auth.Token
  alias Vaultx.Base.{Config, Logger}

  @default_interval_ms 30_000

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(opts) do
    state = %{
      interval_ms: Keyword.get(opts, :interval_ms, @default_interval_ms),
      threshold: Config.get_token_renewal_threshold(),
      token_module: Keyword.get(opts, :token_module, Token),
      initial_creation_ttl: nil
    }

    schedule_tick(state.interval_ms)
    {:ok, state}
  end

  @impl true
  def handle_info(:tick, state) do
    new_state = do_check_and_renew(state)
    {:noreply, new_state}
  end

  # Internal
  defp schedule_tick(ms), do: Process.send_after(self(), :tick, ms)

  defp do_check_and_renew(state) do
    case state.token_module.lookup_self(timeout: Config.get_timeout()) do
      {:ok, token_info} ->
        ttl = Map.get(token_info, :ttl) || 0
        renewable? = Map.get(token_info, :renewable) == true

        observed_creation_ttl =
          Map.get(token_info, :creation_ttl) || Map.get(token_info, :initial_ttl)

        creation_ttl = state.initial_creation_ttl || observed_creation_ttl

        # update cached initial_creation_ttl if first seen
        state =
          if (is_nil(state.initial_creation_ttl) and creation_ttl) && creation_ttl > 0,
            do: %{state | initial_creation_ttl: creation_ttl},
            else: state

        if renewable? and ttl > 0 do
          threshold = state.threshold

          renew_now? =
            if creation_ttl && creation_ttl > 0 do
              percent_left = ttl * 100 / creation_ttl
              percent_left <= 100 - threshold
            else
              # fallback heuristic without creation ttl
              ttl_percentage_below_threshold?(ttl, threshold)
            end

          if renew_now? do
            Logger.info("Token TTL below threshold; renewing token", %{
              ttl: ttl,
              creation_ttl: creation_ttl,
              threshold: threshold
            })

            _ = state.token_module.renew_token(nil)
          end
        end

        # adaptive scheduling: next tick based on TTL and threshold
        next_ms =
          if ttl > 0 do
            # schedule at half of the safe window to re-check
            safe_window_ms =
              if creation_ttl && creation_ttl > 0 do
                trunc(creation_ttl * (100 - state.threshold) / 100)
              else
                @default_interval_ms * max(1, div(100 - state.threshold, 10))
              end

            min(max(div(safe_window_ms, 2), 5_000), 60_000)
          else
            @default_interval_ms
          end

        schedule_tick(next_ms)
        state

      {:error, error} ->
        # Swallow errors, log debug to avoid noise; try again later
        Logger.debug("Token lookup failed in renewal worker", %{error: error})
        schedule_tick(@default_interval_ms)
        state
    end
  end

  # Approximate percentage check using a time window based on interval
  defp ttl_percentage_below_threshold?(ttl_ms, threshold) when is_integer(ttl_ms) do
    # If ttl less than interval * (100-threshold)/100 we renew
    window_ms = @default_interval_ms * max(1, div(100 - threshold, 10))
    ttl_ms <= window_ms
  end
end
