defmodule Vaultx.Transport.HTTPTest do
  use ExUnit.Case, async: true

  alias Vaultx.Transport.HTTP

  import Vaultx.Test.HTTPHelpers

  describe "HTTP methods" do
    test "get/2 makes successful GET request" do
      expect_get(200, %{"data" => %{"key" => "value"}})

      assert {:ok, response} = HTTP.get("secret/test")
      assert response.status == 200
      assert response.body["data"]["key"] == "value"
    end

    test "post/3 makes successful POST request" do
      expect_post(200, %{"data" => %{"version" => 1}})

      assert {:ok, response} = HTTP.post("secret/data/test", %{"data" => %{"key" => "value"}})
      assert response.status == 200
      assert response.body["data"]["version"] == 1
    end

    test "put/3 makes successful PUT request" do
      expect_put(200, %{"data" => %{"version" => 2}})

      assert {:ok, response} = HTTP.put("secret/data/test", %{"data" => %{"key" => "new_value"}})
      assert response.status == 200
      assert response.body["data"]["version"] == 2
    end

    test "delete/2 makes successful DELETE request" do
      expect_delete(204, %{})

      assert {:ok, response} = HTTP.delete("secret/data/test")
      assert response.status == 204
    end

    test "patch/3 makes successful PATCH request" do
      expect_patch(200, %{"data" => %{"version" => 3}})

      assert {:ok, response} = HTTP.patch("secret/data/test", %{"data" => %{"key" => "patched"}})
      assert response.status == 200
      assert response.body["data"]["version"] == 3
    end
  end

  describe "error handling" do
    test "handles HTTP 400 Bad Request" do
      expect_get(400, %{"errors" => ["invalid request"]})

      assert {:ok, response} = HTTP.get("invalid/path")
      assert response.status == 400
      assert response.body["errors"] == ["invalid request"]
    end

    test "handles HTTP 401 Unauthorized" do
      expect_get(401, %{"errors" => ["permission denied"]})

      assert {:ok, response} = HTTP.get("secret/test")
      assert response.status == 401
      assert response.body["errors"] == ["permission denied"]
    end

    test "handles HTTP 403 Forbidden" do
      expect_get(403, %{"errors" => ["insufficient permissions"]})

      assert {:ok, response} = HTTP.get("secret/test")
      assert response.status == 403
      assert response.body["errors"] == ["insufficient permissions"]
    end

    test "handles HTTP 404 Not Found" do
      expect_get(404, %{"errors" => ["path not found"]})

      assert {:ok, response} = HTTP.get("nonexistent/path")
      assert response.status == 404
      assert response.body["errors"] == ["path not found"]
    end

    test "handles HTTP 429 Rate Limited" do
      expect_get(429, %{"errors" => ["rate limit exceeded"]})

      assert {:ok, response} = HTTP.get("secret/test")
      assert response.status == 429
      assert response.body["errors"] == ["rate limit exceeded"]
    end

    test "handles HTTP 500 Server Error" do
      expect_get(500, %{"errors" => ["internal server error"]})

      assert {:ok, response} = HTTP.get("secret/test")
      assert response.status == 500
      assert response.body["errors"] == ["internal server error"]
    end

    test "handles network errors" do
      # Use stub to handle retry attempts
      stub_request(:get, :network_error, "Network error: timeout")

      assert {:error, error} = HTTP.get("secret/test")
      assert error.type == :network_error
    end
  end

  describe "coverage tests" do
    setup do
      # Store original values
      original_config = %{
        url: Application.get_env(:vaultx, :url),
        namespace: Application.get_env(:vaultx, :namespace),
        audit_enabled: Application.get_env(:vaultx, :audit_enabled),
        security_headers_enabled: Application.get_env(:vaultx, :security_headers_enabled),
        rate_limit_enabled: Application.get_env(:vaultx, :rate_limit_enabled),
        rate_limit_requests: Application.get_env(:vaultx, :rate_limit_requests),
        rate_limit_burst: Application.get_env(:vaultx, :rate_limit_burst),
        retry_attempts: Application.get_env(:vaultx, :retry_attempts),
        retry_delay: Application.get_env(:vaultx, :retry_delay),
        retry_backoff: Application.get_env(:vaultx, :retry_backoff)
      }

      on_exit(fn ->
        # Restore original values
        Enum.each(original_config, fn {key, value} ->
          if value,
            do: Application.put_env(:vaultx, key, value),
            else: Application.delete_env(:vaultx, key)
        end)
      end)

      :ok
    end

    test "covers audit, rate limiter, security headers, and namespace handling" do
      # Setup config for coverage paths
      Application.put_env(:vaultx, :url, "https://api.example.com")
      Application.put_env(:vaultx, :namespace, "ns1")
      Application.put_env(:vaultx, :audit_enabled, true)
      Application.put_env(:vaultx, :security_headers_enabled, true)
      Application.put_env(:vaultx, :rate_limit_enabled, true)
      # High rate for spacing = 1
      Application.put_env(:vaultx, :rate_limit_requests, 1000)
      Application.put_env(:vaultx, :rate_limit_burst, 0)

      # Ensure RateLimiter is started to cover the _pid -> do_consume branch
      unless Process.whereis(Vaultx.Base.RateLimiter) do
        {:ok, _pid} = Vaultx.Base.RateLimiter.start_link(rate: 1000, burst: 0)
      end

      # Success path with content-type header
      expect_get(200, %{}, fn url, _body, _opts ->
        assert String.contains?(url, "/v1/sys/health")
      end)

      assert {:ok, %{status: 200}} = HTTP.get("sys/health")

      # Error path for audit failure
      stub_request(:get, :network_error, "Network error")
      assert {:error, _} = HTTP.get("sys/health")
    end

    test "covers namespace header nil path" do
      Application.put_env(:vaultx, :namespace, nil)
      Application.put_env(:vaultx, :rate_limit_enabled, false)

      expect_get(200, %{})
      assert {:ok, _} = HTTP.get("sys/health")
    end

    test "covers retry backoff branches" do
      Application.put_env(:vaultx, :rate_limit_enabled, false)
      Application.put_env(:vaultx, :retry_attempts, 1)
      Application.put_env(:vaultx, :retry_delay, 1)

      # Linear backoff
      Application.put_env(:vaultx, :retry_backoff, :linear)
      stub_request(:get, :timeout, "timeout")
      assert {:error, _} = HTTP.get("sys/health")

      # Exponential backoff
      Application.put_env(:vaultx, :retry_backoff, :exponential)
      stub_request(:get, :timeout, "timeout")
      assert {:error, _} = HTTP.get("sys/health")
    end

    test "covers security header validation" do
      Application.put_env(:vaultx, :security_headers_enabled, true)
      Application.put_env(:vaultx, :rate_limit_enabled, false)

      # Response without content-type header triggers warning
      expect_get(200, %{})
      assert {:ok, _} = HTTP.get("sys/health")
    end
  end

  describe "options and configuration" do
    test "passes custom options to request" do
      expect_get(200, %{}, fn _url, _body, opts ->
        assert opts[:timeout] == 60_000
        assert opts[:retry_attempts] == 5
      end)

      assert {:ok, _response} = HTTP.get("secret/test", timeout: 60_000, retry_attempts: 5)
    end

    test "handles custom headers" do
      expect_get(200, %{})

      assert {:ok, _response} = HTTP.get("secret/test", headers: [{"X-Custom", "value"}])
    end

    test "handles token authentication" do
      expect_get(200, %{})

      assert {:ok, _response} = HTTP.get("secret/test", token: "hvs.test")
    end
  end

  describe "request/5 comprehensive" do
    test "makes request with all parameters" do
      expect_post(201, %{"created" => true})

      assert {:ok, response} =
               HTTP.request(:post, "test/path", %{"data" => "test"}, [{"X-Test", "value"}],
                 timeout: 30_000
               )

      assert response.status == 201
      assert response.body["created"] == true
    end

    test "handles binary body" do
      expect_post(200, %{"received" => "binary"}, fn _url, _raw, _opts -> :ok end, decode: false)

      binary_data = <<1, 2, 3, 4>>
      assert {:ok, response} = HTTP.request(:post, "test/binary", binary_data, [], [])
      assert response.status == 200
      assert response.body["received"] == "binary"
    end

    test "handles namespace header" do
      # Mock config with namespace
      original_config = Application.get_env(:vaultx, :namespace)
      Application.put_env(:vaultx, :namespace, "test-namespace")

      try do
        expect_get(200, %{})

        assert {:ok, _response} = HTTP.get("secret/test")
      after
        # Restore original config
        if original_config do
          Application.put_env(:vaultx, :namespace, original_config)
        else
          Application.delete_env(:vaultx, :namespace)
        end
      end
    end

    test "handles different HTTP methods in options" do
      # Test that method option is handled correctly
      expect_patch(200, %{}, fn _url, _body, opts ->
        assert opts[:method] == :patch
      end)

      assert {:ok, _response} = HTTP.request(:patch, "test/path", %{}, [], method: :patch)
    end

    test "handles request without retry" do
      # Test the else branch where retry_attempts is 0
      expect_get(200, %{"no_retry" => true})

      assert {:ok, response} = HTTP.get("secret/test", retry_attempts: 0)
      assert response.body["no_retry"] == true
    end

    test "handles request without token" do
      # Test the else branch where no token is provided
      # We need to temporarily clear the config token
      original_config = Application.get_env(:vaultx, :token)
      Application.delete_env(:vaultx, :token)

      try do
        expect_get(200, %{})

        assert {:ok, _response} = HTTP.get("secret/test")
      after
        # Restore original config
        if original_config do
          Application.put_env(:vaultx, :token, original_config)
        end
      end
    end
  end

  describe "URL building" do
    test "builds URL without query parameters" do
      # This test covers the empty query_params branch in build_url_with_query
      expect_get(200, %{"status" => "ok"}, fn url, _body, _opts ->
        # Should not contain query parameters
        refute String.contains?(url, "?")
        assert String.ends_with?(url, "/v1/sys/health")
      end)

      assert {:ok, response} = HTTP.get("sys/health")
      assert response.status == 200
    end

    test "builds URL with query parameters" do
      expect_get(200, %{"status" => "ok"}, fn url, _body, _opts ->
        # Should contain query parameters
        assert String.contains?(url, "?")
        assert String.contains?(url, "standbyok=true")
      end)

      # Use a path with query parameters to test the build_url_with_query function
      assert {:ok, response} = HTTP.get("sys/health?standbyok=true")
      assert response.status == 200
    end
  end
end
