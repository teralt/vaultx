defmodule Vaultx.Sys.SealTest do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Sys.Seal
  alias Vaultx.Base.Error

  describe "seal/1" do
    test "seals vault successfully with 204 response" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/seal")
        assert body == %{}
      end)

      assert {:ok, response} = Seal.seal()
      assert response.status == 204
    end

    test "seals vault successfully with 200 response" do
      expect_post(200, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/seal")
        assert body == %{}
      end)

      assert {:ok, response} = Seal.seal()
      assert response.status == 200
    end

    test "handles seal errors" do
      expect_post(403, %{"errors" => ["permission denied"]})

      assert {:error, %Error{} = error} = Seal.seal()
      assert error.type == :server_error
      assert String.contains?(error.message, "Failed to seal Vault")
    end

    test "handles network errors" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{} = error} = Seal.seal()
      assert error.type == :unknown_error
    end

    test "passes custom options" do
      expect_post(204, %{}, fn _url, _body, opts ->
        assert opts[:timeout] == 30_000
      end)

      assert {:ok, _response} = Seal.seal(timeout: 30_000)
    end
  end

  describe "check_seal_permission/1" do
    test "confirms seal permission with root capability" do
      expect_post(200, %{"capabilities" => ["root"]}, fn url, body, _opts ->
        assert String.contains?(url, "sys/capabilities-self")
        assert body["path"] == "sys/seal"
      end)

      assert :ok = Seal.check_seal_permission()
    end

    test "confirms seal permission with sudo capability" do
      expect_post(200, %{"capabilities" => ["sudo"]}, fn url, body, _opts ->
        assert String.contains?(url, "sys/capabilities-self")
        assert body["path"] == "sys/seal"
      end)

      assert :ok = Seal.check_seal_permission()
    end

    test "confirms seal permission with both root and sudo" do
      expect_post(200, %{"capabilities" => ["root", "sudo", "read"]}, fn url, body, _opts ->
        assert String.contains?(url, "sys/capabilities-self")
        assert body["path"] == "sys/seal"
      end)

      assert :ok = Seal.check_seal_permission()
    end

    test "denies seal permission with insufficient capabilities" do
      expect_post(200, %{"capabilities" => ["read", "list"]}, fn _url, _body, _opts ->
        :ok
      end)

      assert {:error, %Error{} = error} = Seal.check_seal_permission()
      assert error.type == :permission_denied
      assert String.contains?(error.message, "Insufficient permissions")
    end

    test "handles capabilities check errors" do
      expect_post(500, %{"errors" => ["internal server error"]})

      assert {:error, %Error{} = error} = Seal.check_seal_permission()
      assert error.type == :server_error
      assert String.contains?(error.message, "Failed to check seal permission")
    end

    test "handles network errors during permission check" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{} = error} = Seal.check_seal_permission()
      assert error.type == :unknown_error
    end

    test "handles malformed capabilities response" do
      expect_post(200, %{"invalid" => "response"})

      assert {:error, %Error{} = error} = Seal.check_seal_permission()
      assert error.type == :server_error
    end
  end

  describe "safe_seal/1" do
    test "performs safe seal with permission check" do
      # First call: check permissions
      expect_post(200, %{"capabilities" => ["root"]}, fn url, body, _opts ->
        assert String.contains?(url, "sys/capabilities-self")
        assert body["path"] == "sys/seal"
      end)

      # Second call: actual seal
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/seal")
        assert body == %{}
      end)

      assert {:ok, response} = Seal.safe_seal()
      assert response.status == 204
    end

    test "skips permission check when requested" do
      # Only expect the seal call, no permission check
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/seal")
        assert body == %{}
      end)

      assert {:ok, response} = Seal.safe_seal(skip_permission_check: true)
      assert response.status == 204
    end

    test "forces seal without any checks" do
      # Only expect the seal call, no permission check
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/seal")
        assert body == %{}
      end)

      assert {:ok, response} = Seal.safe_seal(force: true)
      assert response.status == 204
    end

    test "aborts on permission check failure" do
      # Only expect permission check, no seal call
      expect_post(200, %{"capabilities" => ["read"]}, fn url, body, _opts ->
        assert String.contains?(url, "sys/capabilities-self")
        assert body["path"] == "sys/seal"
      end)

      assert {:error, %Error{} = error} = Seal.safe_seal()
      assert error.type == :permission_denied
    end

    test "handles permission check network errors" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{} = error} = Seal.safe_seal()
      assert error.type == :unknown_error
    end

    test "handles seal failure after successful permission check" do
      # First call: successful permission check
      expect_post(200, %{"capabilities" => ["sudo"]}, fn url, _body, _opts ->
        assert String.contains?(url, "sys/capabilities-self")
      end)

      # Second call: seal failure
      expect_post(500, %{"errors" => ["internal error"]}, fn url, _body, _opts ->
        assert String.contains?(url, "sys/seal")
      end)

      assert {:error, %Error{} = error} = Seal.safe_seal()
      assert error.type == :server_error
      assert String.contains?(error.message, "Failed to seal Vault")
    end
  end

  describe "edge cases and error scenarios" do
    test "handles empty capabilities list" do
      expect_post(200, %{"capabilities" => []}, fn _url, _body, _opts ->
        :ok
      end)

      assert {:error, %Error{} = error} = Seal.check_seal_permission()
      assert error.type == :permission_denied
    end

    test "handles null capabilities" do
      expect_post(200, %{"capabilities" => nil}, fn _url, _body, _opts ->
        :ok
      end)

      assert {:error, %Error{} = error} = Seal.check_seal_permission()
      assert error.type == :server_error
    end

    test "handles missing capabilities field" do
      expect_post(200, %{}, fn _url, _body, _opts ->
        :ok
      end)

      assert {:error, %Error{} = error} = Seal.check_seal_permission()
      assert error.type == :server_error
    end

    test "handles various HTTP error codes for seal" do
      error_codes = [400, 401, 403, 404, 500, 502, 503]

      Enum.each(error_codes, fn code ->
        expect_post(code, %{"errors" => ["error #{code}"]})

        assert {:error, %Error{} = error} = Seal.seal()
        assert error.type == :server_error
        assert String.contains?(error.message, "HTTP #{code}")
      end)
    end

    test "handles malformed error responses" do
      expect_post(500, "invalid json")

      assert {:error, %Error{} = error} = Seal.seal()
      assert error.type == :server_error
    end
  end

  describe "integration scenarios" do
    test "complete safe seal workflow" do
      # Step 1: Check permission (success)
      expect_post(200, %{"capabilities" => ["root"]}, fn url, body, _opts ->
        assert String.contains?(url, "sys/capabilities-self")
        assert body["path"] == "sys/seal"
      end)

      # Step 2: Perform seal (success)
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/seal")
        assert body == %{}
      end)

      assert {:ok, response} = Seal.safe_seal()
      assert response.status == 204
    end

    test "permission denied workflow" do
      # Only permission check, should fail
      expect_post(200, %{"capabilities" => ["read", "list"]}, fn url, body, _opts ->
        assert String.contains?(url, "sys/capabilities-self")
        assert body["path"] == "sys/seal"
      end)

      assert {:error, %Error{} = error} = Seal.safe_seal()
      assert error.type == :permission_denied
      assert String.contains?(error.message, "Insufficient permissions")
    end

    test "force seal bypasses all checks" do
      # Should only call seal, no permission check
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/seal")
        assert body == %{}
      end)

      assert {:ok, response} = Seal.safe_seal(force: true)
      assert response.status == 204
    end

    test "custom options passed through all operations" do
      custom_opts = [timeout: 45_000]

      # Permission check with custom options
      expect_post(200, %{"capabilities" => ["sudo"]}, fn _url, _body, opts ->
        assert opts[:timeout] == 45_000
      end)

      # Seal with custom options
      expect_post(204, %{}, fn _url, _body, opts ->
        assert opts[:timeout] == 45_000
      end)

      assert {:ok, response} = Seal.safe_seal(custom_opts)
      assert response.status == 204
    end
  end
end
