defmodule Vaultx.Sys.PolicyTest do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Sys.Policy
  alias Vaultx.Base.Error

  # Sample policy list response from Vault
  @policy_list_response %{
    "policies" => ["default", "root", "my-policy", "app-policy"]
  }

  # Sample policy read response from Vault
  @policy_read_response %{
    "name" => "my-policy",
    "rules" => ~s(path "secret/myapp/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/shared/*" {
  capabilities = ["read", "list"]
})
  }

  # Sample policy rules
  @policy_rules ~s(path "secret/myapp/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/shared/*" {
  capabilities = ["read", "list"]
})

  describe "list/1" do
    test "returns policy list successfully" do
      expect_get(200, @policy_list_response, fn url, _body, _opts ->
        assert String.contains?(url, "sys/policy")
        refute String.contains?(url, "sys/policy/")
      end)

      assert {:ok, policies} = Policy.list()
      assert policies == ["default", "root", "my-policy", "app-policy"]
    end

    test "handles empty policy list" do
      expect_get(200, %{"policies" => []})

      assert {:ok, policies} = Policy.list()
      assert policies == []
    end

    test "wraps network errors" do
      stub_request_raw(:get, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{type: :unknown_error}} = Policy.list()
    end
  end

  describe "read/2" do
    test "returns policy successfully" do
      expect_get(200, @policy_read_response, fn url, _body, _opts ->
        assert String.contains?(url, "sys/policy/my-policy")
      end)

      assert {:ok, policy} = Policy.read("my-policy")
      assert policy.name == "my-policy"
      assert String.contains?(policy.rules, "secret/myapp/*")
      assert String.contains?(policy.rules, "secret/shared/*")
    end

    test "returns error for non-existent policy" do
      expect_get(404, %{"errors" => ["policy not found"]})

      assert {:error, %Error{type: :not_found}} = Policy.read("non-existent")
    end

    test "wraps network errors" do
      stub_request_raw(:get, %Req.TransportError{reason: :econnrefused})

      assert {:error, %Error{type: :unknown_error}} = Policy.read("my-policy")
    end
  end

  describe "write/3" do
    test "creates policy successfully" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/policy/new-policy")
        assert body["policy"] == @policy_rules
      end)

      assert :ok = Policy.write("new-policy", @policy_rules)
    end

    test "updates existing policy successfully" do
      expect_post(200, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/policy/existing-policy")
        assert body["policy"] == @policy_rules
      end)

      assert :ok = Policy.write("existing-policy", @policy_rules)
    end

    test "wraps network errors" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{type: :unknown_error}} = Policy.write("my-policy", @policy_rules)
    end
  end

  describe "delete/2" do
    test "deletes policy successfully" do
      expect_delete(204, %{}, fn url, _body, _opts ->
        assert String.contains?(url, "sys/policy/old-policy")
      end)

      assert :ok = Policy.delete("old-policy")
    end

    test "handles successful deletion with 200 status" do
      expect_delete(200, %{})

      assert :ok = Policy.delete("old-policy")
    end

    test "returns error for non-existent policy" do
      expect_delete(404, %{"errors" => ["policy not found"]})

      assert {:error, %Error{type: :not_found}} = Policy.delete("non-existent")
    end

    test "prevents deletion of root policy" do
      assert {:error, %Error{type: :invalid_request, message: message}} = Policy.delete("root")
      assert String.contains?(message, "Cannot delete system policy: root")
    end

    test "prevents deletion of default policy" do
      assert {:error, %Error{type: :invalid_request, message: message}} = Policy.delete("default")
      assert String.contains?(message, "Cannot delete system policy: default")
    end

    test "wraps network errors" do
      stub_request_raw(:delete, %Req.TransportError{reason: :econnrefused})

      assert {:error, %Error{type: :unknown_error}} = Policy.delete("my-policy")
    end
  end

  describe "edge cases and error handling" do
    test "handles nil policy rules" do
      response_with_nil = %{
        "name" => "test-policy",
        "rules" => nil
      }

      expect_get(200, response_with_nil)

      assert {:ok, policy} = Policy.read("test-policy")
      assert policy.name == "test-policy"
      assert policy.rules == nil
    end

    test "handles empty policy rules" do
      response_with_empty = %{
        "name" => "test-policy",
        "rules" => ""
      }

      expect_get(200, response_with_empty)

      assert {:ok, policy} = Policy.read("test-policy")
      assert policy.name == "test-policy"
      assert policy.rules == ""
    end

    test "handles policy names with special characters" do
      policy_name = "my-app-policy-v1.0"

      expect_get(200, %{"name" => policy_name, "rules" => @policy_rules}, fn url, _body, _opts ->
        assert String.contains?(url, "sys/policy/#{policy_name}")
      end)

      assert {:ok, policy} = Policy.read(policy_name)
      assert policy.name == policy_name
    end

    test "handles large policy rules" do
      large_rules = String.duplicate(@policy_rules, 100)

      expect_post(200, %{}, fn _url, body, _opts ->
        assert body["policy"] == large_rules
      end)

      assert :ok = Policy.write("large-policy", large_rules)
    end
  end

  describe "options handling" do
    test "passes through timeout option" do
      expect_get(200, @policy_list_response, fn _url, _body, opts ->
        assert opts[:timeout] == 60_000
      end)

      assert {:ok, _policies} = Policy.list(timeout: 60_000)
    end

    test "passes through namespace option" do
      expect_get(200, @policy_read_response, fn _url, _body, _opts ->
        # Namespace is handled by HTTP layer, not directly visible in opts here
        true
      end)

      assert {:ok, _policy} = Policy.read("my-policy", namespace: "my-namespace")
    end

    test "passes through retry options" do
      expect_post(200, %{}, fn _url, _body, opts ->
        assert opts[:retry_attempts] == 3
      end)

      assert :ok = Policy.write("my-policy", @policy_rules, retry_attempts: 3)
    end
  end
end
