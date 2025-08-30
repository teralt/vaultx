defmodule Vaultx.Sys.Policies.PasswordTest do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Sys.Policies.Password
  alias Vaultx.Base.Error

  # Sample password policy list response from Vault
  @password_policy_list_response %{
    "data" => %{
      "keys" => ["my-policy", "strong-policy", "basic-policy"]
    }
  }

  # Alternative response format (direct keys)
  @password_policy_list_response_alt %{
    "keys" => ["my-policy", "strong-policy", "basic-policy"]
  }

  # Sample password policy read response from Vault
  @password_policy_read_response %{
    "policy" => ~s(length = 20
rule "charset" {
  charset = "abcdefghijklmnopqrstuvwxyz"
  min-chars = 1
}
rule "charset" {
  charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  min-chars = 1
}
rule "charset" {
  charset = "0123456789"
  min-chars = 1
})
  }

  # Sample password generation response from Vault
  @password_generation_response %{
    "password" => "Kj8mN2pQ9rT5vW3xY7zA"
  }

  # Sample password policy rules
  @password_policy_rules ~s(length = 20
rule "charset" {
  charset = "abcdefghijklmnopqrstuvwxyz"
  min-chars = 1
}
rule "charset" {
  charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  min-chars = 1
}
rule "charset" {
  charset = "0123456789"
  min-chars = 1
})

  describe "write/3" do
    test "creates password policy successfully" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/policies/password/new-policy")
        assert body["policy"] == @password_policy_rules
      end)

      assert :ok = Password.write("new-policy", @password_policy_rules)
    end

    test "updates existing password policy successfully" do
      expect_post(200, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/policies/password/existing-policy")
        assert body["policy"] == @password_policy_rules
      end)

      assert :ok = Password.write("existing-policy", @password_policy_rules)
    end

    test "wraps network errors for password policy write" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{type: :unknown_error}} =
               Password.write("test-policy", @password_policy_rules)
    end

    test "handles Vault validation errors" do
      expect_post(400, %{"errors" => ["invalid policy syntax"]})

      assert {:error, %Error{type: :invalid_request}} =
               Password.write("invalid-policy", "invalid syntax")
    end
  end

  describe "list/1" do
    test "returns password policy list successfully with data wrapper" do
      expect_any(:list, 200, @password_policy_list_response, fn url, _body, _opts ->
        assert String.contains?(url, "sys/policies/password")
        refute String.contains?(url, "sys/policies/password/")
      end)

      assert {:ok, policies} = Password.list()
      assert policies == ["my-policy", "strong-policy", "basic-policy"]
    end

    test "returns password policy list successfully with direct keys" do
      expect_any(:list, 200, @password_policy_list_response_alt, fn url, _body, _opts ->
        assert String.contains?(url, "sys/policies/password")
        refute String.contains?(url, "sys/policies/password/")
      end)

      assert {:ok, policies} = Password.list()
      assert policies == ["my-policy", "strong-policy", "basic-policy"]
    end

    test "handles empty password policy list with data wrapper" do
      expect_any(:list, 200, %{"data" => %{"keys" => []}})

      assert {:ok, policies} = Password.list()
      assert policies == []
    end

    test "handles empty password policy list with direct keys" do
      expect_any(:list, 200, %{"keys" => []})

      assert {:ok, policies} = Password.list()
      assert policies == []
    end

    test "wraps network errors for password policy list" do
      stub_request_raw(:list, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{type: :unknown_error}} = Password.list()
    end
  end

  describe "read/2" do
    test "returns password policy successfully" do
      expect_get(200, @password_policy_read_response, fn url, _body, _opts ->
        assert String.contains?(url, "sys/policies/password/my-policy")
      end)

      assert {:ok, policy_info} = Password.read("my-policy")
      assert String.contains?(policy_info.policy, "length = 20")
      assert String.contains?(policy_info.policy, "charset")
      assert String.contains?(policy_info.policy, "abcdefghijklmnopqrstuvwxyz")
    end

    test "returns error for non-existent password policy" do
      expect_get(404, %{"errors" => ["policy not found"]})

      assert {:error, %Error{type: :not_found}} = Password.read("non-existent")
    end

    test "wraps network errors for password policy read" do
      stub_request_raw(:get, %Req.TransportError{reason: :econnrefused})

      assert {:error, %Error{type: :unknown_error}} = Password.read("my-policy")
    end
  end

  describe "delete/2" do
    test "deletes password policy successfully" do
      expect_delete(204, %{}, fn url, _body, _opts ->
        assert String.contains?(url, "sys/policies/password/old-policy")
      end)

      assert :ok = Password.delete("old-policy")
    end

    test "returns success for 200 status" do
      expect_delete(200, %{}, fn url, _body, _opts ->
        assert String.contains?(url, "sys/policies/password/old-policy")
      end)

      assert :ok = Password.delete("old-policy")
    end

    test "returns error for non-existent password policy deletion" do
      expect_delete(404, %{"errors" => ["policy not found"]})

      assert {:error, %Error{type: :not_found}} = Password.delete("non-existent")
    end

    test "wraps network errors for password policy delete" do
      stub_request_raw(:delete, %Req.TransportError{reason: :econnrefused})

      assert {:error, %Error{type: :unknown_error}} = Password.delete("test-policy")
    end
  end

  describe "generate/2" do
    test "generates password from policy successfully" do
      expect_get(200, @password_generation_response, fn url, _body, _opts ->
        assert String.contains?(url, "sys/policies/password/my-policy/generate")
      end)

      assert {:ok, result} = Password.generate("my-policy")
      assert result.password == "Kj8mN2pQ9rT5vW3xY7zA"
    end

    test "returns error for non-existent password policy generation" do
      expect_get(404, %{"errors" => ["policy not found"]})

      assert {:error, %Error{type: :not_found}} = Password.generate("non-existent")
    end

    test "wraps network errors for password generation" do
      stub_request_raw(:get, %Req.TransportError{reason: :econnrefused})

      assert {:error, %Error{type: :unknown_error}} = Password.generate("my-policy")
    end

    test "handles policy generation errors" do
      expect_get(400, %{"errors" => ["policy cannot generate valid passwords"]})

      assert {:error, %Error{type: :invalid_request}} = Password.generate("problematic-policy")
    end
  end

  describe "integration scenarios" do
    test "complete password policy lifecycle" do
      policy_name = "lifecycle-test-policy"

      # Create policy
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/policies/password/#{policy_name}")
        assert body["policy"] == @password_policy_rules
      end)

      assert :ok = Password.write(policy_name, @password_policy_rules)

      # List policies (should include our new policy)
      list_response = %{"keys" => [policy_name, "other-policy"]}
      expect_any(:list, 200, list_response)

      assert {:ok, policies} = Password.list()
      assert policy_name in policies

      # Read policy
      expect_get(200, @password_policy_read_response, fn url, _body, _opts ->
        assert String.contains?(url, "sys/policies/password/#{policy_name}")
      end)

      assert {:ok, policy_info} = Password.read(policy_name)
      assert String.contains?(policy_info.policy, "length = 20")

      # Generate password
      expect_get(200, @password_generation_response, fn url, _body, _opts ->
        assert String.contains?(url, "sys/policies/password/#{policy_name}/generate")
      end)

      assert {:ok, result} = Password.generate(policy_name)
      assert is_binary(result.password)
      assert String.length(result.password) > 0

      # Delete policy
      expect_delete(204, %{}, fn url, _body, _opts ->
        assert String.contains?(url, "sys/policies/password/#{policy_name}")
      end)

      assert :ok = Password.delete(policy_name)
    end

    test "handles various policy formats" do
      simple_policy = "length = 12"
      complex_policy = ~s(length = 24
rule "charset" {
  charset = "abcdefghijklmnopqrstuvwxyz"
  min-chars = 5
}
rule "charset" {
  charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  min-chars = 5
}
rule "charset" {
  charset = "0123456789"
  min-chars = 3
}
rule "charset" {
  charset = "!@#$%^&*"
  min-chars = 2
})

      # Test simple policy
      expect_post(204, %{}, fn _url, body, _opts ->
        assert body["policy"] == simple_policy
      end)

      assert :ok = Password.write("simple-policy", simple_policy)

      # Test complex policy
      expect_post(204, %{}, fn _url, body, _opts ->
        assert body["policy"] == complex_policy
      end)

      assert :ok = Password.write("complex-policy", complex_policy)
    end
  end
end
