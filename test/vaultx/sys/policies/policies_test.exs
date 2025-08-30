defmodule Vaultx.Sys.PoliciesTest do
  use ExUnit.Case, async: true
  import Vaultx.Test.HTTPHelpers

  alias Vaultx.Sys.Policies
  alias Vaultx.Base.Error

  # Sample ACL policy list response from Vault
  @acl_policy_list_response %{
    "keys" => ["default", "root", "my-policy", "app-policy"]
  }

  # Sample ACL policy read response from Vault
  @acl_policy_read_response %{
    "name" => "my-policy",
    "policy" => ~s(path "secret/myapp/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/shared/*" {
  capabilities = ["read", "list"]
})
  }

  # Sample RGP policy list response from Vault
  @rgp_policy_list_response %{
    "keys" => ["webapp", "database", "compliance"]
  }

  # Sample RGP policy read response from Vault
  @rgp_policy_read_response %{
    "name" => "webapp",
    "policy" => "rule main = { token.ttl <= 3600 and \"developers\" in token.groups }",
    "enforcement_level" => "soft-mandatory"
  }

  # Sample EGP policy list response from Vault
  @egp_policy_list_response %{
    "keys" => ["breakglass", "global-policy"]
  }

  # Sample EGP policy read response from Vault
  @egp_policy_read_response %{
    "name" => "breakglass",
    "policy" => "rule main = { request.operation in [\"create\", \"update\"] }",
    "enforcement_level" => "soft-mandatory",
    "paths" => ["*"]
  }

  # Sample policy rules
  @acl_policy_rules ~s(path "secret/myapp/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/shared/*" {
  capabilities = ["read", "list"]
})

  @rgp_policy_config %{
    policy: "rule main = { token.ttl <= 3600 and \"developers\" in token.groups }",
    enforcement_level: "soft-mandatory"
  }

  @egp_policy_config %{
    policy: "rule main = { request.operation in [\"create\", \"update\"] }",
    enforcement_level: "soft-mandatory",
    paths: ["*", "secret/*", "transit/keys/*"]
  }

  describe "list_acl/1" do
    test "returns ACL policy list successfully" do
      expect_any(:list, 200, @acl_policy_list_response, fn url, _body, _opts ->
        assert String.contains?(url, "sys/policies/acl")
        refute String.contains?(url, "sys/policies/acl/")
      end)

      assert {:ok, policies} = Policies.list_acl()
      assert policies == ["default", "root", "my-policy", "app-policy"]
    end

    test "handles empty ACL policy list" do
      expect_any(:list, 200, %{"keys" => []})

      assert {:ok, policies} = Policies.list_acl()
      assert policies == []
    end

    test "wraps network errors for ACL list" do
      stub_request_raw(:list, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{type: :unknown_error}} = Policies.list_acl()
    end
  end

  describe "read_acl/2" do
    test "returns ACL policy successfully" do
      expect_get(200, @acl_policy_read_response, fn url, _body, _opts ->
        assert String.contains?(url, "sys/policies/acl/my-policy")
      end)

      assert {:ok, policy} = Policies.read_acl("my-policy")
      assert policy.name == "my-policy"
      assert String.contains?(policy.policy, "secret/myapp/*")
      assert String.contains?(policy.policy, "secret/shared/*")
    end

    test "returns error for non-existent ACL policy" do
      expect_get(404, %{"errors" => ["policy not found"]})

      assert {:error, %Error{type: :not_found}} = Policies.read_acl("non-existent")
    end

    test "wraps network errors for ACL read" do
      stub_request_raw(:get, %Req.TransportError{reason: :econnrefused})

      assert {:error, %Error{type: :unknown_error}} = Policies.read_acl("my-policy")
    end
  end

  describe "write_acl/3" do
    test "creates ACL policy successfully" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/policies/acl/new-policy")
        assert body["policy"] == @acl_policy_rules
      end)

      assert :ok = Policies.write_acl("new-policy", @acl_policy_rules)
    end

    test "updates existing ACL policy successfully" do
      expect_post(200, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/policies/acl/existing-policy")
        assert body["policy"] == @acl_policy_rules
      end)

      assert :ok = Policies.write_acl("existing-policy", @acl_policy_rules)
    end

    test "wraps network errors for ACL write" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{type: :unknown_error}} =
               Policies.write_acl("test-policy", @acl_policy_rules)
    end
  end

  describe "delete_acl/2" do
    test "deletes ACL policy successfully" do
      expect_delete(204, %{}, fn url, _body, _opts ->
        assert String.contains?(url, "sys/policies/acl/old-policy")
      end)

      assert :ok = Policies.delete_acl("old-policy")
    end

    test "returns error for non-existent ACL policy deletion" do
      expect_delete(404, %{"errors" => ["policy not found"]})

      assert {:error, %Error{type: :not_found}} = Policies.delete_acl("non-existent")
    end

    test "prevents deletion of root policy" do
      assert {:error, %Error{type: :invalid_request}} = Policies.delete_acl("root")
    end

    test "prevents deletion of default policy" do
      assert {:error, %Error{type: :invalid_request}} = Policies.delete_acl("default")
    end

    test "wraps network errors for ACL delete" do
      stub_request_raw(:delete, %Req.TransportError{reason: :econnrefused})

      assert {:error, %Error{type: :unknown_error}} = Policies.delete_acl("test-policy")
    end
  end

  describe "list_rgp/1" do
    test "returns RGP policy list successfully" do
      expect_any(:list, 200, @rgp_policy_list_response, fn url, _body, _opts ->
        assert String.contains?(url, "sys/policies/rgp")
        refute String.contains?(url, "sys/policies/rgp/")
      end)

      assert {:ok, policies} = Policies.list_rgp()
      assert policies == ["webapp", "database", "compliance"]
    end

    test "handles empty RGP policy list" do
      expect_any(:list, 200, %{"keys" => []})

      assert {:ok, policies} = Policies.list_rgp()
      assert policies == []
    end

    test "wraps network errors for RGP list" do
      stub_request_raw(:list, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{type: :unknown_error}} = Policies.list_rgp()
    end
  end

  describe "read_rgp/2" do
    test "returns RGP policy successfully" do
      expect_get(200, @rgp_policy_read_response, fn url, _body, _opts ->
        assert String.contains?(url, "sys/policies/rgp/webapp")
      end)

      assert {:ok, policy} = Policies.read_rgp("webapp")
      assert policy.name == "webapp"
      assert String.contains?(policy.policy, "token.ttl <= 3600")
      assert policy.enforcement_level == "soft-mandatory"
    end

    test "returns error for non-existent RGP policy" do
      expect_get(404, %{"errors" => ["policy not found"]})

      assert {:error, %Error{type: :not_found}} = Policies.read_rgp("non-existent")
    end

    test "wraps network errors for RGP read" do
      stub_request_raw(:get, %Req.TransportError{reason: :econnrefused})

      assert {:error, %Error{type: :unknown_error}} = Policies.read_rgp("webapp")
    end
  end

  describe "write_rgp/3" do
    test "creates RGP policy successfully" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/policies/rgp/new-rgp-policy")
        assert body["policy"] == @rgp_policy_config.policy
        assert body["enforcement_level"] == @rgp_policy_config.enforcement_level
      end)

      assert :ok = Policies.write_rgp("new-rgp-policy", @rgp_policy_config)
    end

    test "validates enforcement level" do
      invalid_config = %{
        policy: "rule main = { true }",
        enforcement_level: "invalid-level"
      }

      assert {:error, %Error{type: :invalid_request}} =
               Policies.write_rgp("test-policy", invalid_config)
    end

    test "accepts valid enforcement levels" do
      for level <- ["advisory", "soft-mandatory", "hard-mandatory"] do
        config = %{policy: "rule main = { true }", enforcement_level: level}
        expect_post(204, %{})
        assert :ok = Policies.write_rgp("test-#{level}", config)
      end
    end

    test "wraps network errors for RGP write" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{type: :unknown_error}} =
               Policies.write_rgp("test-policy", @rgp_policy_config)
    end
  end

  describe "delete_rgp/2" do
    test "deletes RGP policy successfully" do
      expect_delete(204, %{}, fn url, _body, _opts ->
        assert String.contains?(url, "sys/policies/rgp/old-rgp-policy")
      end)

      assert :ok = Policies.delete_rgp("old-rgp-policy")
    end

    test "returns error for non-existent RGP policy deletion" do
      expect_delete(404, %{"errors" => ["policy not found"]})

      assert {:error, %Error{type: :not_found}} = Policies.delete_rgp("non-existent")
    end

    test "wraps network errors for RGP delete" do
      stub_request_raw(:delete, %Req.TransportError{reason: :econnrefused})

      assert {:error, %Error{type: :unknown_error}} = Policies.delete_rgp("test-policy")
    end
  end

  describe "list_egp/1" do
    test "returns EGP policy list successfully" do
      expect_any(:list, 200, @egp_policy_list_response, fn url, _body, _opts ->
        assert String.contains?(url, "sys/policies/egp")
        refute String.contains?(url, "sys/policies/egp/")
      end)

      assert {:ok, policies} = Policies.list_egp()
      assert policies == ["breakglass", "global-policy"]
    end

    test "handles empty EGP policy list" do
      expect_any(:list, 200, %{"keys" => []})

      assert {:ok, policies} = Policies.list_egp()
      assert policies == []
    end

    test "wraps network errors for EGP list" do
      stub_request_raw(:list, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{type: :unknown_error}} = Policies.list_egp()
    end
  end

  describe "read_egp/2" do
    test "returns EGP policy successfully" do
      expect_get(200, @egp_policy_read_response, fn url, _body, _opts ->
        assert String.contains?(url, "sys/policies/egp/breakglass")
      end)

      assert {:ok, policy} = Policies.read_egp("breakglass")
      assert policy.name == "breakglass"
      assert String.contains?(policy.policy, "request.operation")
      assert policy.enforcement_level == "soft-mandatory"
      assert policy.paths == ["*"]
    end

    test "returns error for non-existent EGP policy" do
      expect_get(404, %{"errors" => ["policy not found"]})

      assert {:error, %Error{type: :not_found}} = Policies.read_egp("non-existent")
    end

    test "wraps network errors for EGP read" do
      stub_request_raw(:get, %Req.TransportError{reason: :econnrefused})

      assert {:error, %Error{type: :unknown_error}} = Policies.read_egp("breakglass")
    end
  end

  describe "write_egp/3" do
    test "creates EGP policy successfully with list paths" do
      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/policies/egp/new-egp-policy")
        assert body["policy"] == @egp_policy_config.policy
        assert body["enforcement_level"] == @egp_policy_config.enforcement_level
        assert body["paths"] == @egp_policy_config.paths
      end)

      assert :ok = Policies.write_egp("new-egp-policy", @egp_policy_config)
    end

    test "creates EGP policy successfully with string paths" do
      config_with_string_paths = %{
        policy: "rule main = { true }",
        enforcement_level: "soft-mandatory",
        paths: "*, secret/*, transit/keys/*"
      }

      expect_post(204, %{}, fn url, body, _opts ->
        assert String.contains?(url, "sys/policies/egp/string-paths-policy")
        assert body["paths"] == ["*", "secret/*", "transit/keys/*"]
      end)

      assert :ok = Policies.write_egp("string-paths-policy", config_with_string_paths)
    end

    test "validates enforcement level for EGP" do
      invalid_config = %{
        policy: "rule main = { true }",
        enforcement_level: "invalid-level",
        paths: ["*"]
      }

      assert {:error, %Error{type: :invalid_request}} =
               Policies.write_egp("test-policy", invalid_config)
    end

    test "accepts valid enforcement levels for EGP" do
      for level <- ["advisory", "soft-mandatory", "hard-mandatory"] do
        config = %{
          policy: "rule main = { true }",
          enforcement_level: level,
          paths: ["*"]
        }

        expect_post(204, %{})
        assert :ok = Policies.write_egp("test-egp-#{level}", config)
      end
    end

    test "handles empty paths" do
      config_with_empty_paths = %{
        policy: "rule main = { true }",
        enforcement_level: "soft-mandatory",
        paths: []
      }

      expect_post(204, %{}, fn _url, body, _opts ->
        assert body["paths"] == []
      end)

      assert :ok = Policies.write_egp("empty-paths-policy", config_with_empty_paths)
    end

    test "handles nil paths" do
      config_with_nil_paths = %{
        policy: "rule main = { true }",
        enforcement_level: "soft-mandatory",
        paths: nil
      }

      expect_post(204, %{}, fn _url, body, _opts ->
        assert body["paths"] == []
      end)

      assert :ok = Policies.write_egp("nil-paths-policy", config_with_nil_paths)
    end

    test "wraps network errors for EGP write" do
      stub_request_raw(:post, %Req.TransportError{reason: :timeout})

      assert {:error, %Error{type: :unknown_error}} =
               Policies.write_egp("test-policy", @egp_policy_config)
    end
  end

  describe "delete_egp/2" do
    test "deletes EGP policy successfully" do
      expect_delete(204, %{}, fn url, _body, _opts ->
        assert String.contains?(url, "sys/policies/egp/old-egp-policy")
      end)

      assert :ok = Policies.delete_egp("old-egp-policy")
    end

    test "returns error for non-existent EGP policy deletion" do
      expect_delete(404, %{"errors" => ["policy not found"]})

      assert {:error, %Error{type: :not_found}} = Policies.delete_egp("non-existent")
    end

    test "wraps network errors for EGP delete" do
      stub_request_raw(:delete, %Req.TransportError{reason: :econnrefused})

      assert {:error, %Error{type: :unknown_error}} = Policies.delete_egp("test-policy")
    end
  end
end
