defmodule Vaultx.Sys.Policies do
  @moduledoc """
  Comprehensive policy management for HashiCorp Vault system backend.

  This module provides enterprise-grade policy management capabilities for Vault
  ACL (Access Control List), RGP (Role Governing Policies), and EGP (Endpoint
  Governing Policies), enabling fine-grained access control and security governance
  for enterprise Vault deployments with complete policy lifecycle management.

  ## Enterprise Policy Management

  ### ACL Policies (Access Control Lists)
  - Standard Vault policies written in HCL format
  - Define path-based access permissions and capabilities
  - Support for create, read, update, delete, list, and deny operations
  - Automatic policy validation and syntax checking

  ### RGP Policies (Role Governing Policies) - Enterprise
  - Advanced policy enforcement using Sentinel language
  - Role-based policy governance with enforcement levels
  - Support for advisory, soft-mandatory, and hard-mandatory enforcement
  - Complex business logic and compliance rule implementation

  ### EGP Policies (Endpoint Governing Policies) - Enterprise
  - Path-based policy enforcement across multiple endpoints
  - Global policy application with wildcard path support
  - Advanced request/response filtering and validation
  - Multi-path policy assignment and management

  ## API Compliance

  Fully implements HashiCorp Vault Policies API:
  - [System Policies API](https://developer.hashicorp.com/vault/api-docs/system/policies)
  - [Policy Concepts](https://developer.hashicorp.com/vault/docs/concepts/policies)
  - [Policy Syntax](https://developer.hashicorp.com/vault/docs/concepts/policies#policy-syntax)

  ## Usage Examples

      # ACL Policy Operations
      {:ok, policies} = Vaultx.Sys.Policies.list_acl()
      {:ok, policy} = Vaultx.Sys.Policies.read_acl("my-policy")
      :ok = Vaultx.Sys.Policies.write_acl("my-policy", policy_rules)
      :ok = Vaultx.Sys.Policies.delete_acl("my-policy")

      # RGP Policy Operations (Enterprise)
      {:ok, policies} = Vaultx.Sys.Policies.list_rgp()
      {:ok, policy} = Vaultx.Sys.Policies.read_rgp("webapp-policy")
      :ok = Vaultx.Sys.Policies.write_rgp("webapp-policy", %{
        policy: "rule main = {...",
        enforcement_level: "soft-mandatory"
      })

      # EGP Policy Operations (Enterprise)
      {:ok, policies} = Vaultx.Sys.Policies.list_egp()
      {:ok, policy} = Vaultx.Sys.Policies.read_egp("global-policy")
      :ok = Vaultx.Sys.Policies.write_egp("global-policy", %{
        policy: "rule main = {...",
        paths: ["*", "secret/*"],
        enforcement_level: "hard-mandatory"
      })

  ## Policy Language Examples

  ### ACL Policy (HCL Format)
      # Allow full access to secret/myapp/*
      path "secret/myapp/*" {
        capabilities = ["create", "read", "update", "delete", "list"]
      }

      # Allow read-only access to secret/shared/*
      path "secret/shared/*" {
        capabilities = ["read", "list"]
      }

  ### RGP Policy (Sentinel Language)
      rule main = {
        token.ttl <= 3600 and
        "developers" in token.groups
      }

  ### EGP Policy (Sentinel Language)
      rule main = {
        request.operation in ["create", "update"] and
        strings.has_prefix(request.path, "secret/")
      }

  ## Security Considerations

  - Policy changes take effect immediately for all associated tokens
  - The "root" policy cannot be deleted or modified
  - The "default" policy is automatically attached to all tokens
  - Use principle of least privilege when designing policies
  - RGP and EGP policies require Vault Enterprise
  - Test policies thoroughly before production deployment

  """

  alias Vaultx.Base.{Error, Logger, Telemetry}
  alias Vaultx.Transport.HTTP
  alias Vaultx.Types

  @typedoc """
  Policy management options.
  """
  @type policy_opts :: [
          # Base options
          timeout: pos_integer(),
          retry_attempts: non_neg_integer(),
          namespace: String.t()
        ]

  @typedoc """
  ACL policy information structure.
  """
  @type acl_policy_info :: %{
          name: String.t(),
          policy: String.t()
        }

  @typedoc """
  RGP policy information structure.
  """
  @type rgp_policy_info :: %{
          name: String.t(),
          policy: String.t(),
          enforcement_level: String.t()
        }

  @typedoc """
  EGP policy information structure.
  """
  @type egp_policy_info :: %{
          name: String.t(),
          policy: String.t(),
          enforcement_level: String.t(),
          paths: [String.t()]
        }

  @typedoc """
  RGP policy configuration for creation/update.
  """
  @type rgp_policy_config :: %{
          policy: String.t(),
          enforcement_level: String.t()
        }

  @typedoc """
  EGP policy configuration for creation/update.
  """
  @type egp_policy_config :: %{
          policy: String.t(),
          enforcement_level: String.t(),
          paths: [String.t()] | String.t()
        }

  # ACL Policy Operations

  @doc """
  List all configured ACL policies.

  Returns a list of ACL policy names available in the Vault instance.
  Implements `LIST /sys/policies/acl`.

  ## Examples

      {:ok, policies} = Vaultx.Sys.Policies.list_acl()
      policies #=> ["default", "root", "my-policy"]

  """
  @spec list_acl(policy_opts()) :: Types.result([String.t()])
  def list_acl(opts \\ []) do
    start_time = System.monotonic_time()

    metadata = %{
      operation: :list_acl_policies,
      policy_type: :acl,
      module: __MODULE__
    }

    Logger.debug("Listing ACL policies", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.request(:list, "sys/policies/acl", nil, [], opts) do
      {:ok, %{status: 200, body: %{"keys" => policies}}} ->
        duration = System.monotonic_time() - start_time

        Logger.debug("ACL policy listing successful", Map.put(metadata, :count, length(policies)))
        Telemetry.operation_success(duration, Map.put(metadata, :count, length(policies)))

        {:ok, policies}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("ACL policy listing failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Read a specific ACL policy.

  Retrieves the policy rules for the specified ACL policy name.
  Implements `GET /sys/policies/acl/:name`.

  ## Examples

      {:ok, policy} = Vaultx.Sys.Policies.read_acl("my-policy")
      policy.name #=> "my-policy"
      policy.policy #=> "path \"secret/*\" { capabilities = [\"read\"] }"

  """
  @spec read_acl(String.t(), policy_opts()) :: Types.result(acl_policy_info())
  def read_acl(name, opts \\ []) do
    start_time = System.monotonic_time()

    metadata = %{
      operation: :read_acl_policy,
      policy_type: :acl,
      policy_name: name,
      module: __MODULE__
    }

    Logger.debug("Reading ACL policy", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.get("sys/policies/acl/#{name}", opts) do
      {:ok, %{status: 200, body: %{"name" => ^name, "policy" => policy}}} ->
        duration = System.monotonic_time() - start_time

        policy_info = %{name: name, policy: policy}

        Logger.debug("ACL policy read successful", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, policy_info}

      {:ok, %{status: 404}} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:not_found, "ACL policy not found: #{name}")

        Logger.debug("ACL policy not found", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("ACL policy read failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Create or update an ACL policy.

  Creates a new ACL policy or updates an existing one with the specified rules.
  Policy changes take effect immediately for all associated tokens.
  Implements `POST /sys/policies/acl/:name`.

  ## Examples

      rules = ~s(path "secret/myapp/*" { capabilities = ["create", "read", "update", "delete"] })
      :ok = Vaultx.Sys.Policies.write_acl("myapp-policy", rules)

  """
  @spec write_acl(String.t(), String.t(), policy_opts()) :: Types.result(:ok)
  def write_acl(name, policy, opts \\ []) do
    start_time = System.monotonic_time()

    metadata = %{
      operation: :write_acl_policy,
      policy_type: :acl,
      policy_name: name,
      module: __MODULE__
    }

    Logger.debug("Writing ACL policy", metadata)
    Telemetry.operation_start(metadata)

    payload = %{"policy" => policy}

    case HTTP.post("sys/policies/acl/#{name}", payload, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        duration = System.monotonic_time() - start_time

        Logger.info("ACL policy written successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        :ok

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("ACL policy write failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Delete an ACL policy.

  Permanently removes the specified ACL policy. This will immediately affect
  all tokens associated with this policy.
  Implements `DELETE /sys/policies/acl/:name`.

  ## Security Notes

  - The "root" policy cannot be deleted
  - The "default" policy cannot be deleted
  - Deletion takes effect immediately for all associated tokens

  ## Examples

      :ok = Vaultx.Sys.Policies.delete_acl("old-policy")

  """
  @spec delete_acl(String.t(), policy_opts()) :: Types.result(:ok)
  def delete_acl(name, opts \\ []) do
    start_time = System.monotonic_time()

    metadata = %{
      operation: :delete_acl_policy,
      policy_type: :acl,
      policy_name: name,
      module: __MODULE__
    }

    Logger.debug("Deleting ACL policy", metadata)
    Telemetry.operation_start(metadata)

    # Prevent deletion of system policies
    if name in ["root", "default"] do
      error = Error.new(:invalid_request, "Cannot delete system ACL policy: #{name}")
      Logger.warning("Attempted to delete system ACL policy", Map.put(metadata, :error, error))
      {:error, error}
    else
      case HTTP.delete("sys/policies/acl/#{name}", opts) do
        {:ok, %{status: status}} when status in [200, 204] ->
          duration = System.monotonic_time() - start_time

          Logger.info("ACL policy deleted successfully", metadata)
          Telemetry.operation_success(duration, metadata)

          :ok

        {:ok, %{status: 404}} ->
          duration = System.monotonic_time() - start_time
          error = Error.new(:not_found, "ACL policy not found: #{name}")

          Logger.debug("ACL policy not found for deletion", Map.put(metadata, :error, error))
          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}

        {:error, error} ->
          duration = System.monotonic_time() - start_time

          Logger.error("ACL policy deletion failed", Map.put(metadata, :error, error))
          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}
      end
    end
  end

  # RGP Policy Operations (Enterprise)

  @doc """
  List all configured RGP policies.

  Returns a list of RGP (Role Governing Policy) names available in the Vault Enterprise instance.
  RGP policies are only available in Vault Enterprise.
  Implements `LIST /sys/policies/rgp`.

  ## Examples

      {:ok, policies} = Vaultx.Sys.Policies.list_rgp()
      policies #=> ["webapp", "database"]

  """
  @spec list_rgp(policy_opts()) :: Types.result([String.t()])
  def list_rgp(opts \\ []) do
    start_time = System.monotonic_time()

    metadata = %{
      operation: :list_rgp_policies,
      policy_type: :rgp,
      module: __MODULE__
    }

    Logger.debug("Listing RGP policies", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.request(:list, "sys/policies/rgp", nil, [], opts) do
      {:ok, %{status: 200, body: %{"keys" => policies}}} ->
        duration = System.monotonic_time() - start_time

        Logger.debug("RGP policy listing successful", Map.put(metadata, :count, length(policies)))
        Telemetry.operation_success(duration, Map.put(metadata, :count, length(policies)))

        {:ok, policies}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("RGP policy listing failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Read a specific RGP policy.

  Retrieves the policy rules and configuration for the specified RGP policy name.
  RGP policies are only available in Vault Enterprise.
  Implements `GET /sys/policies/rgp/:name`.

  ## Examples

      {:ok, policy} = Vaultx.Sys.Policies.read_rgp("webapp")
      policy.name #=> "webapp"
      policy.policy #=> "rule main = { token.ttl <= 3600 }"
      policy.enforcement_level #=> "soft-mandatory"

  """
  @spec read_rgp(String.t(), policy_opts()) :: Types.result(rgp_policy_info())
  def read_rgp(name, opts \\ []) do
    start_time = System.monotonic_time()

    metadata = %{
      operation: :read_rgp_policy,
      policy_type: :rgp,
      policy_name: name,
      module: __MODULE__
    }

    Logger.debug("Reading RGP policy", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.get("sys/policies/rgp/#{name}", opts) do
      {:ok,
       %{
         status: 200,
         body: %{"name" => ^name, "policy" => policy, "enforcement_level" => enforcement_level}
       }} ->
        duration = System.monotonic_time() - start_time

        policy_info = %{
          name: name,
          policy: policy,
          enforcement_level: enforcement_level
        }

        Logger.debug("RGP policy read successful", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, policy_info}

      {:ok, %{status: 404}} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:not_found, "RGP policy not found: #{name}")

        Logger.debug("RGP policy not found", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("RGP policy read failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Create or update an RGP policy.

  Creates a new RGP policy or updates an existing one with the specified rules and enforcement level.
  RGP policies are only available in Vault Enterprise.
  Policy changes take effect immediately for all associated tokens.
  Implements `POST /sys/policies/rgp/:name`.

  ## Parameters

  - `name`: The name of the RGP policy
  - `config`: Policy configuration containing:
    - `policy`: The Sentinel policy document
    - `enforcement_level`: One of "advisory", "soft-mandatory", or "hard-mandatory"

  ## Examples

      config = %{
        policy: "rule main = { token.ttl <= 3600 and \"developers\" in token.groups }",
        enforcement_level: "soft-mandatory"
      }
      :ok = Vaultx.Sys.Policies.write_rgp("webapp-policy", config)

  """
  @spec write_rgp(String.t(), rgp_policy_config(), policy_opts()) :: Types.result(:ok)
  def write_rgp(name, config, opts \\ []) do
    start_time = System.monotonic_time()

    metadata = %{
      operation: :write_rgp_policy,
      policy_type: :rgp,
      policy_name: name,
      enforcement_level: config[:enforcement_level],
      module: __MODULE__
    }

    Logger.debug("Writing RGP policy", metadata)
    Telemetry.operation_start(metadata)

    # Validate enforcement level
    valid_levels = ["advisory", "soft-mandatory", "hard-mandatory"]
    enforcement_level = config[:enforcement_level]

    if enforcement_level not in valid_levels do
      error =
        Error.new(
          :invalid_request,
          "Invalid enforcement level: #{enforcement_level}. Must be one of: #{Enum.join(valid_levels, ", ")}"
        )

      Logger.error("Invalid RGP enforcement level", Map.put(metadata, :error, error))
      {:error, error}
    else
      payload = %{
        "policy" => config[:policy],
        "enforcement_level" => enforcement_level
      }

      case HTTP.post("sys/policies/rgp/#{name}", payload, opts) do
        {:ok, %{status: status}} when status in [200, 204] ->
          duration = System.monotonic_time() - start_time

          Logger.info("RGP policy written successfully", metadata)
          Telemetry.operation_success(duration, metadata)

          :ok

        {:error, error} ->
          duration = System.monotonic_time() - start_time

          Logger.error("RGP policy write failed", Map.put(metadata, :error, error))
          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}
      end
    end
  end

  @doc """
  Delete an RGP policy.

  Permanently removes the specified RGP policy. This will immediately affect
  all tokens associated with this policy.
  RGP policies are only available in Vault Enterprise.
  Implements `DELETE /sys/policies/rgp/:name`.

  ## Examples

      :ok = Vaultx.Sys.Policies.delete_rgp("old-rgp-policy")

  """
  @spec delete_rgp(String.t(), policy_opts()) :: Types.result(:ok)
  def delete_rgp(name, opts \\ []) do
    start_time = System.monotonic_time()

    metadata = %{
      operation: :delete_rgp_policy,
      policy_type: :rgp,
      policy_name: name,
      module: __MODULE__
    }

    Logger.debug("Deleting RGP policy", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.delete("sys/policies/rgp/#{name}", opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        duration = System.monotonic_time() - start_time

        Logger.info("RGP policy deleted successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        :ok

      {:ok, %{status: 404}} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:not_found, "RGP policy not found: #{name}")

        Logger.debug("RGP policy not found for deletion", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("RGP policy deletion failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  # EGP Policy Operations (Enterprise)

  @doc """
  List all configured EGP policies.

  Returns a list of EGP (Endpoint Governing Policy) names available in the Vault Enterprise instance.
  EGP policies are only available in Vault Enterprise.
  Implements `LIST /sys/policies/egp`.

  ## Examples

      {:ok, policies} = Vaultx.Sys.Policies.list_egp()
      policies #=> ["breakglass", "global-policy"]

  """
  @spec list_egp(policy_opts()) :: Types.result([String.t()])
  def list_egp(opts \\ []) do
    start_time = System.monotonic_time()

    metadata = %{
      operation: :list_egp_policies,
      policy_type: :egp,
      module: __MODULE__
    }

    Logger.debug("Listing EGP policies", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.request(:list, "sys/policies/egp", nil, [], opts) do
      {:ok, %{status: 200, body: %{"keys" => policies}}} ->
        duration = System.monotonic_time() - start_time

        Logger.debug("EGP policy listing successful", Map.put(metadata, :count, length(policies)))
        Telemetry.operation_success(duration, Map.put(metadata, :count, length(policies)))

        {:ok, policies}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("EGP policy listing failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Read a specific EGP policy.

  Retrieves the policy rules and configuration for the specified EGP policy name.
  EGP policies are only available in Vault Enterprise.
  Implements `GET /sys/policies/egp/:name`.

  ## Examples

      {:ok, policy} = Vaultx.Sys.Policies.read_egp("breakglass")
      policy.name #=> "breakglass"
      policy.policy #=> "rule main = { request.operation in [\"create\", \"update\"] }"
      policy.enforcement_level #=> "soft-mandatory"
      policy.paths #=> ["*"]

  """
  @spec read_egp(String.t(), policy_opts()) :: Types.result(egp_policy_info())
  def read_egp(name, opts \\ []) do
    start_time = System.monotonic_time()

    metadata = %{
      operation: :read_egp_policy,
      policy_type: :egp,
      policy_name: name,
      module: __MODULE__
    }

    Logger.debug("Reading EGP policy", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.get("sys/policies/egp/#{name}", opts) do
      {:ok,
       %{
         status: 200,
         body: %{
           "name" => ^name,
           "policy" => policy,
           "enforcement_level" => enforcement_level,
           "paths" => paths
         }
       }} ->
        duration = System.monotonic_time() - start_time

        policy_info = %{
          name: name,
          policy: policy,
          enforcement_level: enforcement_level,
          paths: paths
        }

        Logger.debug("EGP policy read successful", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, policy_info}

      {:ok, %{status: 404}} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:not_found, "EGP policy not found: #{name}")

        Logger.debug("EGP policy not found", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("EGP policy read failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Create or update an EGP policy.

  Creates a new EGP policy or updates an existing one with the specified rules, enforcement level, and paths.
  EGP policies are only available in Vault Enterprise.
  Policy changes take effect immediately for all associated tokens.
  Implements `POST /sys/policies/egp/:name`.

  ## Parameters

  - `name`: The name of the EGP policy
  - `config`: Policy configuration containing:
    - `policy`: The Sentinel policy document
    - `enforcement_level`: One of "advisory", "soft-mandatory", or "hard-mandatory"
    - `paths`: List of paths or comma-separated string of paths where the policy applies

  ## Examples

      config = %{
        policy: "rule main = { request.operation in [\"create\", \"update\"] }",
        enforcement_level: "soft-mandatory",
        paths: ["*", "secret/*", "transit/keys/*"]
      }
      :ok = Vaultx.Sys.Policies.write_egp("global-policy", config)

  """
  @spec write_egp(String.t(), egp_policy_config(), policy_opts()) :: Types.result(:ok)
  def write_egp(name, config, opts \\ []) do
    start_time = System.monotonic_time()

    metadata = %{
      operation: :write_egp_policy,
      policy_type: :egp,
      policy_name: name,
      enforcement_level: config[:enforcement_level],
      module: __MODULE__
    }

    Logger.debug("Writing EGP policy", metadata)
    Telemetry.operation_start(metadata)

    # Validate enforcement level
    valid_levels = ["advisory", "soft-mandatory", "hard-mandatory"]
    enforcement_level = config[:enforcement_level]

    if enforcement_level not in valid_levels do
      error =
        Error.new(
          :invalid_request,
          "Invalid enforcement level: #{enforcement_level}. Must be one of: #{Enum.join(valid_levels, ", ")}"
        )

      Logger.error("Invalid EGP enforcement level", Map.put(metadata, :error, error))
      {:error, error}
    else
      # Handle paths - can be a list or comma-separated string
      paths =
        case config[:paths] do
          paths when is_list(paths) ->
            paths

          paths when is_binary(paths) ->
            paths
            |> String.split(",", trim: true)
            |> Enum.map(&String.trim/1)

          _ ->
            []
        end

      payload = %{
        "policy" => config[:policy],
        "enforcement_level" => enforcement_level,
        "paths" => paths
      }

      case HTTP.post("sys/policies/egp/#{name}", payload, opts) do
        {:ok, %{status: status}} when status in [200, 204] ->
          duration = System.monotonic_time() - start_time

          Logger.info("EGP policy written successfully", metadata)
          Telemetry.operation_success(duration, metadata)

          :ok

        {:error, error} ->
          duration = System.monotonic_time() - start_time

          Logger.error("EGP policy write failed", Map.put(metadata, :error, error))
          Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

          {:error, error}
      end
    end
  end

  @doc """
  Delete an EGP policy.

  Permanently removes the specified EGP policy from all paths on which it was configured.
  This will immediately affect all tokens associated with this policy.
  EGP policies are only available in Vault Enterprise.
  Implements `DELETE /sys/policies/egp/:name`.

  ## Examples

      :ok = Vaultx.Sys.Policies.delete_egp("old-egp-policy")

  """
  @spec delete_egp(String.t(), policy_opts()) :: Types.result(:ok)
  def delete_egp(name, opts \\ []) do
    start_time = System.monotonic_time()

    metadata = %{
      operation: :delete_egp_policy,
      policy_type: :egp,
      policy_name: name,
      module: __MODULE__
    }

    Logger.debug("Deleting EGP policy", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.delete("sys/policies/egp/#{name}", opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        duration = System.monotonic_time() - start_time

        Logger.info("EGP policy deleted successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        :ok

      {:ok, %{status: 404}} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:not_found, "EGP policy not found: #{name}")

        Logger.debug("EGP policy not found for deletion", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, error} ->
        duration = System.monotonic_time() - start_time

        Logger.error("EGP policy deletion failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end
end
