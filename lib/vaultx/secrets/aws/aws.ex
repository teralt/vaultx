defmodule Vaultx.Secrets.AWS do
  @moduledoc """
  Unified AWS secrets engine interface for HashiCorp Vault.

  This module provides a comprehensive, enterprise-grade interface for the
  AWS secrets engine, offering dynamic and static credential management,
  configuration operations, and role management. It supports all AWS
  credential types with advanced security features and compliance capabilities.

  ## Enterprise AWS Credential Management

  - Dynamic Credential Generation: IAM users, assumed roles, federation tokens, session tokens
  - Static Credential Management: Managed IAM user credentials with rotation
  - Configuration Management: Root credentials, lease settings, and rotation policies
  - Role Management: Dynamic and static role configuration with policy enforcement
  - Cross-Account Support: Multi-account AWS credential management
  - Security Compliance: Audit logging, least privilege, and policy validation

  ## Supported Credential Types

  ### Dynamic Credentials
  - IAM User: Temporary IAM users with attached policies and groups
  - Assumed Role: STS credentials via role assumption with session management
  - Federation Token: Federated user credentials with policy filtering
  - Session Token: Temporary session tokens with MFA support

  ### Static Credentials
  - Static Roles: 1-to-1 mapping with existing IAM users
  - Automatic Rotation: Configurable rotation periods and policies
  - Cross-Account: Assume roles in target accounts for credential management

  ## Configuration Examples

      # Configure root AWS credentials
      config = %{
        access_key: "AKIA...",
        secret_key: "...",
        region: "us-east-1"
      }
      {:ok, _} = AWS.configure_root(config)

      # Create a dynamic role for assumed role credentials
      role_config = %{
        credential_type: "assumed_role",
        role_arns: ["arn:aws:iam::123456789012:role/MyRole"],
        default_sts_ttl: "1h",
        max_sts_ttl: "12h"
      }
      {:ok, _} = AWS.create_role("my-role", role_config)

      # Generate credentials
      {:ok, creds} = AWS.generate_credentials("my-role")

  ## API Compliance

  Fully implements HashiCorp Vault AWS secrets engine:
  - [AWS Secrets Engine API](https://developer.hashicorp.com/vault/api-docs/secret/aws)
  - [AWS Secrets Engine Guide](https://developer.hashicorp.com/vault/docs/secrets/aws)
  - [AWS Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)

  """

  alias Vaultx.Base.{Error, Logger, Telemetry}
  alias Vaultx.Secrets.AWS.Behaviour
  alias Vaultx.Transport.HTTP

  @behaviour Behaviour

  @default_mount_path "aws"

  # Configuration Operations

  @doc """
  Configure root AWS credentials for the secrets engine.

  Sets up the AWS access credentials that Vault will use to manage
  AWS resources. Supports both static credentials and Plugin Workload
  Identity Federation (WIF) for enhanced security.

  ## Parameters

  - `config` - Root configuration parameters
  - `opts` - Request options including mount path

  ## Examples

      # Static credentials
      config = %{
        access_key: "AKIA...",
        secret_key: "...",
        region: "us-east-1",
        max_retries: 3
      }
      {:ok, _} = AWS.configure_root(config)

      # With custom endpoints
      config = %{
        access_key: "AKIA...",
        secret_key: "...",
        region: "us-gov-west-1",
        iam_endpoint: "https://iam.us-gov.amazonaws.com",
        sts_endpoint: "https://sts.us-gov-west-1.amazonaws.com"
      }

  """
  @impl Behaviour
  def configure_root(config, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    telemetry_metadata = %{
      operation: :configure_root,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()

    Telemetry.operation_start(telemetry_metadata)

    Logger.info("Configuring AWS root credentials", %{
      mount_path: mount_path,
      region: Map.get(config, :region)
    })

    path = "/#{mount_path}/config/root"

    case HTTP.post(path, config, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        Logger.info("Successfully configured AWS root credentials", %{
          mount_path: mount_path
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_success(duration, telemetry_metadata)
        :ok

      {:ok, response} ->
        error = Error.from_http_response(response.status, response.body)

        Logger.error("Failed to configure AWS root credentials", %{
          mount_path: mount_path,
          error: error
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}

      {:error, reason} ->
        error = Error.new(:http_error, "HTTP request failed", details: %{reason: reason})

        Logger.error("HTTP error configuring AWS root credentials", %{
          mount_path: mount_path,
          error: error
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}
    end
  end

  @doc """
  Read the current root configuration.

  Returns the non-sensitive parts of the root configuration.
  The secret_key is never returned for security reasons.

  ## Examples

      {:ok, config} = AWS.read_root_config()
      %{
        "access_key" => "AKIA...",
        "region" => "us-east-1",
        "max_retries" => -1
      }

  """
  @impl Behaviour
  def read_root_config(opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    telemetry_metadata = %{
      operation: :read_root_config,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()

    Telemetry.operation_start(telemetry_metadata)

    path = "/#{mount_path}/config/root"

    case HTTP.get(path, opts) do
      {:ok, %{status: 200, body: %{"data" => data}}} ->
        duration = System.monotonic_time() - start_time
        Telemetry.operation_success(duration, telemetry_metadata)
        {:ok, data}

      {:ok, response} ->
        error = Error.from_http_response(response.status, response.body)
        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}

      {:error, reason} ->
        error = Error.new(:http_error, "HTTP request failed", details: %{reason: reason})
        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}
    end
  end

  @doc """
  Rotate the root AWS credentials.

  Generates a new access key for the IAM user and updates Vault's
  configuration to use the new credentials. The old access key is
  automatically deleted.

  ## Examples

      {:ok, result} = AWS.rotate_root()
      %{"access_key" => "AKIA..."}

  """
  @impl Behaviour
  def rotate_root(opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    telemetry_metadata = %{
      operation: :rotate_root,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()

    Telemetry.operation_start(telemetry_metadata)

    Logger.info("Rotating AWS root credentials", %{mount_path: mount_path})

    path = "/#{mount_path}/config/rotate-root"

    case HTTP.post(path, %{}, opts) do
      {:ok, %{status: 200, body: %{"data" => data}}} ->
        Logger.info("Successfully rotated AWS root credentials", %{
          mount_path: mount_path,
          new_access_key: Map.get(data, "access_key")
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_success(duration, telemetry_metadata)
        {:ok, data}

      {:ok, response} ->
        error = Error.from_http_response(response.status, response.body)

        Logger.error("Failed to rotate AWS root credentials", %{
          mount_path: mount_path,
          error: error
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}

      {:error, reason} ->
        error = Error.new(:http_error, "HTTP request failed", details: %{reason: reason})
        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}
    end
  end

  @doc """
  Configure lease settings for the AWS secrets engine.

  Sets the default lease duration and maximum lease duration for
  generated credentials.

  ## Parameters

  - `config` - Lease configuration with `:lease` and `:lease_max`
  - `opts` - Request options

  ## Examples

      config = %{
        lease: "30m",
        lease_max: "12h"
      }
      {:ok, _} = AWS.configure_lease(config)

  """
  @impl Behaviour
  def configure_lease(config, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    telemetry_metadata = %{
      operation: :configure_lease,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()

    Telemetry.operation_start(telemetry_metadata)

    path = "/#{mount_path}/config/lease"

    case HTTP.post(path, config, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        duration = System.monotonic_time() - start_time
        Telemetry.operation_success(duration, telemetry_metadata)
        :ok

      {:ok, response} ->
        error = Error.from_http_response(response.status, response.body)
        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}

      {:error, reason} ->
        error = Error.new(:http_error, "HTTP request failed", details: %{reason: reason})
        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}
    end
  end

  @doc """
  Read the current lease configuration.

  ## Examples

      {:ok, config} = AWS.read_lease_config()
      %{
        lease: "30m0s",
        lease_max: "12h0m0s"
      }

  """
  @impl Behaviour
  def read_lease_config(opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    path = "/#{mount_path}/config/lease"

    case HTTP.get(path, opts) do
      {:ok, %{status: 200, body: %{"data" => data}}} ->
        config = %{
          lease: Map.get(data, "lease"),
          lease_max: Map.get(data, "lease_max")
        }

        {:ok, config}

      {:ok, response} ->
        {:error, Error.from_http_response(response.status, response.body)}

      {:error, reason} ->
        {:error, Error.new(:http_error, "HTTP request failed", details: %{reason: reason})}
    end
  end

  # Dynamic Role Operations

  @doc """
  Create or update a dynamic role.

  Configures a role that can be used to generate AWS credentials.
  The role defines the type of credentials to generate and the
  associated policies and constraints.

  ## Parameters

  - `name` - Role name
  - `config` - Role configuration
  - `opts` - Request options

  ## Examples

      # IAM User role
      config = %{
        credential_type: "iam_user",
        policy_document: "{\"Version\": \"2012-10-17\", ...}",
        iam_groups: ["developers"]
      }
      {:ok, _} = AWS.create_role("dev-role", config)

      # Assumed Role
      config = %{
        credential_type: "assumed_role",
        role_arns: ["arn:aws:iam::123456789012:role/MyRole"],
        default_sts_ttl: "1h",
        max_sts_ttl: "12h"
      }
      {:ok, _} = AWS.create_role("assume-role", config)

  """
  @impl Behaviour
  def create_role(name, config, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    telemetry_metadata = %{
      operation: :create_role,
      role_name: name,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()

    Telemetry.operation_start(telemetry_metadata)

    Logger.info("Creating AWS role", %{
      role_name: name,
      credential_type: Map.get(config, :credential_type),
      mount_path: mount_path
    })

    path = "/#{mount_path}/roles/#{name}"

    case HTTP.post(path, config, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        Logger.info("Successfully created AWS role", %{
          role_name: name,
          mount_path: mount_path
        })

        Telemetry.operation_success(start_time, %{
          credential_type: Map.get(config, :credential_type)
        })

        :ok

      {:ok, response} ->
        error = Error.from_http_response(response.status, response.body)

        Logger.error("Failed to create AWS role", %{
          role_name: name,
          error: error
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}

      {:error, reason} ->
        error = Error.new(:http_error, "HTTP request failed", details: %{reason: reason})
        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}
    end
  end

  @doc """
  Read a dynamic role configuration.

  ## Examples

      {:ok, config} = AWS.read_role("my-role")
      %{
        credential_type: "assumed_role",
        role_arns: ["arn:aws:iam::123456789012:role/MyRole"],
        policy_arns: [],
        iam_groups: []
      }

  """
  @impl Behaviour
  def read_role(name, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    path = "/#{mount_path}/roles/#{name}"

    case HTTP.get(path, opts) do
      {:ok, %{status: 200, body: %{"data" => data}}} ->
        config = %{
          credential_type: Map.get(data, "credential_type"),
          role_arns: Map.get(data, "role_arns", []),
          policy_arns: Map.get(data, "policy_arns", []),
          policy_document: Map.get(data, "policy_document"),
          iam_groups: Map.get(data, "iam_groups", []),
          iam_tags: Map.get(data, "iam_tags", []),
          default_sts_ttl: Map.get(data, "default_sts_ttl"),
          max_sts_ttl: Map.get(data, "max_sts_ttl"),
          user_path: Map.get(data, "user_path"),
          permissions_boundary_arn: Map.get(data, "permissions_boundary_arn"),
          mfa_serial_number: Map.get(data, "mfa_serial_number")
        }

        {:ok, config}

      {:ok, response} ->
        {:error, Error.from_http_response(response.status, response.body)}

      {:error, reason} ->
        {:error, Error.new(:http_error, "HTTP request failed", details: %{reason: reason})}
    end
  end

  @doc """
  List all configured dynamic roles.

  ## Examples

      {:ok, roles} = AWS.list_roles()
      ["dev-role", "prod-role", "assume-role"]

  """
  @impl Behaviour
  def list_roles(opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    path = "/#{mount_path}/roles"

    case HTTP.request(:list, path, nil, [], opts) do
      {:ok, %{status: 200, body: %{"data" => %{"keys" => keys}}}} ->
        {:ok, keys}

      {:ok, response} ->
        {:error, Error.from_http_response(response.status, response.body)}

      {:error, reason} ->
        {:error, Error.new(:http_error, "HTTP request failed", details: %{reason: reason})}
    end
  end

  @doc """
  Delete a dynamic role.

  ## Examples

      :ok = AWS.delete_role("old-role")

  """
  @impl Behaviour
  def delete_role(name, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    telemetry_metadata = %{
      operation: :delete_role,
      role_name: name,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()

    Telemetry.operation_start(telemetry_metadata)

    path = "/#{mount_path}/roles/#{name}"

    case HTTP.delete(path, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        duration = System.monotonic_time() - start_time
        Telemetry.operation_success(duration, telemetry_metadata)
        :ok

      {:ok, response} ->
        error = Error.from_http_response(response.status, response.body)
        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}

      {:error, reason} ->
        error = Error.new(:http_error, "HTTP request failed", details: %{reason: reason})
        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}
    end
  end

  @doc """
  Generate credentials for a dynamic role.

  Delegates to the Credentials module for actual credential generation.

  ## Examples

      {:ok, creds} = AWS.generate_credentials("my-role")
      %{
        access_key: "AKIA...",
        secret_key: "...",
        session_token: nil,
        arn: "arn:aws:iam::123456789012:user/vault-user-...",
        expiration: nil
      }

  """
  @impl Behaviour
  def generate_credentials(name, opts \\ []) do
    Vaultx.Secrets.AWS.Credentials.generate(name, opts)
  end

  # Static Role Operations

  @doc """
  Create or update a static role.

  Static roles provide 1-to-1 mapping with existing IAM users and
  enable automatic credential rotation.

  ## Parameters

  - `name` - Static role name
  - `config` - Static role configuration
  - `opts` - Request options

  ## Examples

      config = %{
        username: "existing-iam-user",
        rotation_period: "24h"
      }
      {:ok, result} = AWS.create_static_role("my-static-role", config)

  """
  @impl Behaviour
  def create_static_role(name, config, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    telemetry_metadata = %{
      operation: :create_static_role,
      role_name: name,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()

    Telemetry.operation_start(telemetry_metadata)

    Logger.info("Creating AWS static role", %{
      role_name: name,
      username: Map.get(config, :username),
      mount_path: mount_path
    })

    path = "/#{mount_path}/static-roles/#{name}"

    case HTTP.post(path, config, opts) do
      {:ok, %{status: 200, body: %{"data" => data}}} ->
        Logger.info("Successfully created AWS static role", %{
          role_name: name,
          mount_path: mount_path
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_success(duration, telemetry_metadata)
        {:ok, data}

      {:ok, response} ->
        error = Error.from_http_response(response.status, response.body)

        Logger.error("Failed to create AWS static role", %{
          role_name: name,
          error: error
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}

      {:error, reason} ->
        error = Error.new(:http_error, "HTTP request failed", details: %{reason: reason})
        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}
    end
  end

  @doc """
  Read a static role configuration.

  ## Examples

      {:ok, config} = AWS.read_static_role("my-static-role")
      %{
        username: "existing-iam-user",
        rotation_period: "24h"
      }

  """
  @impl Behaviour
  def read_static_role(name, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    path = "/#{mount_path}/static-roles/#{name}"

    case HTTP.get(path, opts) do
      {:ok, %{status: 200, body: %{"data" => data}}} ->
        config = %{
          username: Map.get(data, "username"),
          rotation_period: Map.get(data, "rotation_period")
        }

        {:ok, config}

      {:ok, %{status: 200, body: data}} when is_map(data) ->
        config = %{
          username: Map.get(data, "username"),
          rotation_period: Map.get(data, "rotation_period")
        }

        {:ok, config}

      {:ok, response} ->
        {:error, Error.from_http_response(response.status, response.body)}

      {:error, reason} ->
        {:error, Error.new(:http_error, "HTTP request failed", details: %{reason: reason})}
    end
  end

  @doc """
  List all configured static roles.

  ## Examples

      {:ok, roles} = AWS.list_static_roles()
      ["static-role-1", "static-role-2"]

  """
  @impl Behaviour
  def list_static_roles(opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    path = "/#{mount_path}/static-roles"

    case HTTP.request(:list, path, nil, [], opts) do
      {:ok, %{status: 200, body: %{"data" => %{"keys" => keys}}}} ->
        {:ok, keys}

      {:ok, response} ->
        {:error, Error.from_http_response(response.status, response.body)}

      {:error, reason} ->
        {:error, Error.new(:http_error, "HTTP request failed", details: %{reason: reason})}
    end
  end

  @doc """
  Delete a static role.

  ## Examples

      :ok = AWS.delete_static_role("old-static-role")

  """
  @impl Behaviour
  def delete_static_role(name, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    telemetry_metadata = %{
      operation: :delete_static_role,
      role_name: name,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()

    Telemetry.operation_start(telemetry_metadata)

    path = "/#{mount_path}/static-roles/#{name}"

    case HTTP.delete(path, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        duration = System.monotonic_time() - start_time
        Telemetry.operation_success(duration, telemetry_metadata)
        :ok

      {:ok, response} ->
        error = Error.from_http_response(response.status, response.body)
        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}

      {:error, reason} ->
        error = Error.new(:http_error, "HTTP request failed", details: %{reason: reason})
        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}
    end
  end

  @doc """
  Get static credentials for a static role.

  Delegates to the Credentials module for actual credential retrieval.

  ## Examples

      {:ok, creds} = AWS.get_static_credentials("my-static-role")
      %{
        access_key: "AKIA...",
        secret_key: "...",
        expiration: "2025-08-30T23:59:59Z"
      }

  """
  @impl Behaviour
  def get_static_credentials(name, opts \\ []) do
    Vaultx.Secrets.AWS.Credentials.get_static(name, opts)
  end
end
