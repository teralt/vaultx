defmodule Vaultx.Secrets.AWS.Behaviour do
  @moduledoc """
  Comprehensive behaviour for HashiCorp Vault AWS secrets engine.

  This behaviour provides AWS-specific operations
  for dynamic and static credential management. It provides a complete interface
  for AWS IAM user creation, role assumption, federation tokens, and session
  tokens with enterprise-grade security and compliance features.

  ## AWS Secrets Engine Capabilities

  ### Dynamic Credential Types
  - IAM User: Create temporary IAM users with attached policies
  - Assumed Role: Generate STS credentials by assuming AWS roles
  - Federation Token: Create federated user credentials with policies
  - Session Token: Generate temporary session tokens with MFA support

  ### Static Credential Management
  - Static Role Management: 1-to-1 mapping with existing IAM users
  - Automatic Rotation: Configurable rotation periods for static credentials
  - Cross-Account Support: Manage credentials across AWS accounts

  ### Configuration Management
  - Root Credential Configuration: AWS access keys and regions
  - Lease Configuration: Default and maximum lease durations
  - Root Credential Rotation: Automated rotation of Vault's AWS credentials

  ## Extended AWS Operations

  Beyond standard secrets operations, AWS engines provide:

  ### Configuration Operations
  - `configure_root/2` - Configure AWS root credentials
  - `read_root_config/1` - Read root configuration (non-sensitive)
  - `rotate_root/1` - Rotate root AWS credentials
  - `configure_lease/2` - Configure default lease settings
  - `read_lease_config/1` - Read lease configuration

  ### Dynamic Role Operations
  - `create_role/3` - Create or update dynamic roles
  - `read_role/2` - Read role configuration
  - `list_roles/1` - List all configured roles
  - `delete_role/2` - Delete role configuration
  - `generate_credentials/2` - Generate dynamic credentials

  ### Static Role Operations
  - `create_static_role/3` - Create or update static roles
  - `read_static_role/2` - Read static role configuration
  - `list_static_roles/1` - List all static roles
  - `delete_static_role/2` - Delete static role
  - `get_static_credentials/2` - Get current static credentials

  ## API Compliance

  Fully implements HashiCorp Vault AWS secrets engine:
  - [AWS Secrets Engine API](https://developer.hashicorp.com/vault/api-docs/secret/aws)
  - [AWS Secrets Engine Guide](https://developer.hashicorp.com/vault/docs/secrets/aws)
  - [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)

  """

  alias Vaultx.Base.Error

  @typedoc """
  AWS operation options.
  Common options for all AWS operations.
  """
  @type aws_opts :: [
          # Base options
          timeout: pos_integer(),
          retry_attempts: non_neg_integer(),
          namespace: String.t(),
          token: String.t(),
          mount_path: String.t(),

          # AWS-specific options
          region: String.t(),
          max_retries: integer(),
          iam_endpoint: String.t(),
          sts_endpoint: String.t(),
          role_arn: String.t(),
          role_session_name: String.t(),
          ttl: String.t(),
          mfa_code: String.t()
        ]

  @typedoc """
  Root configuration parameters.
  """
  @type root_config :: %{
          access_key: String.t(),
          secret_key: String.t(),
          region: String.t(),
          max_retries: integer(),
          iam_endpoint: String.t(),
          sts_endpoint: String.t(),
          username_template: String.t()
        }

  @typedoc """
  Lease configuration parameters.
  """
  @type lease_config :: %{
          lease: String.t(),
          lease_max: String.t()
        }

  @typedoc """
  Dynamic role configuration.
  """
  @type role_config :: %{
          credential_type: String.t(),
          role_arns: [String.t()],
          policy_arns: [String.t()],
          policy_document: String.t(),
          iam_groups: [String.t()],
          iam_tags: [String.t()],
          default_sts_ttl: String.t(),
          max_sts_ttl: String.t(),
          user_path: String.t(),
          permissions_boundary_arn: String.t(),
          mfa_serial_number: String.t()
        }

  @typedoc """
  Static role configuration.
  """
  @type static_role_config :: %{
          username: String.t(),
          rotation_period: String.t()
        }

  @typedoc """
  Generated credentials result.
  """
  @type credentials_result :: %{
          access_key: String.t(),
          secret_key: String.t(),
          session_token: String.t() | nil,
          arn: String.t() | nil,
          expiration: String.t() | nil
        }

  # Configuration Operations
  @callback configure_root(config :: root_config(), opts :: aws_opts()) ::
              :ok | {:error, Error.t()}

  @callback read_root_config(opts :: aws_opts()) ::
              {:ok, map()} | {:error, Error.t()}

  @callback rotate_root(opts :: aws_opts()) ::
              {:ok, map()} | {:error, Error.t()}

  @callback configure_lease(config :: lease_config(), opts :: aws_opts()) ::
              :ok | {:error, Error.t()}

  @callback read_lease_config(opts :: aws_opts()) ::
              {:ok, lease_config()} | {:error, Error.t()}

  # Dynamic Role Operations
  @callback create_role(name :: String.t(), config :: role_config(), opts :: aws_opts()) ::
              :ok | {:error, Error.t()}

  @callback read_role(name :: String.t(), opts :: aws_opts()) ::
              {:ok, role_config()} | {:error, Error.t()}

  @callback list_roles(opts :: aws_opts()) ::
              {:ok, [String.t()]} | {:error, Error.t()}

  @callback delete_role(name :: String.t(), opts :: aws_opts()) ::
              :ok | {:error, Error.t()}

  @callback generate_credentials(name :: String.t(), opts :: aws_opts()) ::
              {:ok, credentials_result()} | {:error, Error.t()}

  # Static Role Operations
  @callback create_static_role(
              name :: String.t(),
              config :: static_role_config(),
              opts :: aws_opts()
            ) ::
              {:ok, map()} | {:error, Error.t()}

  @callback read_static_role(name :: String.t(), opts :: aws_opts()) ::
              {:ok, static_role_config()} | {:error, Error.t()}

  @callback list_static_roles(opts :: aws_opts()) ::
              {:ok, [String.t()]} | {:error, Error.t()}

  @callback delete_static_role(name :: String.t(), opts :: aws_opts()) ::
              :ok | {:error, Error.t()}

  @callback get_static_credentials(name :: String.t(), opts :: aws_opts()) ::
              {:ok, credentials_result()} | {:error, Error.t()}
end
