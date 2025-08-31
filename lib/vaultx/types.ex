defmodule Vaultx.Types do
  @moduledoc """
  Comprehensive type definitions for Vaultx HashiCorp Vault client.

  This module centralizes all type definitions used throughout the Vaultx
  library, providing type safety, documentation, and consistency across
  all modules and operations.

  ## Type Categories

  ### Core Types
  Basic types used throughout the library for paths, data, and results.

  ### Structured Types
  Complex data structures representing Vault responses and operations.

  ### Engine-Specific Types
  Types specific to different Vault secret engines (KV, PKI, Transit, etc.).

  ### System Types
  Types for Vault system operations, health checks, and administration.

  ## Usage

  These types are primarily used for:
  - Function specifications (`@spec`)
  - Documentation and IDE support
  - Runtime validation where appropriate
  - Dialyzer static analysis

  ## References

  - [Vault API Documentation](https://developer.hashicorp.com/vault/api-docs)
  - [Elixir Typespecs](https://hexdocs.pm/elixir/typespecs.html)
  """

  # Core types
  @type path :: String.t()
  @type mount_path :: String.t()
  @type secret_data :: %{String.t() => term()}
  @type options :: keyword()
  @type result(success_type) :: {:ok, success_type} | {:error, Vaultx.Base.Error.t()}
  @type result :: result(term())

  # Secrets engine structured types
  defmodule SecretData do
    @moduledoc """
    Structured secret data with metadata.
    """
    @type t :: %__MODULE__{
            data: map(),
            metadata: map() | nil,
            version: pos_integer() | nil,
            created_time: DateTime.t() | nil,
            deletion_time: DateTime.t() | nil,
            destroyed: boolean()
          }

    defstruct [
      :data,
      :metadata,
      :version,
      :created_time,
      :deletion_time,
      destroyed: false
    ]
  end

  defmodule WriteResult do
    @moduledoc """
    Result of a write operation.
    """
    @type t :: %__MODULE__{
            version: pos_integer() | nil,
            created_time: DateTime.t() | nil,
            deletion_time: DateTime.t() | nil,
            destroyed: boolean()
          }

    defstruct [
      :version,
      :created_time,
      :deletion_time,
      destroyed: false
    ]
  end

  defmodule ListResult do
    @moduledoc """
    Result of a list operation.
    """
    @type t :: %__MODULE__{
            keys: [String.t()],
            metadata: map() | nil
          }

    defstruct [:keys, :metadata]
  end

  defmodule EngineMetadata do
    @moduledoc """
    Metadata about a secrets engine.
    """
    @type t :: %__MODULE__{
            type: atom(),
            version: pos_integer() | nil,
            capabilities: [atom()],
            configuration: map(),
            mount_path: String.t()
          }

    defstruct [:type, :version, :capabilities, :configuration, :mount_path]
  end

  defmodule HealthStatus do
    @moduledoc """
    Health status of an engine or system.
    """
    @type t :: %__MODULE__{
            healthy: boolean(),
            details: map(),
            timestamp: DateTime.t()
          }

    defstruct [:healthy, :details, :timestamp]
  end

  # Auth types
  @type token :: String.t()
  @type auth_result :: result(token())

  # Secrets engine types (updated for new structure)
  @type version :: pos_integer()
  @type cas_parameter :: non_neg_integer()
  @type secrets_read_result :: result(SecretData.t())
  @type secrets_write_result :: result(WriteResult.t())
  @type secrets_delete_result :: result(:ok)
  @type secrets_list_result :: result(ListResult.t())
  @type secrets_metadata_result :: result(EngineMetadata.t())
  @type secrets_health_result :: result(HealthStatus.t())

  # Legacy types (for backward compatibility)
  @type read_result :: result(secret_data())
  @type write_result :: result(:ok)
  @type delete_result :: result(:ok)
  @type list_result :: result([String.t()])

  # System types
  @type lease_id :: String.t()
  @type lease_info :: map()
  @type health_status :: map()
  @type seal_status :: map()
  @type mount_info :: map()
  @type policy_name :: String.t()
  @type policy_content :: String.t()

  # HTTP transport types
  @type http_method :: :get | :post | :put | :delete | :patch | :list
  @type headers :: [{String.t(), String.t()}]
  @type body :: map() | String.t() | nil
  @type response :: %{
          status: integer(),
          headers: headers(),
          body: term()
        }
  @type http_result :: result(response())
end
