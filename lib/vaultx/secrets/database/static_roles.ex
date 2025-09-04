defmodule Vaultx.Secrets.Database.StaticRoles do
  @moduledoc """
  Static role management operations for Database secrets engine.

  This module contains all static role related operations that are mixed into
  the main Database module. Static roles provide automatic credential rotation
  for existing database users.

  ## Static Role Features

  - Automatic password rotation based on schedules or periods
  - Support for existing database users
  - Configurable rotation statements
  - Manual rotation triggers
  - Multiple credential types (password, RSA keys, client certificates)

  """

  alias Vaultx.Base.{Error, Logger, Telemetry}
  alias Vaultx.Transport.HTTP

  @default_mount_path "database"

  @doc """
  Create or update a static database role.

  Configures a static role that maps to an existing database user.
  Static roles are automatically rotated based on configured schedules.

  ## Parameters

  - `name` - Static role name
  - `config` - Static role configuration parameters
  - `opts` - Request options

  ## Examples

      # Static role with rotation period
      config = %{
        db_name: "mysql",
        username: "static-database-user",
        rotation_statements: [
          "ALTER USER \"{{name}}\" IDENTIFIED BY '{{password}}';"
        ],
        rotation_period: 3600
      }
      :ok = Database.create_static_role("static-user", config)

      # Static role with rotation schedule
      config = %{
        db_name: "mysql",
        username: "static-database-user",
        rotation_statements: [
          "ALTER USER \"{{name}}\" IDENTIFIED BY '{{password}}';"
        ],
        rotation_schedule: "0 0 * * SAT",
        rotation_window: 3600
      }

  """
  def create_static_role(name, config, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    telemetry_metadata = %{
      operation: :create_static_role,
      role_name: name,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()

    Telemetry.operation_start(telemetry_metadata)

    Logger.info("Creating static database role", %{
      role_name: name,
      mount_path: mount_path,
      db_name: Map.get(config, :db_name),
      username: Map.get(config, :username),
      credential_type: Map.get(config, :credential_type, "password")
    })

    path = "/#{mount_path}/static-roles/#{name}"

    case HTTP.post(path, config, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        Logger.info("Successfully created static database role", %{
          role_name: name,
          mount_path: mount_path
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_success(duration, telemetry_metadata)
        :ok

      {:ok, response} ->
        error = Error.from_http_response(response.status, response.body)

        Logger.error("Failed to create static database role", %{
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
  Read a static database role configuration.

  ## Examples

      {:ok, config} = Database.read_static_role("static-user")
      %{
        credential_type: "password",
        db_name: "mysql",
        username: "static-user",
        rotation_statements: [
          "ALTER USER \"{{name}}\" IDENTIFIED BY '{{password}}';"
        ],
        rotation_period: 3600,
        skip_import_rotation: false
      }

  """
  def read_static_role(name, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    path = "/#{mount_path}/static-roles/#{name}"

    case HTTP.get(path, opts) do
      {:ok, %{status: 200, body: %{"data" => data}}} ->
        config = %{
          credential_type: Map.get(data, "credential_type", "password"),
          credential_config: Map.get(data, "credential_config", %{}),
          db_name: Map.get(data, "db_name"),
          username: Map.get(data, "username"),
          rotation_statements: Map.get(data, "rotation_statements", []),
          rotation_period: Map.get(data, "rotation_period"),
          rotation_schedule: Map.get(data, "rotation_schedule"),
          rotation_window: Map.get(data, "rotation_window"),
          skip_import_rotation: Map.get(data, "skip_import_rotation", false)
        }

        {:ok, config}

      {:ok, response} ->
        {:error, Error.from_http_response(response.status, response.body)}

      {:error, reason} ->
        {:error, Error.new(:http_error, "HTTP request failed", details: %{reason: reason})}
    end
  end

  @doc """
  List all configured static database roles.

  ## Examples

      {:ok, roles} = Database.list_static_roles()
      ["static-user1", "static-user2", "admin-static"]

  """
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
  Delete a static database role.

  ## Examples

      :ok = Database.delete_static_role("old-static-role")

  """
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
  Get current credentials for a static database role.

  ## Examples

      {:ok, creds} = Database.get_static_credentials("static-user")
      %{
        username: "static-user",
        password: "132ae3ef-5a64-7499-351e-bfe59f3a2a21",
        last_vault_rotation: "2019-05-06T15:26:42.525302-05:00",
        rotation_period: 30,
        ttl: 28
      }

  """
  def get_static_credentials(name, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    telemetry_metadata = %{
      operation: :get_static_credentials,
      role_name: name,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()

    Telemetry.operation_start(telemetry_metadata)

    path = "/#{mount_path}/static-creds/#{name}"

    case HTTP.get(path, opts) do
      {:ok, %{status: 200, body: %{"data" => data}}} ->
        credentials = %{
          username: Map.get(data, "username"),
          password: Map.get(data, "password"),
          last_vault_rotation: Map.get(data, "last_vault_rotation"),
          ttl: Map.get(data, "ttl"),
          rotation_period: Map.get(data, "rotation_period"),
          rotation_schedule: Map.get(data, "rotation_schedule"),
          rotation_window: Map.get(data, "rotation_window")
        }

        duration = System.monotonic_time() - start_time
        Telemetry.operation_success(duration, telemetry_metadata)
        {:ok, credentials}

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
  Manually rotate credentials for a static database role.

  ## Examples

      :ok = Database.rotate_static_role_credentials("static-user")

  """
  def rotate_static_role_credentials(name, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    telemetry_metadata = %{
      operation: :rotate_static_role_credentials,
      role_name: name,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()

    Telemetry.operation_start(telemetry_metadata)

    Logger.info("Rotating static role credentials", %{
      role_name: name,
      mount_path: mount_path
    })

    path = "/#{mount_path}/rotate-role/#{name}"

    case HTTP.post(path, %{}, opts) do
      {:ok, %{status: status}} when status in [200, 204] ->
        Logger.info("Successfully rotated static role credentials", %{
          role_name: name,
          mount_path: mount_path
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_success(duration, telemetry_metadata)
        :ok

      {:ok, response} ->
        error = Error.from_http_response(response.status, response.body)

        Logger.error("Failed to rotate static role credentials", %{
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
end
