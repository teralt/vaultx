defmodule Vaultx.Secrets.TOTP do
  @moduledoc """
  Unified TOTP secrets engine interface for HashiCorp Vault.

  This module provides a comprehensive, enterprise-grade interface for the
  TOTP (Time-based One-Time Password) secrets engine, offering dynamic
  TOTP key management, code generation, and validation capabilities.

  ## Enterprise TOTP Management

  - Dynamic Key Generation: Vault-generated TOTP keys with QR codes
  - Key Import: Import existing TOTP keys from external sources
  - Code Generation: Time-based one-time password generation
  - Code Validation: Secure TOTP code validation with skew tolerance
  - Multi-Algorithm Support: SHA1, SHA256, SHA512 algorithms
  - Flexible Configuration: Customizable periods, digits, and parameters

  ## Supported TOTP Features

  ### Key Management
  - Vault-Generated Keys: Automatic key generation with QR codes
  - Imported Keys: Support for existing TOTP URLs and raw keys
  - Multiple Algorithms: SHA1 (default), SHA256, SHA512
  - Configurable Digits: 6 or 8 digit codes
  - Custom Periods: Configurable time periods (default 30 seconds)

  ### Security Features
  - Time Skew Tolerance: Configurable skew for clock drift
  - QR Code Generation: Base64-encoded PNG QR codes
  - URL Export: Standard otpauth:// URL format
  - Secure Storage: Encrypted key storage in Vault

  ## Configuration Examples

      # Generate a new TOTP key with QR code
      config = %{
        generate: true,
        exported: true,
        issuer: "MyApp",
        account_name: "user@example.com",
        algorithm: "SHA256",
        digits: 6,
        period: 30,
        qr_size: 200
      }
      {:ok, response} = TOTP.create_key("user-key", config)

      # Import an existing TOTP key
      config = %{
        url: "otpauth://totp/Google:test@gmail.com?secret=Y64VEVMBTSXCYIWRSHRNDZW62MPGVU2G&issuer=Google"
      }
      {:ok, _} = TOTP.create_key("imported-key", config)

      # Generate and validate codes
      {:ok, code} = TOTP.generate_code("user-key")
      {:ok, result} = TOTP.validate_code("user-key", code.code)

  ## API Compliance

  Fully implements HashiCorp Vault TOTP secrets engine:
  - [TOTP Secrets Engine API](https://developer.hashicorp.com/vault/api-docs/secret/totp)
  - [RFC 6238 - TOTP Algorithm](https://tools.ietf.org/html/rfc6238)

  """

  alias Vaultx.Base.{Error, Logger, Telemetry}
  alias Vaultx.Secrets.TOTP.Behaviour
  alias Vaultx.Transport.HTTP

  @behaviour Behaviour

  @default_mount_path "totp"

  # Key Management Operations

  @doc """
  Create or update a TOTP key.

  Creates a new TOTP key definition that can be used to generate
  time-based one-time passwords. Supports both Vault-generated keys
  and imported keys from external sources.

  ## Parameters

  - `name` - Key name
  - `config` - Key configuration
  - `opts` - Request options including mount path

  ## Examples

      # Generate a new key with QR code
      config = %{
        generate: true,
        exported: true,
        issuer: "MyApp",
        account_name: "user@example.com",
        algorithm: "SHA256",
        digits: 6,
        period: 30,
        qr_size: 200
      }
      {:ok, response} = TOTP.create_key("user-key", config)

      # Import existing key from URL
      config = %{
        url: "otpauth://totp/Google:test@gmail.com?secret=Y64VEVMBTSXCYIWRSHRNDZW62MPGVU2G&issuer=Google"
      }
      {:ok, _} = TOTP.create_key("imported-key", config)

      # Import raw key
      config = %{
        key: "Y64VEVMBTSXCYIWRSHRNDZW62MPGVU2G",
        issuer: "MyApp",
        account_name: "user@example.com"
      }
      {:ok, _} = TOTP.create_key("raw-key", config)

  """
  @impl Behaviour
  def create_key(name, config, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    telemetry_metadata = %{
      operation: :create_key,
      key_name: name,
      mount_path: mount_path,
      generate: Map.get(config, :generate, false)
    }

    start_time = System.monotonic_time()

    Telemetry.operation_start(telemetry_metadata)

    Logger.info("Creating TOTP key", %{
      key_name: name,
      mount_path: mount_path,
      generate: Map.get(config, :generate, false),
      issuer: Map.get(config, :issuer),
      account_name: Map.get(config, :account_name)
    })

    path = "/#{mount_path}/keys/#{name}"

    case HTTP.post(path, config, opts) do
      {:ok, %{status: status, body: %{"data" => data}}} when status in [200, 204] ->
        response = %{
          barcode: Map.get(data, "barcode"),
          url: Map.get(data, "url")
        }

        Logger.info("Successfully created TOTP key", %{
          key_name: name,
          mount_path: mount_path,
          has_qr_code: not is_nil(response.barcode)
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_success(duration, telemetry_metadata)
        {:ok, response}

      {:ok, %{status: status}} when status in [200, 204] ->
        # Handle case where no data is returned
        Logger.info("Successfully created TOTP key", %{
          key_name: name,
          mount_path: mount_path
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_success(duration, telemetry_metadata)
        {:ok, %{}}

      {:ok, response} ->
        error = Error.from_http_response(response.status, response.body)

        Logger.error("Failed to create TOTP key", %{
          key_name: name,
          error: error
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}

      {:error, reason} ->
        error = Error.new(:http_error, "HTTP request failed", details: %{reason: reason})

        Logger.error("HTTP error creating TOTP key", %{
          key_name: name,
          error: error
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_failure(duration, Map.put(telemetry_metadata, :error, error))
        {:error, error}
    end
  end

  @doc """
  Read a TOTP key configuration.

  ## Examples

      {:ok, info} = TOTP.read_key("user-key")
      %{
        account_name: "user@example.com",
        algorithm: "SHA1",
        digits: 6,
        issuer: "MyApp",
        period: 30
      }

  """
  @impl Behaviour
  def read_key(name, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    path = "/#{mount_path}/keys/#{name}"

    case HTTP.get(path, opts) do
      {:ok, %{status: 200, body: %{"data" => data}}} ->
        key_info = %{
          account_name: Map.get(data, "account_name", ""),
          algorithm: Map.get(data, "algorithm", "SHA1"),
          digits: Map.get(data, "digits", 6),
          issuer: Map.get(data, "issuer", ""),
          period: Map.get(data, "period", 30)
        }

        {:ok, key_info}

      {:ok, response} ->
        {:error, Error.from_http_response(response.status, response.body)}

      {:error, reason} ->
        {:error, Error.new(:http_error, "HTTP request failed", details: %{reason: reason})}
    end
  end

  @doc """
  List all configured TOTP keys.

  ## Examples

      {:ok, keys} = TOTP.list_keys()
      ["user-key", "admin-key", "service-key"]

  """
  @impl Behaviour
  def list_keys(opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    path = "/#{mount_path}/keys"

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
  Delete a TOTP key.

  ## Examples

      :ok = TOTP.delete_key("old-key")

  """
  @impl Behaviour
  def delete_key(name, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    telemetry_metadata = %{
      operation: :delete_key,
      key_name: name,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()

    Telemetry.operation_start(telemetry_metadata)

    path = "/#{mount_path}/keys/#{name}"

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
  Generate a TOTP code for a key.

  Generates a new time-based one-time password based on the named key.
  The code is valid for the period configured in the key definition.

  ## Parameters

  - `name` - Key name to generate code for
  - `opts` - Request options

  ## Returns

  - `{:ok, code}` - Successfully generated code
  - `{:error, error}` - Failed to generate code

  ## Examples

      {:ok, code} = TOTP.generate_code("user-key")
      %{
        code: "810920"
      }

  """
  @impl Behaviour
  def generate_code(name, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    telemetry_metadata = %{
      operation: :generate_code,
      key_name: name,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()

    Telemetry.operation_start(telemetry_metadata)

    Logger.info("Generating TOTP code", %{
      key_name: name,
      mount_path: mount_path
    })

    path = "/#{mount_path}/code/#{name}"

    case HTTP.get(path, opts) do
      {:ok, %{status: 200, body: %{"data" => data}}} ->
        code = %{
          code: Map.get(data, "code")
        }

        Logger.info("Successfully generated TOTP code", %{
          key_name: name,
          mount_path: mount_path
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_success(duration, telemetry_metadata)
        {:ok, code}

      {:ok, response} ->
        error = Error.from_http_response(response.status, response.body)

        Logger.error("Failed to generate TOTP code", %{
          key_name: name,
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
  Validate a TOTP code against a key.

  Validates a time-based one-time password generated from the named key.
  Takes into account the configured skew tolerance for clock drift.

  ## Parameters

  - `name` - Key name to validate against
  - `code` - TOTP code to validate
  - `opts` - Request options

  ## Returns

  - `{:ok, result}` - Successfully validated code
  - `{:error, error}` - Failed to validate code

  ## Examples

      {:ok, result} = TOTP.validate_code("user-key", "123456")
      %{
        valid: true
      }

  """
  @impl Behaviour
  def validate_code(name, code, opts \\ []) do
    mount_path = Keyword.get(opts, :mount_path, @default_mount_path)

    telemetry_metadata = %{
      operation: :validate_code,
      key_name: name,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()

    Telemetry.operation_start(telemetry_metadata)

    Logger.info("Validating TOTP code", %{
      key_name: name,
      mount_path: mount_path
    })

    path = "/#{mount_path}/code/#{name}"
    payload = %{code: code}

    case HTTP.post(path, payload, opts) do
      {:ok, %{status: 200, body: %{"data" => data}}} ->
        result = %{
          valid: Map.get(data, "valid", false)
        }

        Logger.info("Successfully validated TOTP code", %{
          key_name: name,
          mount_path: mount_path,
          valid: result.valid
        })

        duration = System.monotonic_time() - start_time
        Telemetry.operation_success(duration, telemetry_metadata)
        {:ok, result}

      {:ok, response} ->
        error = Error.from_http_response(response.status, response.body)

        Logger.error("Failed to validate TOTP code", %{
          key_name: name,
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
