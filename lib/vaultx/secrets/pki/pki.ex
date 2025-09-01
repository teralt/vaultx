defmodule Vaultx.Secrets.PKI do
  @moduledoc """
  Comprehensive Public Key Infrastructure (PKI) secrets engine for HashiCorp Vault.

  This module provides a unified interface for enterprise PKI operations,
  including certificate authority management, certificate issuance, role-based
  access control, and complete certificate lifecycle management. It supports
  both root and intermediate CA operations with industry-standard compliance.

  ## Enterprise PKI Capabilities

  ### Certificate Authority Management
  - Generate and manage root CA certificates
  - Create and sign intermediate CA certificates
  - Import existing CA certificates and private keys
  - Manage complex CA hierarchies and trust chains
  - Cross-sign certificates between different authorities

  ## API Compliance

  Fully implements HashiCorp Vault PKI secrets engine:
  - [PKI Secrets Engine](https://developer.hashicorp.com/vault/api-docs/secret/pki)
  - [PKI Certificate Management](https://developer.hashicorp.com/vault/docs/secrets/pki)

  ### Certificate Issuance and Management
  - Issue certificates based on roles
  - Sign certificate signing requests (CSRs)
  - Revoke certificates and manage CRLs
  - Certificate renewal and lifecycle management

  ### Role-Based Certificate Policies
  - Create and manage certificate roles
  - Define domain and naming constraints
  - Configure certificate validity periods
  - Set key usage and extended key usage policies

  ### Advanced PKI Features
  - Multiple issuer support (Vault 1.11+)
  - Certificate transparency integration
  - ACME protocol support for automated certificate management
  - Certificate monitoring and alerting

  ## Usage Examples

      # Generate a root CA
      {:ok, ca} = PKI.generate_root(%{
        common_name: "Example Root CA",
        ttl: "10y"
      })

      # Create a certificate role
      :ok = PKI.create_role("web-server", %{
        allowed_domains: ["example.com"],
        allow_subdomains: true,
        max_ttl: "90d"
      })

      # Issue a certificate
      {:ok, cert} = PKI.issue_certificate("web-server", %{
        common_name: "www.example.com",
        ttl: "30d"
      })

      # Revoke a certificate
      :ok = PKI.revoke_certificate("39:dd:2e:90:b7:23:1f:8d")

  ## Configuration

  PKI operations support various configuration options:

  ### Engine Options
  - `:mount_path` - PKI engine mount path (default: "pki")
  - `:timeout` - Request timeout in milliseconds
  - `:issuer_ref` - Reference to specific issuer (for multi-issuer setups)

  ### Certificate Options
  - `:common_name` - Certificate common name
  - `:alt_names` - Subject alternative names
  - `:ip_sans` - IP address SANs
  - `:uri_sans` - URI SANs
  - `:ttl` - Certificate time-to-live
  - `:format` - Certificate format ("pem", "der", "pem_bundle")

  ## Security Best Practices

  ### CA Security
  - Use offline root CAs when possible
  - Implement proper access controls for CA operations
  - Regular backup and secure storage of CA keys
  - Use hardware security modules (HSMs) for key protection

  ### Certificate Management
  - Implement proper certificate validation
  - Use appropriate certificate validity periods
  - Enable certificate revocation checking
  - Monitor certificate expiration and renewal

  ### Access Control
  - Restrict access to sensitive PKI operations
  - Implement role-based access controls
  - Audit all certificate issuance and revocation
  - Use approval workflows for critical operations

  """

  alias Vaultx.Base.{Error, Logger, Telemetry}
  alias Vaultx.Secrets.PKI.{CA, Certificates}
  alias Vaultx.Transport.HTTP

  @behaviour Vaultx.Secrets.PKI.Behaviour

  @default_mount_path "pki"
  @default_timeout 30_000

  # Certificate Authority Operations

  @impl true
  def generate_root(opts \\ %{}, pki_opts \\ []) do
    CA.generate_root(opts, pki_opts)
  end

  @impl true
  def generate_intermediate(opts \\ %{}, pki_opts \\ []) do
    CA.generate_intermediate(opts, pki_opts)
  end

  @impl true
  def import_ca(certificate, private_key, pki_opts \\ []) do
    CA.import_ca(certificate, private_key, pki_opts)
  end

  @impl true
  def read_ca_certificate(pki_opts \\ []) do
    CA.read_ca_certificate(pki_opts)
  end

  @impl true
  def read_ca_chain(pki_opts \\ []) do
    CA.read_ca_chain(pki_opts)
  end

  # Certificate Issuance Operations

  @impl true
  def issue_certificate(role_name, opts \\ %{}, pki_opts \\ []) do
    Certificates.issue(role_name, opts, pki_opts)
  end

  @impl true
  def sign_certificate(role_name, csr, opts \\ %{}, pki_opts \\ []) do
    Certificates.sign(role_name, csr, opts, pki_opts)
  end

  @impl true
  def sign_intermediate(csr, opts \\ %{}, pki_opts \\ []) do
    CA.sign_intermediate(csr, opts, pki_opts)
  end

  @impl true
  def sign_self_issued(certificate, opts \\ %{}, pki_opts \\ []) do
    # This would be implemented for self-issued certificate signing
    # For now, delegate to sign_verbatim with the certificate as CSR
    sign_verbatim(certificate, opts, pki_opts)
  end

  @impl true
  def sign_verbatim(csr, opts \\ %{}, pki_opts \\ []) do
    Certificates.sign_verbatim(csr, opts, pki_opts)
  end

  # Certificate Management Operations

  @impl true
  def read_certificate(serial_number, pki_opts \\ []) do
    Certificates.read(serial_number, pki_opts)
  end

  @impl true
  def list_certificates(pki_opts \\ []) do
    Certificates.list(pki_opts)
  end

  @impl true
  def revoke_certificate(serial_number, pki_opts \\ []) do
    Certificates.revoke(serial_number, pki_opts)
  end

  @impl true
  def revoke_certificate_with_key(certificate, private_key, pki_opts \\ []) do
    Certificates.revoke_with_key(certificate, private_key, pki_opts)
  end

  # Role Management Operations

  @impl true
  def create_role(name, opts \\ %{}, pki_opts \\ []) do
    mount_path = Keyword.get(pki_opts, :mount_path, @default_mount_path)
    timeout = Keyword.get(pki_opts, :timeout, @default_timeout)

    url = "/v1/#{mount_path}/roles/#{name}"
    payload = build_role_payload(opts)

    metadata = %{
      operation: :create_role,
      mount_path: mount_path,
      role_name: name
    }

    start_time = System.monotonic_time()
    Logger.debug("Creating PKI role", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.post(url, payload, timeout: timeout) do
      {:ok, %{status: 204}} ->
        duration = System.monotonic_time() - start_time

        Logger.info("PKI role created successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        :ok

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warn("PKI role creation failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:network_error, "Failed to create PKI role: #{inspect(reason)}")

        Logger.error("PKI role creation request failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @impl true
  def read_role(name, pki_opts \\ []) do
    mount_path = Keyword.get(pki_opts, :mount_path, @default_mount_path)
    timeout = Keyword.get(pki_opts, :timeout, @default_timeout)

    url = "/v1/#{mount_path}/roles/#{name}"

    metadata = %{
      operation: :read_role,
      mount_path: mount_path,
      role_name: name
    }

    start_time = System.monotonic_time()
    Logger.debug("Reading PKI role", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.get(url, timeout: timeout) do
      {:ok, %{status: 200, body: body}} ->
        duration = System.monotonic_time() - start_time
        role_info = parse_role_response(body, name)

        Logger.debug("PKI role read successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, role_info}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warn("PKI role read failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:network_error, "Failed to read PKI role: #{inspect(reason)}")

        Logger.error("PKI role read request failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @impl true
  def update_role(name, opts \\ %{}, pki_opts \\ []) do
    # Update role uses the same endpoint as create role
    create_role(name, opts, pki_opts)
  end

  @impl true
  def delete_role(name, pki_opts \\ []) do
    mount_path = Keyword.get(pki_opts, :mount_path, @default_mount_path)
    timeout = Keyword.get(pki_opts, :timeout, @default_timeout)

    url = "/v1/#{mount_path}/roles/#{name}"

    metadata = %{
      operation: :delete_role,
      mount_path: mount_path,
      role_name: name
    }

    start_time = System.monotonic_time()
    Logger.debug("Deleting PKI role", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.delete(url, timeout: timeout) do
      {:ok, %{status: 204}} ->
        duration = System.monotonic_time() - start_time

        Logger.info("PKI role deleted successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        :ok

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warn("PKI role deletion failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:network_error, "Failed to delete PKI role: #{inspect(reason)}")

        Logger.error("PKI role deletion request failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @impl true
  def list_roles(pki_opts \\ []) do
    mount_path = Keyword.get(pki_opts, :mount_path, @default_mount_path)
    timeout = Keyword.get(pki_opts, :timeout, @default_timeout)

    url = "/v1/#{mount_path}/roles?list=true"

    metadata = %{
      operation: :list_roles,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()
    Logger.debug("Listing PKI roles", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.get(url, timeout: timeout) do
      {:ok, %{status: 200, body: body}} ->
        duration = System.monotonic_time() - start_time

        roles =
          case get_in(body, ["data", "keys"]) do
            list when is_list(list) -> list
            _ -> []
          end

        Logger.debug("PKI roles listed successfully", Map.put(metadata, :count, length(roles)))
        Telemetry.operation_success(duration, Map.put(metadata, :count, length(roles)))

        {:ok, roles}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warn("PKI role listing failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:network_error, "Failed to list PKI roles: #{inspect(reason)}")

        Logger.error("PKI role listing request failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  # Private helper functions

  defp build_role_payload(opts) do
    opts
    |> Enum.reduce(%{}, &build_role_option/2)
  end

  defp build_role_option({:allowed_domains, value}, acc) when is_list(value),
    do: Map.put(acc, "allowed_domains", value)

  defp build_role_option({:allow_subdomains, value}, acc) when is_boolean(value),
    do: Map.put(acc, "allow_subdomains", value)

  defp build_role_option({:allow_any_name, value}, acc) when is_boolean(value),
    do: Map.put(acc, "allow_any_name", value)

  defp build_role_option({:allow_bare_domains, value}, acc) when is_boolean(value),
    do: Map.put(acc, "allow_bare_domains", value)

  defp build_role_option({:allow_localhost, value}, acc) when is_boolean(value),
    do: Map.put(acc, "allow_localhost", value)

  defp build_role_option({:allow_ip_sans, value}, acc) when is_boolean(value),
    do: Map.put(acc, "allow_ip_sans", value)

  defp build_role_option({:key_type, value}, acc) when is_binary(value),
    do: Map.put(acc, "key_type", value)

  defp build_role_option({:key_bits, value}, acc) when is_integer(value),
    do: Map.put(acc, "key_bits", value)

  defp build_role_option({:max_ttl, value}, acc) when is_binary(value),
    do: Map.put(acc, "max_ttl", value)

  defp build_role_option({:ttl, value}, acc) when is_binary(value), do: Map.put(acc, "ttl", value)

  defp build_role_option({:server_flag, value}, acc) when is_boolean(value),
    do: Map.put(acc, "server_flag", value)

  defp build_role_option({:client_flag, value}, acc) when is_boolean(value),
    do: Map.put(acc, "client_flag", value)

  defp build_role_option({:code_signing_flag, value}, acc) when is_boolean(value),
    do: Map.put(acc, "code_signing_flag", value)

  defp build_role_option({:email_protection_flag, value}, acc) when is_boolean(value),
    do: Map.put(acc, "email_protection_flag", value)

  defp build_role_option(_other, acc), do: acc

  defp parse_role_response(body, name) when is_map(body) do
    data = Map.get(body, "data", %{})

    %{
      name: name,
      allowed_domains: Map.get(data, "allowed_domains", []),
      allow_subdomains: Map.get(data, "allow_subdomains", false),
      allow_any_name: Map.get(data, "allow_any_name", false),
      key_type: Map.get(data, "key_type", "rsa"),
      key_bits: Map.get(data, "key_bits", 2048),
      max_ttl: Map.get(data, "max_ttl", ""),
      ttl: Map.get(data, "ttl", ""),
      server_flag: Map.get(data, "server_flag", false),
      client_flag: Map.get(data, "client_flag", false)
    }
  end

  defp parse_role_response(_, name), do: %{name: name}

  # CRL Operations

  @impl true
  def read_crl(pki_opts \\ []) do
    mount_path = Keyword.get(pki_opts, :mount_path, @default_mount_path)
    timeout = Keyword.get(pki_opts, :timeout, @default_timeout)

    url = "/v1/#{mount_path}/crl/pem"

    metadata = %{
      operation: :read_crl,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()
    Logger.debug("Reading CRL", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.get(url, timeout: timeout) do
      {:ok, %{status: 200, body: body}} when is_binary(body) ->
        duration = System.monotonic_time() - start_time

        Logger.debug("CRL read successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, body}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warn("CRL read failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:network_error, "Failed to read CRL: #{inspect(reason)}")

        Logger.error("CRL read request failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @impl true
  def rotate_crl(pki_opts \\ []) do
    mount_path = Keyword.get(pki_opts, :mount_path, @default_mount_path)
    timeout = Keyword.get(pki_opts, :timeout, @default_timeout)

    url = "/v1/#{mount_path}/crl/rotate"

    metadata = %{
      operation: :rotate_crl,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()
    Logger.debug("Rotating CRL", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.get(url, timeout: timeout) do
      {:ok, %{status: 200}} ->
        duration = System.monotonic_time() - start_time

        Logger.info("CRL rotated successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        :ok

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warn("CRL rotation failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:network_error, "Failed to rotate CRL: #{inspect(reason)}")

        Logger.error("CRL rotation request failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  # Configuration Operations

  @impl true
  def read_urls(pki_opts \\ []) do
    mount_path = Keyword.get(pki_opts, :mount_path, @default_mount_path)
    timeout = Keyword.get(pki_opts, :timeout, @default_timeout)

    url = "/v1/#{mount_path}/config/urls"

    metadata = %{
      operation: :read_urls,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()
    Logger.debug("Reading PKI URLs configuration", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.get(url, timeout: timeout) do
      {:ok, %{status: 200, body: body}} ->
        duration = System.monotonic_time() - start_time
        config = Map.get(body, "data", %{})

        Logger.debug("PKI URLs configuration read successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, config}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warn("PKI URLs configuration read failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:network_error, "Failed to read PKI URLs configuration: #{inspect(reason)}")

        Logger.error(
          "PKI URLs configuration read request failed",
          Map.put(metadata, :error, error)
        )

        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @impl true
  def write_urls(config, pki_opts \\ []) do
    mount_path = Keyword.get(pki_opts, :mount_path, @default_mount_path)
    timeout = Keyword.get(pki_opts, :timeout, @default_timeout)

    url = "/v1/#{mount_path}/config/urls"

    metadata = %{
      operation: :write_urls,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()
    Logger.debug("Writing PKI URLs configuration", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.post(url, config, timeout: timeout) do
      {:ok, %{status: 204}} ->
        duration = System.monotonic_time() - start_time

        Logger.info("PKI URLs configuration written successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        :ok

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warn("PKI URLs configuration write failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:network_error, "Failed to write PKI URLs configuration: #{inspect(reason)}")

        Logger.error(
          "PKI URLs configuration write request failed",
          Map.put(metadata, :error, error)
        )

        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  # Maintenance Operations

  @impl true
  def tidy(opts \\ [], pki_opts \\ []) do
    mount_path = Keyword.get(pki_opts, :mount_path, @default_mount_path)
    timeout = Keyword.get(pki_opts, :timeout, @default_timeout)

    url = "/v1/#{mount_path}/tidy"
    payload = build_tidy_payload(opts)

    metadata = %{
      operation: :tidy,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()
    Logger.debug("Starting PKI tidy operation", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.post(url, payload, timeout: timeout) do
      {:ok, %{status: 202}} ->
        duration = System.monotonic_time() - start_time

        Logger.info("PKI tidy operation started successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        :ok

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warn("PKI tidy operation failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:network_error, "Failed to start PKI tidy operation: #{inspect(reason)}")

        Logger.error("PKI tidy operation request failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @impl true
  def tidy_status(pki_opts \\ []) do
    mount_path = Keyword.get(pki_opts, :mount_path, @default_mount_path)
    timeout = Keyword.get(pki_opts, :timeout, @default_timeout)

    url = "/v1/#{mount_path}/tidy-status"

    metadata = %{
      operation: :tidy_status,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()
    Logger.debug("Checking PKI tidy status", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.get(url, timeout: timeout) do
      {:ok, %{status: 200, body: body}} ->
        duration = System.monotonic_time() - start_time
        status = Map.get(body, "data", %{})

        Logger.debug("PKI tidy status retrieved successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, status}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warn("PKI tidy status check failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:network_error, "Failed to check PKI tidy status: #{inspect(reason)}")

        Logger.error("PKI tidy status check request failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @impl true
  def tidy_cancel(pki_opts \\ []) do
    mount_path = Keyword.get(pki_opts, :mount_path, @default_mount_path)
    timeout = Keyword.get(pki_opts, :timeout, @default_timeout)

    url = "/v1/#{mount_path}/tidy-cancel"

    metadata = %{
      operation: :tidy_cancel,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()
    Logger.debug("Cancelling PKI tidy operation", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.post(url, %{}, timeout: timeout) do
      {:ok, %{status: 200}} ->
        duration = System.monotonic_time() - start_time

        Logger.info("PKI tidy operation cancelled successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        :ok

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warn("PKI tidy operation cancellation failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:network_error, "Failed to cancel PKI tidy operation: #{inspect(reason)}")

        Logger.error(
          "PKI tidy operation cancellation request failed",
          Map.put(metadata, :error, error)
        )

        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  # Additional private helper functions

  defp build_tidy_payload(opts) do
    opts
    |> Enum.reduce(%{}, &build_tidy_option/2)
  end

  defp build_tidy_option({:tidy_cert_store, value}, acc) when is_boolean(value),
    do: Map.put(acc, "tidy_cert_store", value)

  defp build_tidy_option({:tidy_revoked_certs, value}, acc) when is_boolean(value),
    do: Map.put(acc, "tidy_revoked_certs", value)

  defp build_tidy_option({:safety_buffer, value}, acc) when is_binary(value),
    do: Map.put(acc, "safety_buffer", value)

  defp build_tidy_option(_other, acc), do: acc
end
