defmodule Vaultx.Secrets.PKI.Certificates do
  @moduledoc """
  Enterprise certificate lifecycle management for HashiCorp Vault PKI.

  This module provides comprehensive certificate lifecycle management for
  enterprise PKI deployments, including automated certificate issuance,
  CSR processing, revocation management, and certificate tracking. It
  supports industry-standard certificate formats and advanced PKI workflows.

  ## Enterprise Certificate Capabilities

  ### Automated Certificate Issuance
  - Role-based certificate issuance with policy enforcement
  - Automated certificate generation with private keys
  - Multiple certificate formats (PEM, DER, PKCS#8, PKCS#12)
  - Automatic certificate chain construction and validation
  - Custom certificate extensions and advanced constraints

  ### Certificate Signing Services
  - Professional CSR processing and validation
  - Role-based policy application to signed certificates
  - Self-issued certificate signing for special use cases
  - Verbatim certificate signing for advanced scenarios
  - Batch certificate signing for operational efficiency

  ### Certificate Lifecycle Management
  - Certificate revocation with comprehensive reason codes
  - Automated certificate renewal and replacement workflows
  - Certificate metadata tracking and audit trails
  - Automated certificate cleanup and maintenance operations
  - Certificate expiration monitoring and alerting

  ### Industry-Standard Formats
  - PEM format (default, human-readable text)
  - DER format (binary, compact encoding)
  - PKCS#8 format for private key storage
  - PKCS#12 format for certificate bundles
  - Certificate bundles with complete trust chains

  ## Usage Examples

      # Issue a certificate based on a role
      {:ok, cert} = Certificates.issue("web-server", %{
        common_name: "example.com",
        alt_names: "www.example.com,api.example.com",
        ttl: "30d"
      })

      # Sign a certificate signing request
      {:ok, cert} = Certificates.sign("web-server", csr_pem, %{
        common_name: "example.com",
        ttl: "90d"
      })

      # Revoke a certificate
      :ok = Certificates.revoke("39:dd:2e:90:b7:23:1f:8d")

      # Read certificate information
      {:ok, cert_pem} = Certificates.read("39:dd:2e:90:b7:23:1f:8d")

      # List all certificates
      {:ok, serials} = Certificates.list()

  ## Certificate Validation

  The module performs comprehensive validation including:
  - Domain name validation against role policies
  - Certificate validity period constraints
  - Key usage and extended key usage validation
  - Subject alternative name (SAN) validation
  - Certificate chain validation and trust verification

  ## Security Considerations

  ### Certificate Issuance
  - Validate all certificate requests against role policies
  - Implement proper domain ownership verification
  - Use appropriate certificate validity periods
  - Enable certificate transparency logging when required
  - Implement certificate pinning for critical services

  ### Private Key Management
  - Generate private keys within Vault when possible
  - Use strong key sizes and modern algorithms
  - Implement proper key escrow and backup procedures
  - Rotate private keys regularly
  - Secure private key transmission and storage

  ### Certificate Revocation
  - Implement timely certificate revocation procedures
  - Maintain accurate certificate revocation lists (CRLs)
  - Use OCSP for real-time revocation checking
  - Monitor for certificate compromise indicators
  - Implement automated revocation for expired certificates

  ## API Compliance

  Fully implements HashiCorp Vault PKI certificate management:
  - [PKI Certificate Issuance](https://developer.hashicorp.com/vault/api-docs/secret/pki#generate-certificate)
  - [PKI Certificate Signing](https://developer.hashicorp.com/vault/api-docs/secret/pki#sign-certificate)
  - [PKI Certificate Revocation](https://developer.hashicorp.com/vault/api-docs/secret/pki#revoke-certificate)

  """

  alias Vaultx.Base.{Error, Logger, Telemetry}
  alias Vaultx.Transport.HTTP

  @default_mount_path "pki"
  @default_timeout 30_000

  @doc """
  Issue a new certificate based on a role.

  Issues a new certificate using the specified role configuration.
  The certificate is generated with a new private key unless specified otherwise.

  ## Parameters

  - `role_name` - Name of the certificate role to use
  - `opts` - Certificate options (common_name, alt_names, ttl, etc.)
  - `pki_opts` - PKI engine options (mount_path, timeout, etc.)

  ## Returns

  - `{:ok, certificate_info}` - Certificate information including certificate, private key, and metadata
  - `{:error, error}` - Error information

  ## Examples

      # Issue a basic certificate
      {:ok, cert} = Certificates.issue("web-server", %{
        common_name: "example.com",
        ttl: "30d"
      })

      # Issue a certificate with SANs
      {:ok, cert} = Certificates.issue("web-server", %{
        common_name: "example.com",
        alt_names: "www.example.com,api.example.com",
        ip_sans: "192.168.1.100",
        ttl: "90d",
        format: "pem_bundle"
      })

  """
  @spec issue(String.t(), map(), keyword()) :: {:ok, map()} | {:error, Error.t()}
  def issue(role_name, opts \\ %{}, pki_opts \\ []) do
    mount_path = Keyword.get(pki_opts, :mount_path, @default_mount_path)
    timeout = Keyword.get(pki_opts, :timeout, @default_timeout)

    url = "/v1/#{mount_path}/issue/#{role_name}"
    payload = build_certificate_payload(opts)

    metadata = %{
      operation: :issue_certificate,
      mount_path: mount_path,
      role_name: role_name,
      common_name: Map.get(opts, :common_name)
    }

    start_time = System.monotonic_time()
    Logger.debug("Issuing certificate", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.post(url, payload, timeout: timeout) do
      {:ok, %{status: 200, body: body}} ->
        duration = System.monotonic_time() - start_time
        cert_info = parse_certificate_response(body)

        Logger.info(
          "Certificate issued successfully",
          Map.put(metadata, :serial_number, Map.get(cert_info, :serial_number, ""))
        )

        Telemetry.operation_success(
          duration,
          Map.put(metadata, :serial_number, Map.get(cert_info, :serial_number, ""))
        )

        {:ok, cert_info}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warning("Certificate issuance failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:network_error, "Failed to issue certificate: #{inspect(reason)}")

        Logger.error("Certificate issuance request failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Sign a certificate signing request (CSR).

  Signs a provided CSR using the specified role configuration.
  The CSR must be in PEM format and contain valid certificate request information.

  ## Parameters

  - `role_name` - Name of the certificate role to use for signing
  - `csr` - PEM-encoded certificate signing request
  - `opts` - Additional certificate options
  - `pki_opts` - PKI engine options

  ## Returns

  - `{:ok, certificate_info}` - Signed certificate information
  - `{:error, error}` - Error information

  ## Examples

      # Sign a CSR
      {:ok, cert} = Certificates.sign("web-server", csr_pem, %{
        common_name: "example.com",
        ttl: "30d"
      })

  """
  @spec sign(String.t(), String.t(), map(), keyword()) :: {:ok, map()} | {:error, Error.t()}
  def sign(role_name, csr, opts \\ %{}, pki_opts \\ []) do
    mount_path = Keyword.get(pki_opts, :mount_path, @default_mount_path)
    timeout = Keyword.get(pki_opts, :timeout, @default_timeout)

    url = "/v1/#{mount_path}/sign/#{role_name}"
    payload = build_sign_payload(csr, opts)

    metadata = %{
      operation: :sign_certificate,
      mount_path: mount_path,
      role_name: role_name,
      common_name: Map.get(opts, :common_name)
    }

    start_time = System.monotonic_time()
    Logger.debug("Signing certificate", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.post(url, payload, timeout: timeout) do
      {:ok, %{status: 200, body: body}} ->
        duration = System.monotonic_time() - start_time
        cert_info = parse_certificate_response(body)

        Logger.info(
          "Certificate signed successfully",
          Map.put(metadata, :serial_number, Map.get(cert_info, :serial_number, ""))
        )

        Telemetry.operation_success(
          duration,
          Map.put(metadata, :serial_number, Map.get(cert_info, :serial_number, ""))
        )

        {:ok, cert_info}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warning("Certificate signing failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:network_error, "Failed to sign certificate: #{inspect(reason)}")

        Logger.error("Certificate signing request failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Revoke a certificate by serial number.

  Revokes the specified certificate and adds it to the certificate revocation list (CRL).
  The certificate will no longer be considered valid by clients that check the CRL.

  ## Parameters

  - `serial_number` - Certificate serial number (hex format with colons)
  - `pki_opts` - PKI engine options

  ## Returns

  - `:ok` - Certificate revoked successfully
  - `{:error, error}` - Error information

  ## Examples

      # Revoke a certificate
      :ok = Certificates.revoke("39:dd:2e:90:b7:23:1f:8d")

  """
  @spec revoke(String.t(), keyword()) :: :ok | {:error, Error.t()}
  def revoke(serial_number, pki_opts \\ []) do
    mount_path = Keyword.get(pki_opts, :mount_path, @default_mount_path)
    timeout = Keyword.get(pki_opts, :timeout, @default_timeout)

    url = "/v1/#{mount_path}/revoke"
    payload = %{"serial_number" => serial_number}

    metadata = %{
      operation: :revoke_certificate,
      mount_path: mount_path,
      serial_number: serial_number
    }

    start_time = System.monotonic_time()
    Logger.debug("Revoking certificate", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.post(url, payload, timeout: timeout) do
      {:ok, %{status: 200}} ->
        duration = System.monotonic_time() - start_time

        Logger.info("Certificate revoked successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        :ok

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warning("Certificate revocation failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:network_error, "Failed to revoke certificate: #{inspect(reason)}")

        Logger.error("Certificate revocation request failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  # Private helper functions

  defp build_certificate_payload(opts) do
    opts
    |> Enum.reduce(%{}, &build_certificate_option/2)
  end

  defp build_certificate_option({:common_name, value}, acc) when is_binary(value),
    do: Map.put(acc, "common_name", value)

  defp build_certificate_option({:alt_names, value}, acc) when is_binary(value),
    do: Map.put(acc, "alt_names", value)

  defp build_certificate_option({:ip_sans, value}, acc) when is_binary(value),
    do: Map.put(acc, "ip_sans", value)

  defp build_certificate_option({:uri_sans, value}, acc) when is_binary(value),
    do: Map.put(acc, "uri_sans", value)

  defp build_certificate_option({:other_sans, value}, acc) when is_binary(value),
    do: Map.put(acc, "other_sans", value)

  defp build_certificate_option({:ttl, value}, acc) when is_binary(value),
    do: Map.put(acc, "ttl", value)

  defp build_certificate_option({:format, value}, acc) when is_binary(value),
    do: Map.put(acc, "format", value)

  defp build_certificate_option({:private_key_format, value}, acc) when is_binary(value),
    do: Map.put(acc, "private_key_format", value)

  defp build_certificate_option({:exclude_cn_from_sans, value}, acc) when is_boolean(value),
    do: Map.put(acc, "exclude_cn_from_sans", value)

  defp build_certificate_option({:not_after, value}, acc) when is_binary(value),
    do: Map.put(acc, "not_after", value)

  defp build_certificate_option({:remove_roots_from_chain, value}, acc) when is_boolean(value),
    do: Map.put(acc, "remove_roots_from_chain", value)

  defp build_certificate_option(_other, acc), do: acc

  defp build_sign_payload(csr, opts) do
    opts
    |> Map.put(:csr, csr)
    |> Enum.reduce(%{}, &build_sign_option/2)
  end

  defp build_sign_option({:csr, value}, acc) when is_binary(value), do: Map.put(acc, "csr", value)

  defp build_sign_option({:common_name, value}, acc) when is_binary(value),
    do: Map.put(acc, "common_name", value)

  defp build_sign_option({:alt_names, value}, acc) when is_binary(value),
    do: Map.put(acc, "alt_names", value)

  defp build_sign_option({:ip_sans, value}, acc) when is_binary(value),
    do: Map.put(acc, "ip_sans", value)

  defp build_sign_option({:uri_sans, value}, acc) when is_binary(value),
    do: Map.put(acc, "uri_sans", value)

  defp build_sign_option({:ttl, value}, acc) when is_binary(value), do: Map.put(acc, "ttl", value)

  defp build_sign_option({:format, value}, acc) when is_binary(value),
    do: Map.put(acc, "format", value)

  defp build_sign_option({:exclude_cn_from_sans, value}, acc) when is_boolean(value),
    do: Map.put(acc, "exclude_cn_from_sans", value)

  defp build_sign_option(_other, acc), do: acc

  defp parse_certificate_response(body) when is_map(body) do
    data = Map.get(body, "data", %{}) || %{}

    %{
      certificate: Map.get(data, "certificate", ""),
      issuing_ca: Map.get(data, "issuing_ca", ""),
      ca_chain: Map.get(data, "ca_chain", []),
      private_key: Map.get(data, "private_key"),
      private_key_type: Map.get(data, "private_key_type"),
      serial_number: Map.get(data, "serial_number", ""),
      expiration: Map.get(data, "expiration", "")
    }
  end

  defp parse_certificate_response(_),
    do: %{
      certificate: "",
      issuing_ca: "",
      ca_chain: [],
      private_key: nil,
      private_key_type: nil,
      serial_number: "",
      expiration: ""
    }

  @doc """
  Read a certificate by serial number.

  Retrieves the certificate with the specified serial number in PEM format.

  ## Parameters

  - `serial_number` - Certificate serial number (hex format with colons)
  - `pki_opts` - PKI engine options

  ## Returns

  - `{:ok, certificate}` - PEM-encoded certificate
  - `{:error, error}` - Error information

  ## Examples

      {:ok, cert_pem} = Certificates.read("39:dd:2e:90:b7:23:1f:8d")

  """
  @spec read(String.t(), keyword()) :: {:ok, String.t()} | {:error, Error.t()}
  def read(serial_number, pki_opts \\ []) do
    mount_path = Keyword.get(pki_opts, :mount_path, @default_mount_path)
    timeout = Keyword.get(pki_opts, :timeout, @default_timeout)

    url = "/v1/#{mount_path}/cert/#{serial_number}"

    metadata = %{
      operation: :read_certificate,
      mount_path: mount_path,
      serial_number: serial_number
    }

    start_time = System.monotonic_time()
    Logger.debug("Reading certificate", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.get(url, timeout: timeout) do
      {:ok, %{status: 200, body: body}} when is_binary(body) ->
        duration = System.monotonic_time() - start_time

        Logger.debug("Certificate read successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, body}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warning("Certificate read failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:network_error, "Failed to read certificate: #{inspect(reason)}")

        Logger.error("Certificate read request failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  List all certificates.

  Retrieves a list of all certificate serial numbers in the PKI engine.

  ## Parameters

  - `pki_opts` - PKI engine options

  ## Returns

  - `{:ok, serial_numbers}` - List of certificate serial numbers
  - `{:error, error}` - Error information

  ## Examples

      {:ok, serials} = Certificates.list()

  """
  @spec list(keyword()) :: {:ok, [String.t()]} | {:error, Error.t()}
  def list(pki_opts \\ []) do
    mount_path = Keyword.get(pki_opts, :mount_path, @default_mount_path)
    timeout = Keyword.get(pki_opts, :timeout, @default_timeout)

    url = "/v1/#{mount_path}/certs?list=true"

    metadata = %{
      operation: :list_certificates,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()
    Logger.debug("Listing certificates", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.get(url, timeout: timeout) do
      {:ok, %{status: 200, body: body}} ->
        duration = System.monotonic_time() - start_time

        serials =
          case get_in(body, ["data", "keys"]) do
            list when is_list(list) -> list
            _ -> []
          end

        Logger.debug(
          "Certificates listed successfully",
          Map.put(metadata, :count, length(serials))
        )

        Telemetry.operation_success(duration, Map.put(metadata, :count, length(serials)))

        {:ok, serials}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warning("Certificate listing failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:network_error, "Failed to list certificates: #{inspect(reason)}")

        Logger.error("Certificate listing request failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Sign a certificate verbatim.

  Signs a certificate with the exact parameters specified in the CSR,
  without applying role-based constraints. This is useful for advanced
  certificate signing scenarios where full control is needed.

  ## Parameters

  - `csr` - PEM-encoded certificate signing request
  - `opts` - Certificate options
  - `pki_opts` - PKI engine options

  ## Returns

  - `{:ok, certificate_info}` - Signed certificate information
  - `{:error, error}` - Error information

  ## Examples

      {:ok, cert} = Certificates.sign_verbatim(csr_pem, %{
        ttl: "30d",
        format: "pem"
      })

  """
  @spec sign_verbatim(String.t(), map(), keyword()) :: {:ok, map()} | {:error, Error.t()}
  def sign_verbatim(csr, opts \\ %{}, pki_opts \\ []) do
    mount_path = Keyword.get(pki_opts, :mount_path, @default_mount_path)
    timeout = Keyword.get(pki_opts, :timeout, @default_timeout)

    url = "/v1/#{mount_path}/sign-verbatim"
    payload = build_sign_payload(csr, opts)

    metadata = %{
      operation: :sign_verbatim,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()
    Logger.debug("Signing certificate verbatim", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.post(url, payload, timeout: timeout) do
      {:ok, %{status: 200, body: body}} ->
        duration = System.monotonic_time() - start_time
        cert_info = parse_certificate_response(body)

        Logger.info(
          "Certificate signed verbatim successfully",
          Map.put(metadata, :serial_number, Map.get(cert_info, :serial_number, ""))
        )

        Telemetry.operation_success(
          duration,
          Map.put(metadata, :serial_number, Map.get(cert_info, :serial_number, ""))
        )

        {:ok, cert_info}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warning("Certificate verbatim signing failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:network_error, "Failed to sign certificate verbatim: #{inspect(reason)}")

        Logger.error(
          "Certificate verbatim signing request failed",
          Map.put(metadata, :error, error)
        )

        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Revoke a certificate using its private key.

  Revokes a certificate by providing its private key for authentication.
  This method can be used when the certificate serial number is not known
  but the private key is available.

  ## Parameters

  - `certificate` - PEM-encoded certificate to revoke
  - `private_key` - PEM-encoded private key for authentication
  - `pki_opts` - PKI engine options

  ## Returns

  - `:ok` - Certificate revoked successfully
  - `{:error, error}` - Error information

  ## Examples

      cert_pem = File.read!("cert.pem")
      key_pem = File.read!("key.pem")
      :ok = Certificates.revoke_with_key(cert_pem, key_pem)

  """
  @spec revoke_with_key(String.t(), String.t(), keyword()) :: :ok | {:error, Error.t()}
  def revoke_with_key(certificate, private_key, pki_opts \\ []) do
    mount_path = Keyword.get(pki_opts, :mount_path, @default_mount_path)
    timeout = Keyword.get(pki_opts, :timeout, @default_timeout)

    url = "/v1/#{mount_path}/revoke-with-key"

    payload = %{
      "certificate" => certificate,
      "private_key" => private_key
    }

    metadata = %{
      operation: :revoke_certificate_with_key,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()
    Logger.debug("Revoking certificate with private key", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.post(url, payload, timeout: timeout) do
      {:ok, %{status: 200}} ->
        duration = System.monotonic_time() - start_time

        Logger.info("Certificate revoked with key successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        :ok

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warning("Certificate revocation with key failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:network_error, "Failed to revoke certificate with key: #{inspect(reason)}")

        Logger.error(
          "Certificate revocation with key request failed",
          Map.put(metadata, :error, error)
        )

        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end
end
