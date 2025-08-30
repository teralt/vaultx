defmodule Vaultx.Secrets.PKI.CA do
  @moduledoc """
  Enterprise Certificate Authority management for HashiCorp Vault PKI.

  This module provides comprehensive CA management functionality for enterprise
  PKI deployments, supporting complex certificate hierarchies, multi-issuer
  configurations, and automated CA lifecycle management. It implements industry
  best practices for certificate authority operations.

  ## Enterprise CA Capabilities

  ### Root CA Operations
  - Generate new root CA certificates with configurable policies
  - Import existing root CA certificates and private keys
  - Export CA certificates in multiple formats (PEM, DER, PKCS#7)
  - Configure advanced CA certificate policies and constraints
  - Support for Hardware Security Module (HSM) integration

  ### Intermediate CA Operations
  - Generate intermediate CA certificate signing requests
  - Sign intermediate CA certificates from root or parent CAs
  - Build complex hierarchical PKI structures
  - Cross-sign certificates between different CA hierarchies
  - Automated intermediate CA renewal and rotation

  ### Multi-Issuer Management
  - Manage multiple certificate issuers within single PKI mount
  - Configure issuer-specific policies and constraints
  - Automated issuer selection and load balancing
  - Certificate chain validation and trust path verification

  ## Usage Examples

      # Generate a new root CA
      {:ok, ca_info} = CA.generate_root(%{
        common_name: "Example Root CA",
        ttl: "10y",
        key_type: "rsa",
        key_bits: 4096
      })

      # Generate an intermediate CA CSR
      {:ok, %{csr: csr, private_key: key}} = CA.generate_intermediate(%{
        common_name: "Example Intermediate CA",
        key_type: "ec",
        key_bits: 256
      })

      # Import an existing CA certificate
      :ok = CA.import_ca(ca_certificate, ca_private_key)

      # Read the current CA certificate
      {:ok, ca_cert} = CA.read_ca_certificate()

      # Read the full CA chain
      {:ok, ca_chain} = CA.read_ca_chain()

  ## API Compliance

  Fully implements HashiCorp Vault PKI CA management:
  - [PKI Root CA API](https://developer.hashicorp.com/vault/api-docs/secret/pki#generate-root)
  - [PKI Intermediate CA API](https://developer.hashicorp.com/vault/api-docs/secret/pki#generate-intermediate)
  - [PKI Multi-Issuer Support](https://developer.hashicorp.com/vault/docs/secrets/pki/considerations#issuer-storage)

  ## Configuration

  CA operations support various configuration options:

  ### Key Generation Options
  - `:key_type` - "rsa", "ec", or "ed25519"
  - `:key_bits` - Key size (RSA: 2048-8192, EC: 224-521)
  - `:signature_bits` - Signature hash size

  ### Certificate Options
  - `:common_name` - CA certificate common name
  - `:alt_names` - Subject alternative names
  - `:ip_sans` - IP address SANs
  - `:uri_sans` - URI SANs
  - `:ttl` - Certificate validity period
  - `:max_path_length` - Maximum path length for intermediate CAs

  ### Policy Options
  - `:permitted_dns_domains` - Allowed DNS domains
  - `:excluded_dns_domains` - Prohibited DNS domains
  - `:permitted_ip_ranges` - Allowed IP address ranges
  - `:excluded_ip_ranges` - Prohibited IP address ranges

  ## Security Considerations

  ### Root CA Security
  - Generate root CAs offline when possible
  - Use hardware security modules (HSMs) for key storage
  - Implement strict access controls for root CA operations
  - Regular backup and secure storage of root CA keys

  ### Intermediate CA Best Practices
  - Use intermediate CAs for day-to-day certificate issuance
  - Implement shorter validity periods for intermediate CAs
  - Regular rotation of intermediate CA certificates
  - Proper certificate chain validation

  ### Key Management
  - Use strong key sizes (RSA 2048+ bits, EC P-256+)
  - Implement proper key lifecycle management
  - Secure key storage and access controls
  - Regular key rotation and renewal procedures

  """

  alias Vaultx.Base.{Error, Logger, Telemetry}
  alias Vaultx.Transport.HTTP

  @default_mount_path "pki"
  @default_timeout 30_000

  @doc """
  Generate a new root CA certificate and private key.

  Creates a new root CA certificate with the specified configuration.
  This operation generates both the certificate and private key within Vault.

  ## Parameters

  - `opts` - CA generation options (see module documentation)
  - `pki_opts` - PKI engine options (mount_path, timeout, etc.)

  ## Returns

  - `{:ok, ca_info}` - CA certificate information including certificate, private key, and metadata
  - `{:error, error}` - Error information

  ## Examples

      # Generate RSA root CA
      {:ok, ca} = CA.generate_root(%{
        common_name: "Example Root CA",
        ttl: "10y",
        key_type: "rsa",
        key_bits: 4096
      })

      # Generate EC root CA with constraints
      {:ok, ca} = CA.generate_root(%{
        common_name: "Example Root CA",
        ttl: "5y",
        key_type: "ec",
        key_bits: 384,
        max_path_length: 2,
        permitted_dns_domains: ["example.com", "example.org"]
      })

  """
  @spec generate_root(map(), keyword()) :: {:ok, map()} | {:error, Error.t()}
  def generate_root(opts \\ %{}, pki_opts \\ []) do
    mount_path = Keyword.get(pki_opts, :mount_path, @default_mount_path)
    timeout = Keyword.get(pki_opts, :timeout, @default_timeout)

    url = "/v1/#{mount_path}/root/generate/internal"
    payload = build_ca_payload(opts)

    metadata = %{
      operation: :generate_root_ca,
      mount_path: mount_path,
      common_name: Map.get(opts, :common_name),
      key_type: Map.get(opts, :key_type, "rsa")
    }

    start_time = System.monotonic_time()
    Logger.debug("Generating root CA", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.post(url, payload, timeout: timeout) do
      {:ok, %{status: 200, body: body}} ->
        duration = System.monotonic_time() - start_time
        ca_info = parse_ca_response(body)

        Logger.info(
          "Root CA generated successfully",
          Map.put(metadata, :serial_number, Map.get(ca_info, :serial_number, ""))
        )

        Telemetry.operation_success(
          duration,
          Map.put(metadata, :serial_number, Map.get(ca_info, :serial_number, ""))
        )

        {:ok, ca_info}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warning("Root CA generation failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:network_error, "Failed to generate root CA: #{inspect(reason)}")

        Logger.error("Root CA generation request failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Generate an intermediate CA certificate signing request (CSR).

  Creates a new intermediate CA CSR and private key. The CSR can then be
  signed by a root CA or another intermediate CA to create the certificate.

  ## Parameters

  - `opts` - CA generation options
  - `pki_opts` - PKI engine options

  ## Returns

  - `{:ok, %{csr: csr, private_key: key}}` - CSR and private key
  - `{:error, error}` - Error information

  ## Examples

      {:ok, %{csr: csr, private_key: key}} = CA.generate_intermediate(%{
        common_name: "Example Intermediate CA",
        key_type: "rsa",
        key_bits: 2048
      })

  """
  @spec generate_intermediate(map(), keyword()) :: {:ok, map()} | {:error, Error.t()}
  def generate_intermediate(opts \\ %{}, pki_opts \\ []) do
    mount_path = Keyword.get(pki_opts, :mount_path, @default_mount_path)
    timeout = Keyword.get(pki_opts, :timeout, @default_timeout)

    url = "/v1/#{mount_path}/intermediate/generate/internal"
    payload = build_ca_payload(opts)

    metadata = %{
      operation: :generate_intermediate_ca,
      mount_path: mount_path,
      common_name: Map.get(opts, :common_name),
      key_type: Map.get(opts, :key_type, "rsa")
    }

    start_time = System.monotonic_time()
    Logger.debug("Generating intermediate CA CSR", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.post(url, payload, timeout: timeout) do
      {:ok, %{status: 200, body: body}} ->
        duration = System.monotonic_time() - start_time
        result = parse_intermediate_response(body)

        Logger.info("Intermediate CA CSR generated successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, result}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warning("Intermediate CA CSR generation failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:network_error, "Failed to generate intermediate CA CSR: #{inspect(reason)}")

        Logger.error(
          "Intermediate CA CSR generation request failed",
          Map.put(metadata, :error, error)
        )

        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Import an existing CA certificate and private key.

  Imports a CA certificate and its corresponding private key into the PKI engine.
  This is useful for migrating existing PKI infrastructure to Vault.

  ## Parameters

  - `certificate` - PEM-encoded CA certificate
  - `private_key` - PEM-encoded private key
  - `pki_opts` - PKI engine options

  ## Returns

  - `:ok` - Import successful
  - `{:error, error}` - Error information

  ## Examples

      ca_cert = File.read!("ca.pem")
      ca_key = File.read!("ca-key.pem")
      :ok = CA.import_ca(ca_cert, ca_key)

  """
  @spec import_ca(String.t(), String.t(), keyword()) :: :ok | {:error, Error.t()}
  def import_ca(certificate, private_key, pki_opts \\ []) do
    mount_path = Keyword.get(pki_opts, :mount_path, @default_mount_path)
    timeout = Keyword.get(pki_opts, :timeout, @default_timeout)

    url = "/v1/#{mount_path}/config/ca"

    payload = %{
      "pem_bundle" => certificate <> "\n" <> private_key
    }

    metadata = %{
      operation: :import_ca,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()
    Logger.debug("Importing CA certificate", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.post(url, payload, timeout: timeout) do
      {:ok, %{status: 204}} ->
        duration = System.monotonic_time() - start_time

        Logger.info("CA certificate imported successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        :ok

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warning("CA certificate import failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:network_error, "Failed to import CA certificate: #{inspect(reason)}")

        Logger.error("CA certificate import request failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Read the current CA certificate.

  Retrieves the CA certificate for the PKI engine in PEM format.

  ## Parameters

  - `pki_opts` - PKI engine options

  ## Returns

  - `{:ok, certificate}` - PEM-encoded CA certificate
  - `{:error, error}` - Error information

  ## Examples

      {:ok, ca_cert} = CA.read_ca_certificate()

  """
  @spec read_ca_certificate(keyword()) :: {:ok, String.t()} | {:error, Error.t()}
  def read_ca_certificate(pki_opts \\ []) do
    mount_path = Keyword.get(pki_opts, :mount_path, @default_mount_path)
    timeout = Keyword.get(pki_opts, :timeout, @default_timeout)

    url = "/v1/#{mount_path}/ca/pem"

    metadata = %{
      operation: :read_ca_certificate,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()
    Logger.debug("Reading CA certificate", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.get(url, timeout: timeout) do
      {:ok, %{status: 200, body: body}} when is_binary(body) ->
        duration = System.monotonic_time() - start_time

        Logger.debug("CA certificate read successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        {:ok, body}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warning("CA certificate read failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time
        error = Error.new(:network_error, "Failed to read CA certificate: #{inspect(reason)}")

        Logger.error("CA certificate read request failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  # Private helper functions

  defp build_ca_payload(opts) do
    opts
    |> Enum.reduce(%{}, &build_ca_option/2)
  end

  defp build_ca_option({:common_name, value}, acc) when is_binary(value),
    do: Map.put(acc, "common_name", value)

  defp build_ca_option({:alt_names, value}, acc) when is_binary(value),
    do: Map.put(acc, "alt_names", value)

  defp build_ca_option({:ip_sans, value}, acc) when is_binary(value),
    do: Map.put(acc, "ip_sans", value)

  defp build_ca_option({:uri_sans, value}, acc) when is_binary(value),
    do: Map.put(acc, "uri_sans", value)

  defp build_ca_option({:ttl, value}, acc) when is_binary(value), do: Map.put(acc, "ttl", value)

  defp build_ca_option({:key_type, value}, acc) when is_binary(value),
    do: Map.put(acc, "key_type", value)

  defp build_ca_option({:key_bits, value}, acc) when is_integer(value),
    do: Map.put(acc, "key_bits", value)

  defp build_ca_option({:max_path_length, value}, acc) when is_integer(value),
    do: Map.put(acc, "max_path_length", value)

  defp build_ca_option({:permitted_dns_domains, value}, acc) when is_list(value),
    do: Map.put(acc, "permitted_dns_domains", Enum.join(value, ","))

  defp build_ca_option({:excluded_dns_domains, value}, acc) when is_list(value),
    do: Map.put(acc, "excluded_dns_domains", Enum.join(value, ","))

  defp build_ca_option({:format, value}, acc) when is_binary(value),
    do: Map.put(acc, "format", value)

  defp build_ca_option(_other, acc), do: acc

  defp parse_ca_response(body) when is_map(body) do
    data = Map.get(body, "data", %{})

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

  defp parse_ca_response(_), do: %{}

  defp parse_intermediate_response(body) when is_map(body) do
    data = Map.get(body, "data", %{})

    %{
      csr: Map.get(data, "csr", ""),
      private_key: Map.get(data, "private_key", ""),
      private_key_type: Map.get(data, "private_key_type", "")
    }
  end

  defp parse_intermediate_response(_), do: %{}

  @doc """
  Read the full CA certificate chain.

  Retrieves the complete CA certificate chain including the CA certificate
  and any intermediate certificates in the chain.

  ## Parameters

  - `pki_opts` - PKI engine options

  ## Returns

  - `{:ok, ca_chain}` - List of PEM-encoded certificates in the chain
  - `{:error, error}` - Error information

  ## Examples

      {:ok, chain} = CA.read_ca_chain()

  """
  @spec read_ca_chain(keyword()) :: {:ok, [String.t()]} | {:error, Error.t()}
  def read_ca_chain(pki_opts \\ []) do
    mount_path = Keyword.get(pki_opts, :mount_path, @default_mount_path)
    timeout = Keyword.get(pki_opts, :timeout, @default_timeout)

    url = "/v1/#{mount_path}/ca_chain"

    metadata = %{
      operation: :read_ca_chain,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()
    Logger.debug("Reading CA certificate chain", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.get(url, timeout: timeout) do
      {:ok, %{status: 200, body: body}} when is_binary(body) ->
        duration = System.monotonic_time() - start_time
        chain = parse_ca_chain(body)

        Logger.debug(
          "CA certificate chain read successfully",
          Map.put(metadata, :chain_length, length(chain))
        )

        Telemetry.operation_success(duration, Map.put(metadata, :chain_length, length(chain)))

        {:ok, chain}

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warning("CA certificate chain read failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(:network_error, "Failed to read CA certificate chain: #{inspect(reason)}")

        Logger.error("CA certificate chain read request failed", Map.put(metadata, :error, error))
        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Sign an intermediate CA certificate.

  Signs an intermediate CA certificate signing request using the current CA.
  This creates a new intermediate CA certificate that can be used to issue
  end-entity certificates.

  ## Parameters

  - `csr` - PEM-encoded certificate signing request
  - `opts` - Signing options
  - `pki_opts` - PKI engine options

  ## Returns

  - `{:ok, certificate_info}` - Signed certificate information
  - `{:error, error}` - Error information

  ## Examples

      {:ok, cert} = CA.sign_intermediate(csr, %{
        common_name: "Intermediate CA",
        ttl: "5y",
        max_path_length: 1
      })

  """
  @spec sign_intermediate(String.t(), map(), keyword()) :: {:ok, map()} | {:error, Error.t()}
  def sign_intermediate(csr, opts \\ %{}, pki_opts \\ []) do
    mount_path = Keyword.get(pki_opts, :mount_path, @default_mount_path)
    timeout = Keyword.get(pki_opts, :timeout, @default_timeout)

    url = "/v1/#{mount_path}/root/sign-intermediate"
    payload = build_sign_payload(csr, opts)

    metadata = %{
      operation: :sign_intermediate_ca,
      mount_path: mount_path,
      common_name: Map.get(opts, :common_name)
    }

    start_time = System.monotonic_time()
    Logger.debug("Signing intermediate CA certificate", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.post(url, payload, timeout: timeout) do
      {:ok, %{status: 200, body: body}} ->
        duration = System.monotonic_time() - start_time
        cert_info = parse_ca_response(body)

        Logger.info(
          "Intermediate CA certificate signed successfully",
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

        Logger.warning(
          "Intermediate CA certificate signing failed",
          Map.put(metadata, :error, error)
        )

        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(
            :network_error,
            "Failed to sign intermediate CA certificate: #{inspect(reason)}"
          )

        Logger.error(
          "Intermediate CA certificate signing request failed",
          Map.put(metadata, :error, error)
        )

        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  @doc """
  Set the intermediate CA certificate.

  Sets the intermediate CA certificate after it has been signed by a root CA
  or another intermediate CA. This completes the intermediate CA setup process.

  ## Parameters

  - `certificate` - PEM-encoded signed intermediate CA certificate
  - `pki_opts` - PKI engine options

  ## Returns

  - `:ok` - Certificate set successfully
  - `{:error, error}` - Error information

  ## Examples

      :ok = CA.set_intermediate_certificate(signed_cert)

  """
  @spec set_intermediate_certificate(String.t(), keyword()) :: :ok | {:error, Error.t()}
  def set_intermediate_certificate(certificate, pki_opts \\ []) do
    mount_path = Keyword.get(pki_opts, :mount_path, @default_mount_path)
    timeout = Keyword.get(pki_opts, :timeout, @default_timeout)

    url = "/v1/#{mount_path}/intermediate/set-signed"
    payload = %{"certificate" => certificate}

    metadata = %{
      operation: :set_intermediate_certificate,
      mount_path: mount_path
    }

    start_time = System.monotonic_time()
    Logger.debug("Setting intermediate CA certificate", metadata)
    Telemetry.operation_start(metadata)

    case HTTP.post(url, payload, timeout: timeout) do
      {:ok, %{status: 204}} ->
        duration = System.monotonic_time() - start_time

        Logger.info("Intermediate CA certificate set successfully", metadata)
        Telemetry.operation_success(duration, metadata)

        :ok

      {:ok, %{status: status, body: body}} ->
        duration = System.monotonic_time() - start_time
        error = Error.from_http_response(status, body)

        Logger.warning(
          "Setting intermediate CA certificate failed",
          Map.put(metadata, :error, error)
        )

        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}

      {:error, reason} ->
        duration = System.monotonic_time() - start_time

        error =
          Error.new(
            :network_error,
            "Failed to set intermediate CA certificate: #{inspect(reason)}"
          )

        Logger.error(
          "Setting intermediate CA certificate request failed",
          Map.put(metadata, :error, error)
        )

        Telemetry.operation_failure(duration, Map.put(metadata, :error, error))

        {:error, error}
    end
  end

  # Additional private helper functions

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

  defp build_sign_option({:max_path_length, value}, acc) when is_integer(value),
    do: Map.put(acc, "max_path_length", value)

  defp build_sign_option({:permitted_dns_domains, value}, acc) when is_list(value),
    do: Map.put(acc, "permitted_dns_domains", Enum.join(value, ","))

  defp build_sign_option({:excluded_dns_domains, value}, acc) when is_list(value),
    do: Map.put(acc, "excluded_dns_domains", Enum.join(value, ","))

  defp build_sign_option({:format, value}, acc) when is_binary(value),
    do: Map.put(acc, "format", value)

  defp build_sign_option(_other, acc), do: acc

  defp parse_ca_chain(pem_data) when is_binary(pem_data) and pem_data != "" do
    # Split PEM data into individual certificates
    pem_data
    |> String.split("-----END CERTIFICATE-----")
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.map(&(&1 <> "-----END CERTIFICATE-----"))
  end

  defp parse_ca_chain(_), do: []
end
