defmodule Vaultx.Secrets.PKI.Behaviour do
  @moduledoc """
  Comprehensive behaviour for HashiCorp Vault PKI secrets engine.

  This behaviour provides enterprise PKI
  operations for complete Public Key Infrastructure functionality. It provides
  a comprehensive interface for certificate lifecycle management, CA operations,
  and automated certificate issuance following industry standards.

  ## Enterprise PKI Capabilities

  ### Certificate Issuance
  - Issue certificates based on configurable roles
  - Sign certificate signing requests (CSRs)
  - Generate certificates with private keys
  - Support for various certificate formats (PEM, DER, PKCS#8)
  - Batch certificate operations for efficiency

  ### Certificate Authority Management
  - Generate root CA certificates with custom policies
  - Generate intermediate CA certificates
  - Import existing CA certificates and private keys
  - CA certificate chain management and validation
  - Cross-signing and complex certificate hierarchies

  ### Role-Based Management
  - Create and manage certificate roles with policies
  - Define certificate policies and security constraints
  - Configure allowed domains and Subject Alternative Names
  - Set certificate validity periods and key usage restrictions

  ### Certificate Lifecycle
  - Certificate revocation and CRL management
  - Automated certificate renewal and rotation
  - Certificate metadata tracking and auditing
  - Automatic certificate cleanup (tidy operations)

  ### Advanced Protocol Support
  - Multiple issuer support (Vault 1.11+)
  - ACME protocol for automated certificate management
  - EST protocol for enterprise environments
  - SCEP protocol for device enrollment
  - CMP protocol for certificate management

  ## Extended Operations

  Beyond the base secrets operations, PKI engines support:

  ### Certificate Issuance
  - `issue_certificate/3` - Issue a new certificate based on a role
  - `sign_certificate/3` - Sign a certificate signing request
  - `sign_intermediate/3` - Sign an intermediate CA certificate
  - `sign_self_issued/3` - Sign a self-issued certificate
  - `sign_verbatim/3` - Sign a certificate with verbatim parameters

  ### Certificate Authority Operations
  - `generate_root/2` - Generate a new root CA certificate
  - `generate_intermediate/2` - Generate an intermediate CA CSR
  - `import_ca/3` - Import CA certificates and keys
  - `read_ca_certificate/1` - Read the CA certificate
  - `read_ca_chain/1` - Read the full CA certificate chain

  ### Role Management
  - `create_role/3` - Create a new certificate role
  - `read_role/2` - Read role configuration
  - `update_role/3` - Update role configuration
  - `delete_role/2` - Delete a certificate role
  - `list_roles/1` - List all configured roles

  ### Certificate Management
  - `read_certificate/2` - Read a certificate by serial number
  - `list_certificates/1` - List all certificates
  - `revoke_certificate/2` - Revoke a certificate
  - `revoke_certificate_with_key/3` - Revoke using private key

  ### CRL Operations
  - `read_crl/1` - Read the certificate revocation list
  - `rotate_crl/1` - Force CRL rotation
  - `read_crl_config/1` - Read CRL configuration
  - `write_crl_config/2` - Update CRL configuration

  ### Configuration Management
  - `read_urls/1` - Read authority information URLs
  - `write_urls/2` - Configure authority information URLs
  - `read_cluster_config/1` - Read cluster configuration
  - `write_cluster_config/2` - Update cluster configuration

  ### Maintenance Operations
  - `tidy/2` - Clean up expired certificates and revoked entries
  - `tidy_status/1` - Check tidy operation status
  - `tidy_cancel/1` - Cancel running tidy operation

  ## Configuration Options

  PKI operations support various configuration options:

  ### Common Options
  - `:mount_path` - PKI engine mount path (default: "pki")
  - `:timeout` - Request timeout in milliseconds
  - `:issuer_ref` - Reference to specific issuer (for multi-issuer setups)

  ### Certificate Options
  - `:common_name` - Certificate common name
  - `:alt_names` - Subject alternative names
  - `:ip_sans` - IP address SANs
  - `:uri_sans` - URI SANs
  - `:other_sans` - Custom OID SANs
  - `:ttl` - Certificate time-to-live
  - `:format` - Certificate format ("pem", "der", "pem_bundle")
  - `:private_key_format` - Private key format ("der", "pkcs8")

  ### Role Options
  - `:allowed_domains` - Allowed certificate domains
  - `:allow_subdomains` - Allow subdomain certificates
  - `:allow_any_name` - Allow any certificate name
  - `:key_type` - Key type ("rsa", "ec", "ed25519")
  - `:key_bits` - Key size in bits
  - `:max_ttl` - Maximum certificate TTL
  - `:server_flag` - Enable server authentication
  - `:client_flag` - Enable client authentication

  ## References

  - [PKI Secrets Engine API](https://developer.hashicorp.com/vault/api-docs/secret/pki)
  - [PKI Certificate Management](https://developer.hashicorp.com/vault/docs/secrets/pki)
  - [ACME Protocol Support](https://developer.hashicorp.com/vault/docs/secrets/pki/acme)

  ## Error Handling

  PKI operations may return various error types:

  - `:role_not_found` - Certificate role does not exist
  - `:issuer_not_found` - CA issuer does not exist
  - `:certificate_not_found` - Certificate does not exist
  - `:invalid_csr` - Invalid certificate signing request
  - `:domain_not_allowed` - Domain not permitted by role
  - `:ttl_exceeded` - Requested TTL exceeds maximum
  - `:key_generation_failed` - Private key generation failed
  - `:signing_failed` - Certificate signing failed

  ## Key Types and Algorithms

  ### Supported Key Types
  - `rsa` - RSA keys (2048, 3072, 4096, 8192 bits)
  - `ec` - Elliptic Curve keys (P-256, P-384, P-521)
  - `ed25519` - Edwards Curve keys (fixed size)

  ### Signature Algorithms
  - RSA with SHA-256, SHA-384, SHA-512
  - ECDSA with SHA-256, SHA-384, SHA-512
  - Ed25519 (EdDSA)
  - RSA-PSS (Probabilistic Signature Scheme)

  ## Security Considerations

  ### Best Practices
  - Use intermediate CAs instead of root CAs for certificate issuance
  - Implement proper role-based access controls
  - Configure appropriate certificate validity periods
  - Enable certificate revocation checking
  - Use strong key sizes and modern algorithms
  - Regularly rotate CA certificates
  - Monitor certificate expiration and renewal

  ### Access Control
  - Restrict access to CA generation and import operations
  - Limit certificate issuance to authorized roles
  - Implement approval workflows for sensitive operations
  - Audit certificate issuance and revocation activities

  ## Examples

      # Issue a certificate
      {:ok, cert} = MyPKI.issue_certificate("web-server", %{
        common_name: "example.com",
        alt_names: "www.example.com,api.example.com",
        ttl: "30d"
      })

      # Sign a CSR
      {:ok, cert} = MyPKI.sign_certificate("web-server", %{
        csr: csr_pem,
        common_name: "example.com"
      })

      # Generate root CA
      {:ok, ca} = MyPKI.generate_root(%{
        common_name: "Example Root CA",
        ttl: "10y"
      })

      # Create a role
      :ok = MyPKI.create_role("web-server", %{
        allowed_domains: ["example.com"],
        allow_subdomains: true,
        max_ttl: "90d",
        key_type: "rsa",
        key_bits: 2048
      })

      # Revoke a certificate
      :ok = MyPKI.revoke_certificate("39:dd:2e:90:b7:23:1f:8d")

  """

  alias Vaultx.Base.Error

  @type pki_opts :: [
          mount_path: String.t(),
          timeout: pos_integer(),
          issuer_ref: String.t()
        ]

  @type certificate_opts :: map()

  @type role_opts :: map()

  @type ca_opts :: map()

  @type certificate_info :: %{
          certificate: String.t(),
          issuing_ca: String.t(),
          ca_chain: [String.t()],
          private_key: String.t() | nil,
          private_key_type: String.t() | nil,
          serial_number: String.t(),
          expiration: String.t()
        }

  @type role_info :: %{
          name: String.t(),
          allowed_domains: [String.t()],
          allow_subdomains: boolean(),
          allow_any_name: boolean(),
          key_type: String.t(),
          key_bits: pos_integer(),
          max_ttl: String.t(),
          ttl: String.t(),
          server_flag: boolean(),
          client_flag: boolean()
        }

  @type ca_info :: %{
          certificate: String.t(),
          ca_chain: [String.t()],
          private_key: String.t() | nil,
          private_key_type: String.t() | nil,
          serial_number: String.t(),
          expiration: String.t()
        }

  # Certificate Issuance Operations
  @callback issue_certificate(
              role_name :: String.t(),
              opts :: certificate_opts(),
              pki_opts :: pki_opts()
            ) ::
              {:ok, certificate_info()} | {:error, Error.t()}

  @callback sign_certificate(
              role_name :: String.t(),
              csr :: String.t(),
              opts :: certificate_opts(),
              pki_opts :: pki_opts()
            ) ::
              {:ok, certificate_info()} | {:error, Error.t()}

  @callback sign_intermediate(
              csr :: String.t(),
              opts :: certificate_opts(),
              pki_opts :: pki_opts()
            ) ::
              {:ok, certificate_info()} | {:error, Error.t()}

  @callback sign_self_issued(
              certificate :: String.t(),
              opts :: certificate_opts(),
              pki_opts :: pki_opts()
            ) ::
              {:ok, certificate_info()} | {:error, Error.t()}

  @callback sign_verbatim(csr :: String.t(), opts :: certificate_opts(), pki_opts :: pki_opts()) ::
              {:ok, certificate_info()} | {:error, Error.t()}

  # Certificate Authority Operations
  @callback generate_root(opts :: ca_opts(), pki_opts :: pki_opts()) ::
              {:ok, ca_info()} | {:error, Error.t()}

  @callback generate_intermediate(opts :: ca_opts(), pki_opts :: pki_opts()) ::
              {:ok, %{csr: String.t(), private_key: String.t()}} | {:error, Error.t()}

  @callback import_ca(certificate :: String.t(), private_key :: String.t(), opts :: pki_opts()) ::
              :ok | {:error, Error.t()}

  @callback read_ca_certificate(opts :: pki_opts()) ::
              {:ok, String.t()} | {:error, Error.t()}

  @callback read_ca_chain(opts :: pki_opts()) ::
              {:ok, [String.t()]} | {:error, Error.t()}

  # Role Management Operations
  @callback create_role(name :: String.t(), opts :: role_opts(), pki_opts :: pki_opts()) ::
              :ok | {:error, Error.t()}

  @callback read_role(name :: String.t(), opts :: pki_opts()) ::
              {:ok, role_info()} | {:error, Error.t()}

  @callback update_role(name :: String.t(), opts :: role_opts(), pki_opts :: pki_opts()) ::
              :ok | {:error, Error.t()}

  @callback delete_role(name :: String.t(), opts :: pki_opts()) ::
              :ok | {:error, Error.t()}

  @callback list_roles(opts :: pki_opts()) ::
              {:ok, [String.t()]} | {:error, Error.t()}

  # Certificate Management Operations
  @callback read_certificate(serial_number :: String.t(), opts :: pki_opts()) ::
              {:ok, String.t()} | {:error, Error.t()}

  @callback list_certificates(opts :: pki_opts()) ::
              {:ok, [String.t()]} | {:error, Error.t()}

  @callback revoke_certificate(serial_number :: String.t(), opts :: pki_opts()) ::
              :ok | {:error, Error.t()}

  @callback revoke_certificate_with_key(
              serial_number :: String.t(),
              private_key :: String.t(),
              opts :: pki_opts()
            ) ::
              :ok | {:error, Error.t()}

  # CRL Operations
  @callback read_crl(opts :: pki_opts()) ::
              {:ok, String.t()} | {:error, Error.t()}

  @callback rotate_crl(opts :: pki_opts()) ::
              :ok | {:error, Error.t()}

  # Configuration Operations
  @callback read_urls(opts :: pki_opts()) ::
              {:ok, map()} | {:error, Error.t()}

  @callback write_urls(config :: map(), opts :: pki_opts()) ::
              :ok | {:error, Error.t()}

  # Maintenance Operations
  @callback tidy(opts :: keyword(), pki_opts :: pki_opts()) ::
              :ok | {:error, Error.t()}

  @callback tidy_status(opts :: pki_opts()) ::
              {:ok, map()} | {:error, Error.t()}

  @callback tidy_cancel(opts :: pki_opts()) ::
              :ok | {:error, Error.t()}
end
