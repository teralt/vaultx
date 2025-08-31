defmodule Vaultx.MixProject do
  use Mix.Project

  @version "0.6.1"
  @source_url "https://github.com/teralt/vaultx"
  @description "Modern, enterprise-grade HashiCorp Vault client for Elixir."

  def project do
    [
      app: :vaultx,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases(),

      # Documentation
      name: "Vaultx",
      description: @description,
      source_url: @source_url,
      homepage_url: @source_url,
      docs: docs(),
      package: package(),
      test_coverage: [
        tool: ExCoveralls,
        export: "vaultx_coverage",
        summary: [threshold: 99]
      ],
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.post": :test,
        "coveralls.html": :test,
        "coveralls.json": :test,
        "coveralls.xml": :test,
        "coveralls.cobertura": :test
      ],
      dialyzer: dialyzer(),

      # Compilation
      elixirc_paths: elixirc_paths(Mix.env())
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto, :ssl],
      mod: {Vaultx.Application, []}
    ]
  end

  defp elixirc_paths(env) when env in [:test, :dev], do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      # === Core Modern Dependencies ===
      # Modern HTTP client (includes Finch)
      {:req, "~> 0.5"},
      # CA certificate management
      {:castore, "~> 1.0"},
      # Configuration validation (required)
      {:nimble_options, "~> 1.1"},

      # === JSON Processing (Smart Adapter) ===
      # JSON processing (fallback)
      {:jason, "~> 1.4", optional: true},

      # === Optional Dependencies ===
      # Observability and monitoring
      {:telemetry, "~> 1.3", optional: true},
      # AWS authentication
      {:ex_aws, "~> 2.5", optional: true},
      # JWT processing
      {:jose, "~> 1.11", optional: true},

      # === Development Tools ===
      {:ex_doc, "~> 0.35", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:sobelow, "~> 0.13", only: [:dev, :test], runtime: false},

      # === Testing Tools ===
      {:excoveralls, "~> 0.18", only: [:dev, :test]},
      {:mox, "~> 1.2", only: [:dev, :test]},
      {:stream_data, "~> 1.2", only: [:dev, :test]},
      {:bypass, "~> 2.1", only: [:dev, :test]}
    ]
  end

  defp aliases do
    [
      # Setup and dependencies
      setup: ["deps.get", "compile"],
      test: ["test --cover"],
      "test.watch": ["test.watch --cover"],
      "test.coverage": ["coveralls.html"],
      "test.ci": ["coveralls.json"],
      "test.detail": ["coveralls.detail"],

      # Quality assurance
      quality: ["format", "credo --strict", "dialyzer", "test.coverage"],
      "quality.ci": [
        "format --check-formatted",
        "credo --strict",
        "dialyzer",
        "test.ci"
      ],

      # Documentation
      docs: ["docs --formatter html"],
      "docs.open": ["docs --open"]
    ]
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      source_url: @source_url,
      extras: [
        "README.md",
        "CHANGELOG.md",
        "docs/configuration.md"
      ],
      groups_for_extras: [
        Guides: ~r/guides\/.?/
      ],
      groups_for_modules: [
        Core: [
          Vaultx.Application,
          Vaultx.Client,
          Vaultx.Types
        ],
        "Base Infrastructure": [
          Vaultx.Base.Config,
          Vaultx.Base.Error,
          Vaultx.Base.Features,
          Vaultx.Base.JSON,
          Vaultx.Base.Logger,
          Vaultx.Base.RateLimiter,
          Vaultx.Base.Security,
          Vaultx.Base.Telemetry
        ],
        "Transport & Infrastructure": [
          Vaultx.Transport.HTTPBehaviour,
          Vaultx.Transport.HTTP,
          Vaultx.Transport.Pool
        ],
        "Secrets Engines": [
          Vaultx.Secrets.AWS.Behaviour,
          Vaultx.Secrets.AWS,
          Vaultx.Secrets.AWS.Credentials,
          Vaultx.Secrets.Consul.Behaviour,
          Vaultx.Secrets.Consul,
          Vaultx.Secrets.KV.Behaviour,
          Vaultx.Secrets.KV,
          Vaultx.Secrets.KV.V1,
          Vaultx.Secrets.KV.V2,
          Vaultx.Secrets.PKI.Behaviour,
          Vaultx.Secrets.PKI.CA,
          Vaultx.Secrets.PKI.Certificates,
          Vaultx.Secrets.PKI,
          Vaultx.Secrets.RabbitMQ.Behaviour,
          Vaultx.Secrets.RabbitMQ,
          Vaultx.Secrets.TOTP.Behaviour,
          Vaultx.Secrets.TOTP,
          Vaultx.Secrets.Transit.Behaviour,
          Vaultx.Secrets.Transit.Encryption,
          Vaultx.Secrets.Transit.Keys,
          Vaultx.Secrets.Transit
        ],
        Authentication: [
          Vaultx.Auth.Behaviour,
          Vaultx.Auth.AliCloud,
          Vaultx.Auth.AppRole,
          Vaultx.Auth.AWS,
          Vaultx.Auth.Azure,
          Vaultx.Auth.GitHub,
          Vaultx.Auth.JWT,
          Vaultx.Auth.LDAP,
          Vaultx.Auth.UserPass,
          Vaultx.Auth.Token,
          Vaultx.Auth.TokenRenewal
        ],
        "System Backend": [
          Vaultx.Sys.Audit,
          Vaultx.Sys.AuditHash,
          Vaultx.Sys.Mounts,
          Vaultx.Sys.Remount,
          Vaultx.Sys.SealBackendStatus,
          Vaultx.Sys.SealStatus,
          Vaultx.Sys.Seal,
          Vaultx.Sys.Unseal,
          Vaultx.Sys.Health,
          Vaultx.Sys.Init,
          Vaultx.Sys.Leader,
          Vaultx.Sys.Leases,
          Vaultx.Sys.Monitor,
          Vaultx.Sys.Namespaces,
          Vaultx.Sys.Policy,
          Vaultx.Sys.Tools
        ]
      ]
    ]
  end

  defp package do
    [
      name: "vaultx",
      files: ~w(lib .formatter.exs mix.exs README* CHANGELOG* LICENSE*),
      licenses: ["MIT"],
      maintainers: ["fleey"],
      links: %{
        "GitHub" => @source_url,
        "Changelog" => "https://hexdocs.pm/vaultx/changelog.html"
      }
    ]
  end

  defp dialyzer do
    [
      plt_file: {:no_warn, "priv/plts/dialyzer.plt"},
      plt_add_apps: [:ex_unit, :mix],
      flags: [:error_handling, :underspecs, :unmatched_returns]
    ]
  end
end
