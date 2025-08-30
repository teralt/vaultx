# Changelog

All notable changes to VaultX will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2025-08-21

**Major Release**: Enhanced Auth Methods, new secrets engines, and production readiness improvements.

### Added

#### Auth Methods

- **UserPass**: Username and password authentication support
- **Azure**: Azure Active Directory authentication integration

#### Secrets Engines

- **Consul**: HashiCorp Consul secrets engine for dynamic service credentials
- **RabbitMQ**: RabbitMQ secrets engine for dynamic messaging credentials
- **TOTP**: Time-based One-Time Password generation and validation

#### System Backend

- **Policies**: Comprehensive policy management (ACL, RGP, EGP)
- **Enhanced Configuration**: Advanced configuration validation and diagnostics
- **Security**: Rate limiting with token bucket algorithm and security headers validation

#### Development & Operations

- **GitHub Actions**: Automated CI/CD pipeline with testing and release automation
- **Test Coverage**: Comprehensive test coverage improvements across all modules

### Changed

#### Performance Optimizations

- **JSON Processing**: Migrated from Jason to Elixir's native JSON for better performance
- **Architecture**: Improved Secret Engine Behaviour patterns with better inheritance
- **HTTP Transport**: Optimized transport layer for enhanced performance

#### Code Quality & Architecture

- **Behaviour Patterns**: Removed generic Behaviour in favor of engine-specific implementations
- **Testing Strategy**: Enhanced test suite using http_helper instead of mocks for better reliability
- **Error Handling**: Improved error handling and recovery mechanisms
- **Configuration**: Refined configuration management system

#### Documentation & Release Preparation

- **Documentation**: Comprehensive documentation overhaul with examples and best practices
- **Public Release**: Codebase prepared and optimized for community release
- **Telemetry**: Enhanced observability features

### Fixed

- SSL/TLS certificate handling improvements
- Connection pool management enhancements
- Various stability and reliability improvements

### Migration Notes

- **JSON Library**: Applications using Jason directly may need to update imports
- **Behaviour Patterns**: Custom secret engines should migrate to engine-specific behaviours
- **Configuration**: Review configuration settings for new validation requirements

### Future Considerations

- **Consul Integration**: Evaluating dedicated HashiCorp Consul library development
- **Community Feedback**: Prioritizing community-driven enhancements post-release

## [0.5.0] - 2025-06-28

**Feature Release**: Extended Auth Methods and comprehensive testing improvements.

### Added

#### Auth Methods

- **AliCloud**: Alibaba Cloud authentication integration
- **GitHub**: GitHub organization-based authentication

#### Testing & Quality

- Comprehensive test suite expansion with significantly improved coverage
- Enhanced test reliability and performance across all modules

#### Configuration & Documentation

- Enhanced configuration system with additional options and validation
- Complete documentation overhaul with detailed examples and best practices
- Enhanced API documentation with comprehensive examples

### Changed

- **Configuration**: Optimized management with better environment variable support
- **Authentication**: Improved authentication flow reliability and error handling

### Fixed

- Authentication method error handling improvements
- Configuration validation enhancements
- Various stability and reliability fixes

## [0.4.0] - 2025-05-27

**Foundation Release**: Major architectural improvements and AWS authentication enhancements.

### Added

#### Auth Methods

- **AWS**: Enhanced AWS IAM authentication with additional features and improved reliability

#### Testing & Documentation

- Significant test coverage improvements across the entire codebase
- Comprehensive documentation updates and additions

### Changed

#### Architecture & Performance

- **Major Refactoring**: Structural improvements for better maintainability and performance
- **Code Organization**: Enhanced module separation and boundaries
- **Core Operations**: Optimized for better efficiency and reliability

### Fixed

- Architectural stability improvements
- Module dependency optimization
- Error handling pattern enhancements

---

## Earlier Versions

**Note**: Versions prior to 0.4.0 are not documented in this changelog due to migration from a private repository. For historical information about earlier versions, please refer to the project's git commit history.

## Links

- [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
- [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
- [VaultX Repository](https://github.com/teralt/vaultx)
