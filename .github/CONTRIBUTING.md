# Contributing to VaultX

We are delighted to have anyone contribute to VaultX, regardless of their skill level or background. We welcome contributions both large and small, from typos and documentation improvements, to bug fixes and features. There is a place for everyone's contribution here.

**Before contributing, please ensure you have read our [Code of Conduct](.github/CODE_OF_CONDUCT.md).**

## Contribution Types

VaultX follows conventional commit types for organizing contributions:

- **build**: Changes that affect the build system or external dependencies
- **chore**: Other changes that don't modify src or test files
- **ci**: Changes to CI configuration files and scripts
- **docs**: Documentation only changes
- **feat**: A new feature
- **fix**: A bug fix
- **perf**: A code change that improves performance
- **refactor**: A code change that neither fixes a bug nor adds a feature
- **style**: Changes that do not affect the meaning of the code (white-space, formatting, etc)
- **test**: Adding missing tests or correcting existing tests

## Quality Requirements

### For Substantial Changes (feat, fix, perf, refactor)

For any contribution that involves functional changes or substantial modifications:

1. **Tests Must Pass**: Ensure `mix test` passes completely
2. **Test Coverage**: Maintain project test coverage at **99% or above**
3. **Coverage Exclusions**: If you need to exclude code from coverage using `# coveralls-ignore`, you must:
   - Add a comment explaining why the code is excluded
   - Document the reason in your PR description
4. **Code Formatting**: Run `mix format` before submitting

### For Non-Substantial Changes (docs, style, chore, etc)

For documentation, styling, or other non-functional changes:

1. **Brief Description**: Provide a clear, concise description of the change
2. **Follow Guidelines**: Ensure changes align with project conventions
3. **Code Formatting**: Run `mix format` if applicable

## Development Workflow

### Setting Up Your Development Environment

VaultX uses [mise](https://mise.jdx.dev/) for consistent development environments.

#### Prerequisites

- **Elixir**: ~> 1.18.4
- **OTP**: ~> 28.0.2
- **mise**: For version management (recommended)

#### Quick Setup with mise

1. **Fork and clone the repository:**

   ```bash
   git clone https://github.com/your-username/vaultx.git
   cd vaultx
   ```

2. **Install required versions (if using mise):**

   ```bash
   mise install
   ```

3. **Install dependencies:**

   ```bash
   mix deps.get
   ```

4. **Compile the project:**

   ```bash
   mix compile
   ```

#### Alternative Setup (without mise)

If you prefer to manage versions manually, ensure you have:

- Elixir 1.18.4+ with OTP 28.0.2+
- Then follow steps 3-4 above

### Running Tests and Checks

Before submitting any pull request, run the full test suite:

#### Using mise (Recommended)

```bash
# Run tests
mise run test

# Run tests with coverage
mise run coverage

# Format code
mise run format

# Run comprehensive checks
mise run check

# Release readiness check
mise run release-check
```

#### Using mix directly

```bash
# Run tests
mix test

# Test coverage analysis
mix test --cover

# Format code
mix format

# Check formatting
mix format --check-formatted
```

### Testing with Coverage Requirements

VaultX maintains a strict 99% test coverage requirement. To check coverage:

```bash
mix test --cover
```

If you need to exclude specific lines from coverage, use `# coveralls-ignore`:

```elixir
# This function handles edge case that cannot be reliably tested
# coveralls-ignore-start
def handle_untestable_edge_case do
  # Implementation
end
# coveralls-ignore-stop
```

**Important**: Always document why code is excluded from coverage in both the code comment and your PR description.

### Development Workflow

1. **Create a feature branch:**

   ```bash
   git checkout -b feat/your-feature-name
   # or
   git checkout -b fix/issue-description
   ```

2. **Make your changes** and write comprehensive tests

3. **Run tests and ensure coverage:**

   ```bash
   mix test --cover
   ```

4. **Format your code:**

   ```bash
   mix format
   ```

5. **Commit your changes with conventional commit format:**

   ```bash
   git add .
   git commit -m "feat: add new authentication method"
   # or
   git commit -m "fix: resolve token renewal issue"
   # or
   git commit -m "docs: update configuration examples"
   ```

6. **Push and create a pull request**

## Contributing to Documentation

Documentation contributions are highly valued! You can contribute to:

- **README.md**: Project overview and quick start guide
- **docs/**: Detailed documentation and guides
- **Module documentation**: Inline documentation in source code
- **Examples**: Code examples and usage patterns

### Making Documentation Changes

For most documentation changes, you can use GitHub's web interface:

1. Navigate to the file you want to edit
2. Click the pencil icon (✏️) to edit
3. Make your changes
4. Submit a pull request

For larger documentation restructuring, please open an issue first to discuss the changes.

## Rules and Guidelines

- **Code of Conduct**: We have zero tolerance for failure to abide by our [Code of Conduct](.github/CODE_OF_CONDUCT.md)
- **Issues**: Issues may be opened to propose new ideas, ask questions, or file bugs
- **Feature Proposals**: Before working on a feature, please discuss it with the community via an issue. Focus on the **use case** rather than the proposed implementation
- **Claim Work**: Comment on issues you'd like to work on to avoid duplicate efforts
- **Communication**: Join our community discussions for questions and collaboration

## Testing VaultX with Your Application

To test your VaultX changes with your own application, use a local dependency in your `mix.exs`:

```elixir
defp deps do
  [
    # Replace hex dependency with local path
    {:vaultx, path: "../vaultx"},
    # Your other dependencies...
  ]
end
```

Then run:

```bash
mix deps.get
mix compile
```

**Note**: Testing in your own application is helpful but not sufficient. You must also include automated tests in the VaultX test suite.

## Common Development Tasks

### Using mise (Recommended)

- **Run tests**: `mise run test`
- **Run tests with coverage**: `mise run coverage`
- **Format code**: `mise run format`
- **Install dependencies**: `mise run deps`
- **Compile project**: `mise run compile`
- **Generate documentation**: `mise run docs`
- **Comprehensive checks**: `mise run check`
- **Release readiness**: `mise run release-check`

### Using mix directly

- **Run specific test file**: `mix test test/path/to/test_file.exs`
- **Run tests with coverage**: `mix test --cover`
- **Check formatting**: `mix format --check-formatted`
- **Generate documentation**: `mix docs`

## Pull Request Guidelines

When submitting a pull request:

1. **Use conventional commit format** in your PR title
2. **Provide clear description** of changes and motivation
3. **Reference related issues** using `Fixes #123` or `Closes #123`
4. **Include test coverage information** for substantial changes
5. **Document any coverage exclusions** and explain why they're necessary
6. **Ensure all checks pass** before requesting review

## Getting Help

- **Issues**: Open an issue for bugs, feature requests, or questions
- **Discussions**: Use GitHub Discussions for general questions
- **Community**: Join our community channels for real-time help

Thank you for contributing to VaultX! 🚀
