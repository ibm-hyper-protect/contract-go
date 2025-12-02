# Contributing to contract-go

Thank you for considering contributing to `contract-go`! We appreciate your time and effort in helping improve this project. This guide will help you understand our development process and how to contribute effectively.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Commit Messages](#commit-messages)
- [Pull Request Process](#pull-request-process)
- [Testing](#testing)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Enhancements](#suggesting-enhancements)
- [Questions](#questions)

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the maintainers listed in [MAINTAINERS.md](MAINTAINERS.md).

## How Can I Contribute?

### Reporting Bugs

We use GitHub issue templates to ensure we collect all necessary information. To report a bug:

1. **Check for existing issues**: Search [existing issues](https://github.com/ibm-hyper-protect/contract-go/issues) to avoid duplicates
2. **Use the bug report template**: Click [here](https://github.com/ibm-hyper-protect/contract-go/issues/new?template=bug_report.yml) or select "Bug Report" when creating a new issue
3. **Fill out all required fields**: The template will guide you through providing:
   - Bug description and impact
   - Steps to reproduce
   - Expected vs actual behavior
   - Code samples demonstrating the issue
   - Environment details (Go version, OS, OpenSSL version, etc.)
   - Target platform (HPVS, HPCR-RHVS, HPCC-PeerPod)

**Important**: For security vulnerabilities, **do NOT create a public issue**. Instead, report them via [GitHub Security Advisories](https://github.com/ibm-hyper-protect/contract-go/security/advisories/new) or follow our [Security Policy](SECURITY.md).

### Suggesting Enhancements

To suggest a new feature or enhancement:

1. **Check for existing requests**: Search [existing issues](https://github.com/ibm-hyper-protect/contract-go/issues) to see if it's already been suggested
2. **Use the feature request template**: Click [here](https://github.com/ibm-hyper-protect/contract-go/issues/new?template=feature_request.yml) or select "Feature Request" when creating a new issue
3. **Provide detailed information**: The template will guide you through:
   - Problem statement and motivation
   - Proposed solution
   - Alternatives considered
   - Use cases and examples
   - Expected API usage
   - Priority and impact assessment

### Asking Questions

If you have questions about using the library:

1. **Check the documentation first**: Review our [API documentation](docs/README.md) and [examples](samples/)
2. **Search existing Q&A**: Look through [closed issues](https://github.com/ibm-hyper-protect/contract-go/issues?q=is%3Aissue+label%3Aquestion) with the "question" label
3. **Use GitHub Discussions**: For general questions, use [GitHub Discussions](https://github.com/ibm-hyper-protect/contract-go/discussions)
4. **Create a question issue**: If needed, use our [question template](https://github.com/ibm-hyper-protect/contract-go/issues/new?template=question.yml)

### Code Contributions

We actively welcome your pull requests! However, please follow this process:

1. **Open an issue first** - Before submitting a pull request, open an issue describing:
   - What bug you're fixing or feature you're adding
   - Why it should be fixed or added
   - How you plan to implement it

   This helps us discuss the approach early and avoid duplicated or unnecessary work.

   **Pull requests without a linked issue may be closed.**

2. **Get feedback** - Wait for maintainer feedback on your issue before starting work.

3. **Fork and create a branch** - Once approved, fork the repo and create a feature branch.

4. **Implement your changes** - Follow our coding standards and best practices.

5. **Test thoroughly** - Add tests for your changes and ensure all tests pass.

6. **Submit a pull request** - Reference the original issue in your PR description.

## Getting Started

### Prerequisites

- **Go 1.24.7 or later**
- **OpenSSL** - Required for encryption operations
- **Make** - For running build commands
- **Git** - For version control

### Development Setup

1. **Fork the repository** on GitHub

2. **Clone your fork**:
   ```bash
   git clone https://github.com/YOUR-USERNAME/contract-go.git
   cd contract-go
   ```

3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/ibm-hyper-protect/contract-go.git
   ```

4. **Install dependencies**:
   ```bash
   make install-deps
   ```

5. **Verify your setup**:
   ```bash
   make test
   ```

## Development Workflow

1. **Create a feature branch** from `main`:
   ```bash
   git checkout main
   git pull upstream main
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following our [coding standards](#coding-standards)

3. **Run tests** frequently during development:
   ```bash
   make test
   ```

4. **Tidy dependencies**:
   ```bash
   make tidy
   ```

5. **Format your code** as per standards:
   ```bash
   make fmt
   ```

6. **Commit your changes** with [proper commit messages](#commit-messages)

7. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

8. **Open a Pull Request** from your fork to the main repository

## Coding Standards

### Go Style Guide

- Follow the official [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- Use `gofmt` (run `make fmt`) to format your code (run automatically with most editors)
- Follow [Effective Go](https://golang.org/doc/effective_go) principles
- Write idiomatic Go code

### Best Practices

- **Keep functions small and focused** - Each function should do one thing well
- **Write self-documenting code** - Use clear variable and function names
- **Add comments for complex logic** - Explain the "why", not the "what"
- **Handle errors explicitly** - Never ignore errors
- **Use meaningful package names** - Short, lowercase, no underscores
- **Export only what's necessary** - Keep internal implementation private

### Documentation

- **Add GoDoc comments** for all exported functions, types, and constants
- **Include examples** in documentation where helpful
- **Update README.md** if adding new features
- **Update docs/README.md** with detailed API documentation

### Example of Good Documentation

```go
// HpcrContractSignedEncrypted generates a signed and encrypted contract.
// It validates the contract schema, encrypts the workload and environment sections,
// and signs them with the provided private key.
//
// Parameters:
//   - contract: YAML contract string
//   - hyperProtectOs: Target platform (hpvs, hpcr-rhvs, or hpcc-peerpod)
//   - encryptionCertificate: Optional encryption certificate (uses default if empty)
//   - privateKey: RSA private key for signing
//
// Returns:
//   - Signed and encrypted contract string
//   - Input SHA256 checksum
//   - Output SHA256 checksum
//   - Error if any operation fails
func HpcrContractSignedEncrypted(contract, hyperProtectOs, encryptionCertificate, privateKey string) (string, string, string, error) {
    // Implementation
}
```

## Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/) specification:

### Format

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### Types

- `feat:` - A new feature
- `fix:` - A bug fix
- `docs:` - Documentation only changes
- `refactor:` - Code changes that neither fix a bug nor add a feature
- `perf:` - Performance improvements
- `test:` - Adding or updating tests
- `chore:` - Changes to build process, dependencies, etc.
- `ci:` - CI/CD configuration changes

### Examples

```
feat(contract): add support for contract expiry validation

fix(attestation): handle null values in attestation records

docs: update README with new installation instructions

test(image): add tests for version constraint parsing
```

### Guidelines

- **Use imperative mood** - "add feature" not "added feature"
- **Keep subject line under 50 characters**
- **Capitalize the subject line**
- **Don't end subject line with a period**
- **Separate subject from body with a blank line**
- **Use body to explain what and why, not how**
- **Reference issues** (e.g., "Fixes #123")

## Pull Request Process

### Before Submitting

- [ ] Link to the related issue in your PR description
- [ ] Ensure all tests pass (`make test`)
- [ ] Run `make tidy` to clean up dependencies
- [ ] Run `make fmt` to format code
- [ ] Update documentation if needed
- [ ] Add or update tests for your changes
- [ ] Follow the commit message conventions
- [ ] Rebase your branch on the latest `main` if needed

### PR Template

When opening a PR, include:

```markdown
## Description
Brief description of the changes

## Related Issue
Fixes #issue_number

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
Describe the tests you ran and how to reproduce them

## Checklist
- [ ] My code follows the project's coding standards
- [ ] I have performed a self-review of my code
- [ ] I have commented my code where necessary
- [ ] I have updated the documentation
- [ ] I have added tests that prove my fix/feature works
- [ ] All new and existing tests pass
```

### Review Process

1. **Automated checks** - CI must pass before review
2. **Maintainer review** - Tag @Sashwat-K and @vikas-sharma24 as a reviewer
3. **Address feedback** - Make requested changes promptly
4. **Approval** - At least one maintainer must approve
5. **Merge** - Maintainers will merge your PR

### After Your PR is Merged

- Delete your feature branch
- Update your local repository:
  ```bash
  git checkout main
  git pull upstream main
  ```

## Testing

### Running Tests

```bash
# Run all tests
make test

# Run tests with coverage
make test-cover

# Run specific package tests
go test ./contract -v

# Run specific test
go test ./contract -v -run TestHpcrText
```

### Writing Tests

- **Write tests for all new code** - Aim for good coverage
- **Use table-driven tests** where appropriate
- **Test edge cases** and error conditions
- **Use meaningful test names** - `TestFunctionName_Scenario_ExpectedBehavior`
- **Keep tests independent** - Tests should not depend on each other

### Example Test

```go
func TestHpcrText(t *testing.T) {
    tests := []struct {
        name      string
        input     string
        wantErr   bool
        errMsg    string
    }{
        {
            name:    "valid text input",
            input:   "test data",
            wantErr: false,
        },
        {
            name:    "empty input",
            input:   "",
            wantErr: true,
            errMsg:  "required parameter is empty",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            encoded, inputHash, outputHash, err := HpcrText(tt.input)
            if tt.wantErr {
                require.Error(t, err)
                assert.Contains(t, err.Error(), tt.errMsg)
            } else {
                require.NoError(t, err)
                assert.NotEmpty(t, encoded)
                assert.NotEmpty(t, inputHash)
                assert.NotEmpty(t, outputHash)
            }
        })
    }
}
```

## Questions?

If you have questions about contributing:

1. Check the [documentation](docs/README.md)
2. Search [existing issues](https://github.com/ibm-hyper-protect/contract-go/issues)
3. Open a new issue with the `question` label
4. Reach out to the maintainers listed in [MAINTAINERS.md](MAINTAINERS.md)

## License

By contributing to `contract-go`, you agree that your contributions will be licensed under the Apache License 2.0.

---

Thank you for contributing to contract-go! Your efforts help make this project better for everyone.
