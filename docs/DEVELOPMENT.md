# Development Guide

## Table of Contents
- [Setup and Configuration](#setup-and-configuration)
  - [Prerequisites](#prerequisites)
  - [Quick Start](#quick-start)
- [Development Workflow](#development-workflow)
  - [Available Commands](#available-commands)
  - [Code Quality](#code-quality)
- [Issuer Signer Certificate](#issuer-signer-certificate)
- [Start the Server](#start-the-server)
- [Build](#build)
- [Tag and Release](#tag-and-release-a-new-version)

## Setup and Configuration

### Prerequisites

- [mise](https://mise.jdx.dev/) - Tool version manager
- [just](https://github.com/casey/just) - Command runner (installed via mise)

### Quick Start

```shell
# Install all development tools
mise install

# Setup shared linting tools
just setup-devtools

# Run all quality checks
just verify
```

## Development Workflow

### Available Commands

Run `just` to see all available commands. Key commands:

| Command | Description |
|---------|-------------|
| `just verify` | Run all checks (lint + test) |
| `just lint-all` | Run all linters |
| `just lint-fix` | Auto-fix linting issues |
| `just test` | Run tests (mvn verify) |
| `just build` | Build project |
| `just clean` | Clean build artifacts |

#### Linting Commands

| Command | Tool | Description |
|---------|------|-------------|
| `just lint-commits` | conform | Validate commit messages |
| `just lint-secrets` | gitleaks | Scan for secrets |
| `just lint-yaml` | yamlfmt | Lint YAML files |
| `just lint-markdown` | rumdl | Lint markdown files |
| `just lint-shell` | shellcheck | Lint shell scripts |
| `just lint-shell-fmt` | shfmt | Check shell formatting |
| `just lint-actions` | actionlint | Lint GitHub Actions |
| `just lint-license` | reuse | Check license compliance |
| `just lint-xml` | xmllint | Validate XML files |
| `just lint-container` | hadolint | Lint Containerfile |
| `just lint-java` | Maven | Run all Java linters |
| `just lint-java-checkstyle` | checkstyle | Java style checks |
| `just lint-java-pmd` | pmd | Java static analysis |
| `just lint-java-spotbugs` | spotbugs | Java bug detection |
| `just lint-java-fmt` | formatter | Check Java formatting |

#### Fix Commands

| Command | Description |
|---------|-------------|
| `just lint-yaml-fix` | Fix YAML formatting |
| `just lint-markdown-fix` | Fix markdown formatting |
| `just lint-shell-fmt-fix` | Fix shell formatting |
| `just lint-java-fmt-fix` | Fix Java formatting |

### Code Quality

Run all quality checks before submitting a PR:

```shell
# Run all checks
just verify

# Or run linting only
just lint-all

# Auto-fix where possible
just lint-fix
```

#### Quality Check Details

- **Java Linting**: Checkstyle, PMD, SpotBugs
- **General Linting**: Shell, YAML, Markdown, GitHub Actions, XML
- **Container Linting**: Hadolint for Containerfile
- **Security**: Secret scanning with gitleaks
- **License Compliance**: REUSE tool ensures proper copyright information
- **Commit Structure**: Conform checks commit messages for changelog generation

## Issuer Signer Certificate

Generate private key in PKCS#8 format:
```shell
openssl genpkey -algorithm EC \
  -pkeyopt ec_paramgen_curve:prime256v1 \
  -out issuer_private_pkcs8.key
```

Extract public key:
```shell
openssl pkey -in issuer_private_pkcs8.key -pubout -out issuer_public.key
```

Create self-signed certificate using PKCS#8 key:
```shell
openssl req -new -x509 \
  -key issuer_private_pkcs8.key \
  -out issuer-certificate.crt \
  -days 365 \
  -subj "/CN=local.dev.swedenconnect.se" \
  -addext "subjectAltName = DNS:local.dev.swedenconnect.se" \
  -addext "keyUsage = Digital Signature"
```

Make sure application.properties in the active profile has proper key pair config:
```yaml
credential:
  bundles:
    pem:
      issuercredential:
        private-key: file:./keystores/issuer_private_pkcs8.key
        certificates: file:./keystores/issuer-certificate.crt
        name: "Issuer credential"
  bundle:
    monitoring:
      health-endpoint-enabled: true
```

## Start the Server

### Command Line

```shell
SPRING_PROFILES_ACTIVE=dev mvn spring-boot:run
```

### Docker Compose

See [quick-start](../dev-environment/compose/quick-start.md)
```shell
cd dev-environment/compose
docker-compose --profile ewc up
```

The DemoTestsController can not run in compose.

## Build

```shell
# Using just
just build

# Or using Maven directly
mvn clean verify
```

## Tag and Release a New Version

Activate the GH-workflow with a tag and push:

```shell
git tag -s v0.0.32 -m 'v0.0.32'
git push origin tag v0.0.32
```

The workflow sets the POM version and generates a changelog.
