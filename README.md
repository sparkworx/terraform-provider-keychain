# Terraform Provider: macOS Keychain

Manage secrets stored in macOS Keychains using Terraform.

## Overview

This provider enables infrastructure-as-code management of items stored in macOS Keychains. It supports reading and writing passwords, certificates, keys, and identities to any user-accessible keychain file.

### Use Cases

- **CI/CD Secrets Management**: Store and retrieve deployment credentials, API keys, and certificates from a dedicated keychain
- **Development Environment Setup**: Provision development keychains with required credentials as part of workstation automation
- **Certificate Lifecycle Management**: Manage code signing identities and certificates alongside your infrastructure

### Supported Item Types

| Resource | Description |
|----------|-------------|
| `keychain_generic_password` | Application passwords, API keys, tokens |
| `keychain_internet_password` | Web/network credentials with server, protocol, and port |
| `keychain_certificate` | X.509 certificates |
| `keychain_key` | Cryptographic keys (RSA, EC, AES) |
| `keychain_identity` | Certificate + private key pairs (PKCS#12) |

## Requirements

- macOS (uses Security.framework via cgo)
- Terraform >= 1.0
- Go >= 1.21 (for building from source)

## Installation

```bash
# Install dependencies
make deps

# Build and install locally
make install
```

## Usage

### Provider Configuration

```hcl
provider "keychain" {
  # Path to keychain file (optional, defaults to login keychain)
  keychain_path = "/Users/me/Library/Keychains/MyKeychain.keychain-db"

  # Password to unlock keychain (optional, can use KEYCHAIN_PASSWORD env var)
  password = var.keychain_password
}
```

### Managing a Generic Password

```hcl
resource "keychain_generic_password" "api_key" {
  service  = "my-application"
  account  = "api-user"
  password = var.api_password
  label    = "My Application API Key"
}
```

### Reading an Existing Password

```hcl
data "keychain_generic_password" "existing" {
  service = "existing-service"
  account = "existing-account"
}

output "password" {
  value     = data.keychain_generic_password.existing.password
  sensitive = true
}
```

## Security Considerations

Keychain passwords and secrets are stored in Terraform state. To protect sensitive data:

- Use an encrypted remote state backend (S3 + KMS, Terraform Cloud, etc.)
- Never commit state files to version control
- Mark secret outputs with `sensitive = true`
- Use environment variables for the provider password (`KEYCHAIN_PASSWORD`)

## Development

```bash
make deps          # Install dependencies
make build-all     # Build for ARM64 and AMD64
make test          # Run unit tests
make test-acc      # Run acceptance tests
make lint          # Run linter
make security      # Run security scans
```

## macOS API Deprecation Notice

When building this provider, you may see compiler warnings about deprecated macOS Security.framework APIs (`SecKeychainOpen`, `SecKeychainUnlock`, etc.). These warnings are expected.

**Why we use these APIs:** Apple deprecated the `SecKeychain` functions in macOS 10.10, recommending the `SecItem` API instead. However, `SecItem` cannot open a specific keychain file by path—it only operates on the default keychain or search list. Since this provider must access user-specified keychain files, we use the older API.

**What this means for you:** These APIs continue to work on all current macOS versions and are used by Apple's own `security` command-line tool. We will adapt to any future API changes Apple makes.

## Motivation

I really needed a way to break the chicken-and-egg cycle of using Terraform to manage secrets without resorting to trusting everything to various backends. To that end, I now have something that I can use as a data source to populate Azure Key Vaults, AWS KMS/ACM/Secrets, etc., for my personal projects. I hope you find this useful, too.

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.
