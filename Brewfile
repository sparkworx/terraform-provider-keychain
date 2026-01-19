# Terraform Provider: macOS Keychain - Development Dependencies
# Install with: brew bundle

# Required - Core Build Tools
brew "go"                    # Go 1.21+ required for terraform-plugin-framework
brew "terraform"             # For running acceptance tests

# Required - Code Quality
brew "golangci-lint"         # Go linter aggregator (includes staticcheck, gosimple, etc.)

# Required - Security Scanning
brew "gosec"                 # Go security checker - finds security issues in Go code
brew "govulncheck"           # Official Go vulnerability checker for dependencies
brew "gitleaks"              # Scans for hardcoded secrets in git history
brew "trivy"                 # Comprehensive vulnerability scanner (deps, secrets, misconfig)

# Optional but Recommended
brew "goreleaser"            # Automates release builds and checksums
brew "jq"                    # JSON processing for scripts
brew "pre-commit"            # Git hooks for code quality and security checks

# Xcode Command Line Tools (required for cgo cross-compilation)
# Install separately with: xcode-select --install
