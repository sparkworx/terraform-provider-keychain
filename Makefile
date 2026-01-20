VERSION ?= 0.1.0
BINARY_NAME = terraform-provider-keychain

.PHONY: deps build-all build-arm64 build-amd64 install clean lint test test-acc security gosec govulncheck gitleaks trivy check generate docs

# Install dependencies via Homebrew
deps:
	brew bundle --file Brewfile
	@echo "Verifying Xcode Command Line Tools..."
	@xcode-select -p > /dev/null 2>&1 || (echo "Run: xcode-select --install" && exit 1)

build-all: build-arm64 build-amd64

build-arm64:
	@mkdir -p dist
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -o dist/$(BINARY_NAME)_v$(VERSION)_darwin_arm64

build-amd64:
	@mkdir -p dist
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -o dist/$(BINARY_NAME)_v$(VERSION)_darwin_amd64

install: build-all
	mkdir -p ~/.terraform.d/plugins/localhost/local/keychain/$(VERSION)/darwin_arm64
	mkdir -p ~/.terraform.d/plugins/localhost/local/keychain/$(VERSION)/darwin_amd64
	cp dist/$(BINARY_NAME)_v$(VERSION)_darwin_arm64 ~/.terraform.d/plugins/localhost/local/keychain/$(VERSION)/darwin_arm64/$(BINARY_NAME)
	cp dist/$(BINARY_NAME)_v$(VERSION)_darwin_amd64 ~/.terraform.d/plugins/localhost/local/keychain/$(VERSION)/darwin_amd64/$(BINARY_NAME)

lint:
	golangci-lint run

generate: docs

docs:
	go generate ./...

test:
	go test ./...

test-acc:
	go clean -testcache
	TF_ACC=1 go test ./... -v

# Security scanning targets
security: gosec govulncheck gitleaks trivy
	@echo "✅ All security checks passed"

gosec:
	@echo "🔍 Running gosec (Go security checker)..."
	gosec -exclude-dir=testdata -exclude-generated -fmt=text ./...

govulncheck:
	@echo "🔍 Running govulncheck (dependency vulnerabilities)..."
	govulncheck ./...

gitleaks:
	@echo "🔍 Running gitleaks (secret detection)..."
	gitleaks detect --source . --verbose

trivy:
	@echo "🔍 Running trivy (comprehensive scan)..."
	trivy fs --security-checks vuln,secret,config --severity HIGH,CRITICAL .

# Pre-release check: all quality and security
check: lint test security
	@echo "✅ All checks passed - ready for release"

clean:
	rm -rf dist/
