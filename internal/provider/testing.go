//go:build darwin

package provider

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

const (
	// TestKeychainName is the name of the test keychain file.
	TestKeychainName = "terraform-provider-keychain-test.keychain-db"

	// TestKeychainPassword is the password for the test keychain.
	TestKeychainPassword = "test"

	// ProviderConfig is the HCL configuration for the test provider.
	ProviderConfig = `
provider "keychain" {
  keychain_path = "%s"
  password      = "%s"
}
`
)

// ProtoV6ProviderFactories returns the provider factories for acceptance testing.
func ProtoV6ProviderFactories() map[string]func() (tfprotov6.ProviderServer, error) {
	return map[string]func() (tfprotov6.ProviderServer, error){
		"keychain": providerserver.NewProtocol6WithError(New("test")()),
	}
}

// GetTestKeychainPath returns the path to the test keychain.
func GetTestKeychainPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		panic("unable to get user home directory: " + err.Error())
	}
	return filepath.Join(home, "Library", "Keychains", TestKeychainName)
}

// SkipIfNoTestKeychain skips the test if the test keychain doesn't exist.
func SkipIfNoTestKeychain(t *testing.T) string {
	t.Helper()
	path := GetTestKeychainPath()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skipf("Test keychain not found at %s. Run scripts/create-test-keychain.sh --ci first.", path)
	}
	return path
}

// TestProviderConfig returns the formatted provider configuration for testing.
func TestProviderConfig() string {
	return providerConfigWithPath(GetTestKeychainPath())
}

func providerConfigWithPath(path string) string {
	return `
provider "keychain" {
  keychain_path = "` + path + `"
  password      = "` + TestKeychainPassword + `"
}
`
}
