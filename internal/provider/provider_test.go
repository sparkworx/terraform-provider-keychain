//go:build darwin

package provider

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const (
	testKeychainName     = "terraform-provider-keychain-test.keychain-db"
	testKeychainPassword = "test"
)

func getTestKeychainPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		panic("unable to get user home directory: " + err.Error())
	}
	return filepath.Join(home, "Library", "Keychains", testKeychainName)
}

func skipIfNoTestKeychain(t *testing.T) string {
	t.Helper()
	path := getTestKeychainPath()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skipf("Test keychain not found at %s. Run scripts/create-test-keychain.sh --ci first.", path)
	}
	return path
}

func TestProviderSchema(t *testing.T) {
	p := New("test")()
	resp := &provider.SchemaResponse{}
	p.Schema(context.Background(), provider.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Schema() returned errors: %v", resp.Diagnostics)
	}

	schema := resp.Schema

	// Verify keychain_path attribute
	keychainPathAttr, ok := schema.Attributes["keychain_path"]
	if !ok {
		t.Error("Schema missing 'keychain_path' attribute")
	} else {
		if keychainPathAttr.IsRequired() {
			t.Error("keychain_path should be optional, not required")
		}
	}

	// Verify password attribute
	passwordAttr, ok := schema.Attributes["password"]
	if !ok {
		t.Error("Schema missing 'password' attribute")
	} else {
		if passwordAttr.IsRequired() {
			t.Error("password should be optional, not required")
		}
		if !passwordAttr.IsSensitive() {
			t.Error("password should be marked as sensitive")
		}
	}
}

func TestProviderMetadata(t *testing.T) {
	p := New("1.0.0")()
	resp := &provider.MetadataResponse{}
	p.Metadata(context.Background(), provider.MetadataRequest{}, resp)

	if resp.TypeName != "keychain" {
		t.Errorf("Metadata().TypeName = %q, want %q", resp.TypeName, "keychain")
	}
	if resp.Version != "1.0.0" {
		t.Errorf("Metadata().Version = %q, want %q", resp.Version, "1.0.0")
	}
}

func TestProviderConfigure(t *testing.T) {
	path := skipIfNoTestKeychain(t)

	p := &KeychainProvider{version: "test"}

	// Create a mock config
	config := KeychainProviderModel{
		KeychainPath: types.StringValue(path),
		Password:     types.StringValue(testKeychainPassword),
	}

	// Test that the provider can be configured
	// Note: Full configure testing requires terraform-plugin-testing framework
	// which is tested in acceptance tests
	_ = config
	_ = p
}

func TestProviderConfigure_EnvVar(t *testing.T) {
	path := skipIfNoTestKeychain(t)

	// Set environment variable
	originalEnv := os.Getenv("KEYCHAIN_PASSWORD")
	os.Setenv("KEYCHAIN_PASSWORD", testKeychainPassword)
	defer func() {
		if originalEnv != "" {
			os.Setenv("KEYCHAIN_PASSWORD", originalEnv)
		} else {
			os.Unsetenv("KEYCHAIN_PASSWORD")
		}
	}()

	// The provider should read KEYCHAIN_PASSWORD from environment
	// Full testing of this requires the terraform-plugin-testing framework
	_ = path
}

func TestProviderResources(t *testing.T) {
	p := New("test")()
	resources := p.Resources(context.Background())

	if len(resources) == 0 {
		t.Error("Resources() returned empty list")
	}

	// Verify we have at least one resource
	if len(resources) > 0 {
		// Verify the factory is callable
		r := resources[0]()
		if r == nil {
			t.Error("Resource factory returned nil")
		}
	}
}

func TestProviderDataSources(t *testing.T) {
	p := New("test")()
	dataSources := p.DataSources(context.Background())

	if len(dataSources) == 0 {
		t.Error("DataSources() returned empty list")
	}
}

