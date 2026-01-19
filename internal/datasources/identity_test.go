//go:build darwin

package datasources_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/sparkworx/terraform-provider-keychain/internal/provider"
	"software.sslmate.com/src/go-pkcs12"
)

// generateTestP12ForDS creates a self-signed certificate with private key as PKCS#12
func generateTestP12ForDS(cn string, password string) ([]byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}

	// Encode as PKCS#12 using legacy encoding for macOS compatibility
	pfxData, err := pkcs12.Legacy.Encode(priv, cert, nil, password)
	if err != nil {
		return nil, err
	}

	return pfxData, nil
}

func TestAccIdentityDataSource_basic(t *testing.T) {
	provider.SkipIfNoTestKeychain(t)

	label := "test-acc-ds-identity-basic"
	password := "test123"

	p12Data, err := generateTestP12ForDS(label+".example.com", password)
	if err != nil {
		t.Fatalf("Failed to generate test P12: %v", err)
	}
	p12DataB64 := base64.StdEncoding.EncodeToString(p12Data)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: provider.ProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				// First, create a resource to read
				Config: testAccIdentityResourceConfig(label, p12DataB64, password),
			},
			{
				// Then read it with the data source
				Config: testAccIdentityResourceAndDataSourceConfig(label, p12DataB64, password),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.keychain_identity.test", "label", label),
					resource.TestCheckResourceAttr("data.keychain_identity.test", "id", label),
					resource.TestCheckResourceAttrSet("data.keychain_identity.test", "subject"),
					resource.TestCheckResourceAttrSet("data.keychain_identity.test", "issuer"),
					resource.TestCheckResourceAttrSet("data.keychain_identity.test", "serial_number"),
					resource.TestCheckResourceAttrSet("data.keychain_identity.test", "not_before"),
					resource.TestCheckResourceAttrSet("data.keychain_identity.test", "not_after"),
					resource.TestCheckResourceAttrSet("data.keychain_identity.test", "fingerprint_sha1"),
					resource.TestCheckResourceAttrSet("data.keychain_identity.test", "fingerprint_sha256"),
					resource.TestCheckResourceAttr("data.keychain_identity.test", "key_type", "ec"),
					resource.TestCheckResourceAttr("data.keychain_identity.test", "key_size_bits", "256"),
				),
			},
		},
	})
}

func TestAccIdentityDataSource_readExisting(t *testing.T) {
	provider.SkipIfNoTestKeychain(t)

	label := "test-acc-ds-identity-existing"
	password := "test123"

	p12Data, err := generateTestP12ForDS(label+".example.com", password)
	if err != nil {
		t.Fatalf("Failed to generate test P12: %v", err)
	}
	p12DataB64 := base64.StdEncoding.EncodeToString(p12Data)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: provider.ProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				// Create a resource and data source in the same config
				Config: testAccIdentityResourceAndDataSourceConfig(label, p12DataB64, password),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Verify data source reads the same values as the resource
					resource.TestCheckResourceAttrPair(
						"keychain_identity.test", "label",
						"data.keychain_identity.test", "label",
					),
					resource.TestCheckResourceAttrPair(
						"keychain_identity.test", "subject",
						"data.keychain_identity.test", "subject",
					),
					resource.TestCheckResourceAttrPair(
						"keychain_identity.test", "issuer",
						"data.keychain_identity.test", "issuer",
					),
					resource.TestCheckResourceAttrPair(
						"keychain_identity.test", "key_type",
						"data.keychain_identity.test", "key_type",
					),
					resource.TestCheckResourceAttrPair(
						"keychain_identity.test", "key_size_bits",
						"data.keychain_identity.test", "key_size_bits",
					),
				),
			},
		},
	})
}

func testAccIdentityResourceConfig(label, pkcs12Data, password string) string {
	return provider.TestProviderConfig() + fmt.Sprintf(`
resource "keychain_identity" "test" {
  label       = %q
  pkcs12_data = %q
  password    = %q
}
`, label, pkcs12Data, password)
}

func testAccIdentityResourceAndDataSourceConfig(label, pkcs12Data, password string) string {
	return testAccIdentityResourceConfig(label, pkcs12Data, password) + fmt.Sprintf(`
data "keychain_identity" "test" {
  label = %q

  depends_on = [keychain_identity.test]
}
`, label)
}
