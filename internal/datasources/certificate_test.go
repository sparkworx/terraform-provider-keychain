//go:build darwin

package datasources_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/sparkworx/terraform-provider-keychain/internal/provider"
)

// generateTestCertPEM creates a self-signed certificate for testing
func generateTestCertPEMForDS(cn string) (string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return "", err
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	return string(pemBlock), nil
}

func TestAccCertificateDataSource_basic(t *testing.T) {
	provider.SkipIfNoTestKeychain(t)

	label := "test-acc-ds-cert-basic"
	certPEM, err := generateTestCertPEMForDS("test-ds-basic.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: provider.ProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				// First, create a resource to read
				Config: testAccCertificateResourceConfig(label, certPEM),
			},
			{
				// Then read it with the data source
				Config: testAccCertificateResourceAndDataSourceConfig(label, certPEM),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.keychain_certificate.test", "label", label),
					resource.TestCheckResourceAttr("data.keychain_certificate.test", "id", label),
					resource.TestCheckResourceAttrSet("data.keychain_certificate.test", "certificate"),
					resource.TestCheckResourceAttrSet("data.keychain_certificate.test", "subject"),
					resource.TestCheckResourceAttrSet("data.keychain_certificate.test", "issuer"),
					resource.TestCheckResourceAttrSet("data.keychain_certificate.test", "serial_number"),
					resource.TestCheckResourceAttrSet("data.keychain_certificate.test", "not_before"),
					resource.TestCheckResourceAttrSet("data.keychain_certificate.test", "not_after"),
					resource.TestCheckResourceAttrSet("data.keychain_certificate.test", "fingerprint_sha1"),
					resource.TestCheckResourceAttrSet("data.keychain_certificate.test", "fingerprint_sha256"),
				),
			},
		},
	})
}

func TestAccCertificateDataSource_readExisting(t *testing.T) {
	provider.SkipIfNoTestKeychain(t)

	label := "test-acc-ds-cert-existing"
	certPEM, err := generateTestCertPEMForDS("test-ds-existing.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: provider.ProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				// Create a resource and data source in the same config
				Config: testAccCertificateResourceAndDataSourceConfig(label, certPEM),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Verify data source reads the same values as the resource
					resource.TestCheckResourceAttrPair(
						"keychain_certificate.test", "label",
						"data.keychain_certificate.test", "label",
					),
					resource.TestCheckResourceAttrPair(
						"keychain_certificate.test", "subject",
						"data.keychain_certificate.test", "subject",
					),
					resource.TestCheckResourceAttrPair(
						"keychain_certificate.test", "issuer",
						"data.keychain_certificate.test", "issuer",
					),
					resource.TestCheckResourceAttrPair(
						"keychain_certificate.test", "fingerprint_sha256",
						"data.keychain_certificate.test", "fingerprint_sha256",
					),
				),
			},
		},
	})
}

func testAccCertificateResourceConfig(label, certPEM string) string {
	return provider.TestProviderConfig() + fmt.Sprintf(`
resource "keychain_certificate" "test" {
  label       = %q
  certificate = %q
}
`, label, certPEM)
}

func testAccCertificateResourceAndDataSourceConfig(label, certPEM string) string {
	return testAccCertificateResourceConfig(label, certPEM) + fmt.Sprintf(`
data "keychain_certificate" "test" {
  label = %q

  depends_on = [keychain_certificate.test]
}
`, label)
}
