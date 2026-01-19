//go:build darwin

package resources_test

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
func generateTestCertPEM(cn string) (string, error) {
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

func TestAccCertificate_basic(t *testing.T) {
	provider.SkipIfNoTestKeychain(t)

	label := "test-acc-cert-basic"
	certPEM, err := generateTestCertPEM("test-basic.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: provider.ProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: testAccCertificateConfig(label, certPEM),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("keychain_certificate.test", "label", label),
					resource.TestCheckResourceAttr("keychain_certificate.test", "id", label),
					resource.TestCheckResourceAttrSet("keychain_certificate.test", "subject"),
					resource.TestCheckResourceAttrSet("keychain_certificate.test", "issuer"),
					resource.TestCheckResourceAttrSet("keychain_certificate.test", "serial_number"),
					resource.TestCheckResourceAttrSet("keychain_certificate.test", "not_before"),
					resource.TestCheckResourceAttrSet("keychain_certificate.test", "not_after"),
					resource.TestCheckResourceAttrSet("keychain_certificate.test", "fingerprint_sha1"),
					resource.TestCheckResourceAttrSet("keychain_certificate.test", "fingerprint_sha256"),
				),
			},
		},
	})
}

func TestAccCertificate_update(t *testing.T) {
	provider.SkipIfNoTestKeychain(t)

	label := "test-acc-cert-update"
	certPEM1, err := generateTestCertPEM("test-update-1.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test certificate 1: %v", err)
	}
	certPEM2, err := generateTestCertPEM("test-update-2.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test certificate 2: %v", err)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: provider.ProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: testAccCertificateConfig(label, certPEM1),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("keychain_certificate.test", "label", label),
				),
			},
			{
				Config: testAccCertificateConfig(label, certPEM2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("keychain_certificate.test", "label", label),
					// Subject should be different after update
					resource.TestCheckResourceAttrSet("keychain_certificate.test", "subject"),
				),
			},
		},
	})
}

func TestAccCertificate_import(t *testing.T) {
	provider.SkipIfNoTestKeychain(t)

	label := "test-acc-cert-import"
	certPEM, err := generateTestCertPEM("test-import.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: provider.ProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: testAccCertificateConfig(label, certPEM),
			},
			{
				ResourceName:      "keychain_certificate.test",
				ImportState:       true,
				ImportStateId:     label,
				ImportStateVerify: true,
				// Certificate data format may differ after import (PEM vs base64 DER)
				ImportStateVerifyIgnore: []string{"certificate"},
			},
		},
	})
}

func testAccCertificateConfig(label, certPEM string) string {
	return provider.TestProviderConfig() + fmt.Sprintf(`
resource "keychain_certificate" "test" {
  label       = %q
  certificate = %q
}
`, label, certPEM)
}
