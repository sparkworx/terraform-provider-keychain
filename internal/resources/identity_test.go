//go:build darwin

package resources_test

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

// generateTestP12 creates a self-signed certificate with private key as PKCS#12
func generateTestP12(cn string, password string) ([]byte, error) {
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

func TestAccIdentity_basic(t *testing.T) {
	provider.SkipIfNoTestKeychain(t)

	label := "test-acc-identity-basic"
	password := "test123"

	p12Data, err := generateTestP12(label+".example.com", password)
	if err != nil {
		t.Fatalf("Failed to generate test P12: %v", err)
	}
	p12DataB64 := base64.StdEncoding.EncodeToString(p12Data)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: provider.ProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityConfig(label, p12DataB64, password),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("keychain_identity.test", "label", label),
					resource.TestCheckResourceAttr("keychain_identity.test", "id", label),
					resource.TestCheckResourceAttrSet("keychain_identity.test", "subject"),
					resource.TestCheckResourceAttrSet("keychain_identity.test", "issuer"),
					resource.TestCheckResourceAttrSet("keychain_identity.test", "serial_number"),
					resource.TestCheckResourceAttrSet("keychain_identity.test", "not_before"),
					resource.TestCheckResourceAttrSet("keychain_identity.test", "not_after"),
					resource.TestCheckResourceAttrSet("keychain_identity.test", "fingerprint_sha1"),
					resource.TestCheckResourceAttrSet("keychain_identity.test", "fingerprint_sha256"),
					resource.TestCheckResourceAttr("keychain_identity.test", "key_type", "ec"),
					resource.TestCheckResourceAttr("keychain_identity.test", "key_size_bits", "256"),
				),
			},
		},
	})
}

func TestAccIdentity_update(t *testing.T) {
	provider.SkipIfNoTestKeychain(t)

	label := "test-acc-identity-update"
	password := "test123"

	// Generate two different P12s
	p12Data1, err := generateTestP12(label+"-v1.example.com", password)
	if err != nil {
		t.Fatalf("Failed to generate test P12: %v", err)
	}
	p12DataB64_1 := base64.StdEncoding.EncodeToString(p12Data1)

	p12Data2, err := generateTestP12(label+"-v2.example.com", password)
	if err != nil {
		t.Fatalf("Failed to generate test P12: %v", err)
	}
	p12DataB64_2 := base64.StdEncoding.EncodeToString(p12Data2)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: provider.ProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityConfig(label, p12DataB64_1, password),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("keychain_identity.test", "label", label),
				),
			},
			{
				Config: testAccIdentityConfig(label, p12DataB64_2, password),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("keychain_identity.test", "label", label),
				),
			},
		},
	})
}

func TestAccIdentity_import(t *testing.T) {
	provider.SkipIfNoTestKeychain(t)

	label := "test-acc-identity-import"
	password := "test123"

	p12Data, err := generateTestP12(label+".example.com", password)
	if err != nil {
		t.Fatalf("Failed to generate test P12: %v", err)
	}
	p12DataB64 := base64.StdEncoding.EncodeToString(p12Data)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: provider.ProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityConfig(label, p12DataB64, password),
			},
			{
				ResourceName:      "keychain_identity.test",
				ImportState:       true,
				ImportStateId:     label,
				ImportStateVerify: true,
				// pkcs12_data and password are not stored in keychain, only the imported cert/key
				ImportStateVerifyIgnore: []string{"pkcs12_data", "password"},
			},
		},
	})
}

func testAccIdentityConfig(label, pkcs12Data, password string) string {
	return provider.TestProviderConfig() + fmt.Sprintf(`
resource "keychain_identity" "test" {
  label       = %q
  pkcs12_data = %q
  password    = %q
}
`, label, pkcs12Data, password)
}
