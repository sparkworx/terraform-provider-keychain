//go:build darwin

package keychain

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
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

func openTestKeychain(t *testing.T) *Keychain {
	t.Helper()
	path := skipIfNoTestKeychain(t)

	kc, err := Open(path)
	if err != nil {
		t.Fatalf("Failed to open test keychain: %v", err)
	}

	err = kc.Unlock(testKeychainPassword)
	if err != nil {
		kc.Close()
		t.Fatalf("Failed to unlock test keychain: %v", err)
	}

	t.Cleanup(func() {
		kc.Close()
	})

	return kc
}

func TestOpen(t *testing.T) {
	path := skipIfNoTestKeychain(t)

	t.Run("open existing keychain", func(t *testing.T) {
		kc, err := Open(path)
		if err != nil {
			t.Fatalf("Open(%q) failed: %v", path, err)
		}
		defer kc.Close()

		if kc.Path() != path {
			t.Errorf("kc.Path() = %q, want %q", kc.Path(), path)
		}
	})

	t.Run("open non-existent keychain and try to use it", func(t *testing.T) {
		// SecKeychainOpen doesn't fail for non-existent paths until you try to use the keychain.
		// This is expected macOS behavior - the keychain reference is created lazily.
		kc, err := Open("/nonexistent/path/keychain.keychain-db")
		if err != nil {
			// If it does fail immediately, that's also acceptable
			return
		}
		defer kc.Close()

		// Trying to get a password from a non-existent keychain should fail
		_, err = kc.GetGenericPassword("test", "test")
		if err == nil {
			t.Error("GetGenericPassword from non-existent keychain should return error")
		}
	})

	t.Run("open default keychain with empty path", func(t *testing.T) {
		kc, err := Open("")
		if err != nil {
			t.Fatalf("Open(\"\") failed: %v", err)
		}
		defer kc.Close()

		if kc.Path() != "" {
			t.Errorf("kc.Path() = %q, want empty string", kc.Path())
		}
	})
}

func TestUnlockLock(t *testing.T) {
	path := skipIfNoTestKeychain(t)

	kc, err := Open(path)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer kc.Close()

	t.Run("unlock with correct password", func(t *testing.T) {
		err := kc.Unlock(testKeychainPassword)
		if err != nil {
			t.Errorf("Unlock() with correct password failed: %v", err)
		}
	})

	t.Run("lock keychain", func(t *testing.T) {
		err := kc.Lock()
		if err != nil {
			t.Errorf("Lock() failed: %v", err)
		}
	})

	t.Run("unlock again after lock", func(t *testing.T) {
		err := kc.Unlock(testKeychainPassword)
		if err != nil {
			t.Errorf("Unlock() after Lock() failed: %v", err)
		}
	})
}

func TestGenericPassword_CRUD(t *testing.T) {
	kc := openTestKeychain(t)

	service := "test-service-crud"
	account := "test-account-crud"
	password := []byte("test-password-123")
	label := "Test Label"
	description := "Test Description"

	// Clean up any leftover items from previous test runs
	_ = kc.DeleteGenericPassword(service, account)

	t.Run("create", func(t *testing.T) {
		item := &GenericPasswordItem{
			Service:     service,
			Account:     account,
			Password:    password,
			Label:       label,
			Description: description,
		}

		err := kc.AddGenericPassword(item)
		if err != nil {
			t.Fatalf("AddGenericPassword() failed: %v", err)
		}
	})

	t.Run("read", func(t *testing.T) {
		item, err := kc.GetGenericPassword(service, account)
		if err != nil {
			t.Fatalf("GetGenericPassword() failed: %v", err)
		}

		if item.Service != service {
			t.Errorf("item.Service = %q, want %q", item.Service, service)
		}
		if item.Account != account {
			t.Errorf("item.Account = %q, want %q", item.Account, account)
		}
		if !bytes.Equal(item.Password, password) {
			t.Errorf("item.Password = %q, want %q", item.Password, password)
		}
		if item.Label != label {
			t.Errorf("item.Label = %q, want %q", item.Label, label)
		}
		if item.Description != description {
			t.Errorf("item.Description = %q, want %q", item.Description, description)
		}
	})

	t.Run("update", func(t *testing.T) {
		newPassword := []byte("updated-password-456")
		newLabel := "Updated Label"
		newDescription := "Updated Description"

		item := &GenericPasswordItem{
			Service:     service,
			Account:     account,
			Password:    newPassword,
			Label:       newLabel,
			Description: newDescription,
		}

		err := kc.UpdateGenericPassword(item)
		if err != nil {
			t.Fatalf("UpdateGenericPassword() failed: %v", err)
		}

		// Verify update
		updated, err := kc.GetGenericPassword(service, account)
		if err != nil {
			t.Fatalf("GetGenericPassword() after update failed: %v", err)
		}

		if !bytes.Equal(updated.Password, newPassword) {
			t.Errorf("updated.Password = %q, want %q", updated.Password, newPassword)
		}
		if updated.Label != newLabel {
			t.Errorf("updated.Label = %q, want %q", updated.Label, newLabel)
		}
		if updated.Description != newDescription {
			t.Errorf("updated.Description = %q, want %q", updated.Description, newDescription)
		}
	})

	t.Run("delete", func(t *testing.T) {
		err := kc.DeleteGenericPassword(service, account)
		if err != nil {
			t.Fatalf("DeleteGenericPassword() failed: %v", err)
		}

		// Verify deletion
		_, err = kc.GetGenericPassword(service, account)
		if !IsItemNotFound(err) {
			t.Errorf("GetGenericPassword() after delete: got err = %v, want ErrItemNotFound", err)
		}
	})
}

func TestGenericPassword_NotFound(t *testing.T) {
	kc := openTestKeychain(t)

	_, err := kc.GetGenericPassword("nonexistent-service", "nonexistent-account")
	if !IsItemNotFound(err) {
		t.Errorf("GetGenericPassword() for non-existent item: got err = %v, want ErrItemNotFound", err)
	}
}

func TestGenericPassword_Duplicate(t *testing.T) {
	kc := openTestKeychain(t)

	service := "test-service-duplicate"
	account := "test-account-duplicate"
	password := []byte("test-password")

	// Clean up any leftover items
	_ = kc.DeleteGenericPassword(service, account)

	item := &GenericPasswordItem{
		Service:  service,
		Account:  account,
		Password: password,
	}

	// Create first item
	err := kc.AddGenericPassword(item)
	if err != nil {
		t.Fatalf("First AddGenericPassword() failed: %v", err)
	}

	// Clean up at end of test
	t.Cleanup(func() {
		_ = kc.DeleteGenericPassword(service, account)
	})

	// Try to create duplicate
	err = kc.AddGenericPassword(item)
	if !IsItemAlreadyExists(err) {
		t.Errorf("AddGenericPassword() duplicate: got err = %v, want ErrItemAlreadyExists", err)
	}
}

func TestInternetPassword_CRUD(t *testing.T) {
	kc := openTestKeychain(t)

	server := "test.example.com"
	account := "test-user"
	protocol := ProtocolHTTPS
	port := 443
	password := []byte("internet-password-123")
	path := "/api/v1"
	label := "Test Internet Password"

	// Clean up any leftover items
	_ = kc.DeleteInternetPassword(server, account, protocol, port)

	t.Run("create", func(t *testing.T) {
		item := &InternetPasswordItem{
			Server:   server,
			Account:  account,
			Protocol: protocol,
			Port:     port,
			Password: password,
			Path:     path,
			Label:    label,
		}

		err := kc.AddInternetPassword(item)
		if err != nil {
			t.Fatalf("AddInternetPassword() failed: %v", err)
		}
	})

	t.Run("read", func(t *testing.T) {
		item, err := kc.GetInternetPassword(server, account, protocol, port)
		if err != nil {
			t.Fatalf("GetInternetPassword() failed: %v", err)
		}

		if item.Server != server {
			t.Errorf("item.Server = %q, want %q", item.Server, server)
		}
		if item.Account != account {
			t.Errorf("item.Account = %q, want %q", item.Account, account)
		}
		if item.Protocol != protocol {
			t.Errorf("item.Protocol = %q, want %q", item.Protocol, protocol)
		}
		if item.Port != port {
			t.Errorf("item.Port = %d, want %d", item.Port, port)
		}
		if !bytes.Equal(item.Password, password) {
			t.Errorf("item.Password = %q, want %q", item.Password, password)
		}
	})

	t.Run("update", func(t *testing.T) {
		newPassword := []byte("updated-internet-password-456")
		newPath := "/api/v2"
		newLabel := "Updated Internet Password"

		item := &InternetPasswordItem{
			Server:   server,
			Account:  account,
			Protocol: protocol,
			Port:     port,
			Password: newPassword,
			Path:     newPath,
			Label:    newLabel,
		}

		err := kc.UpdateInternetPassword(item)
		if err != nil {
			t.Fatalf("UpdateInternetPassword() failed: %v", err)
		}

		// Verify update
		updated, err := kc.GetInternetPassword(server, account, protocol, port)
		if err != nil {
			t.Fatalf("GetInternetPassword() after update failed: %v", err)
		}

		if !bytes.Equal(updated.Password, newPassword) {
			t.Errorf("updated.Password = %q, want %q", updated.Password, newPassword)
		}
	})

	t.Run("delete", func(t *testing.T) {
		err := kc.DeleteInternetPassword(server, account, protocol, port)
		if err != nil {
			t.Fatalf("DeleteInternetPassword() failed: %v", err)
		}

		// Verify deletion
		_, err = kc.GetInternetPassword(server, account, protocol, port)
		if !IsItemNotFound(err) {
			t.Errorf("GetInternetPassword() after delete: got err = %v, want ErrItemNotFound", err)
		}
	})
}

// generateTestCert creates a self-signed certificate for testing
func generateTestCert(cn string) ([]byte, error) {
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
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	return derBytes, nil
}

func TestCertificate_CRUD(t *testing.T) {
	kc := openTestKeychain(t)

	label := "test-certificate-crud"

	certDER, err := generateTestCert("test-crud.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Clean up any leftover items from previous test runs
	_ = kc.DeleteCertificate(label)

	t.Run("create", func(t *testing.T) {
		item := &CertificateItem{
			Label:           label,
			CertificateData: certDER,
		}

		err := kc.AddCertificate(item)
		if err != nil {
			t.Fatalf("AddCertificate() failed: %v", err)
		}
	})

	t.Run("read", func(t *testing.T) {
		item, err := kc.GetCertificate(label)
		if err != nil {
			t.Fatalf("GetCertificate() failed: %v", err)
		}

		if item.Label != label {
			t.Errorf("item.Label = %q, want %q", item.Label, label)
		}
		if !bytes.Equal(item.CertificateData, certDER) {
			t.Errorf("item.CertificateData length = %d, want %d", len(item.CertificateData), len(certDER))
		}
		if item.Subject == "" {
			t.Error("item.Subject is empty, expected non-empty")
		}
	})

	t.Run("delete", func(t *testing.T) {
		err := kc.DeleteCertificate(label)
		if err != nil {
			t.Fatalf("DeleteCertificate() failed: %v", err)
		}

		// Verify deletion
		_, err = kc.GetCertificate(label)
		if !IsItemNotFound(err) {
			t.Errorf("GetCertificate() after delete: got err = %v, want ErrItemNotFound", err)
		}
	})
}

func TestKey_CRUD(t *testing.T) {
	kc := openTestKeychain(t)

	label := "test-key-crud"
	// Simple symmetric key data (32 bytes for AES-256)
	keyData := []byte("01234567890123456789012345678901")

	// Clean up any leftover items from previous test runs
	_ = kc.DeleteKey(label)

	t.Run("create", func(t *testing.T) {
		item := &KeyItem{
			Label:         label,
			KeyData:       keyData,
			KeyClass:      KeyClassSymmetric,
			KeyType:       KeyTypeAES,
			KeySizeInBits: 256,
			Extractable:   true,
			Permanent:     true,
		}

		err := kc.AddKey(item)
		if err != nil {
			t.Fatalf("AddKey() failed: %v", err)
		}
	})

	t.Run("read", func(t *testing.T) {
		item, err := kc.GetKey(label)
		if err != nil {
			t.Fatalf("GetKey() failed: %v", err)
		}

		if item.Label != label {
			t.Errorf("item.Label = %q, want %q", item.Label, label)
		}
		if !bytes.Equal(item.KeyData, keyData) {
			t.Errorf("item.KeyData length = %d, want %d", len(item.KeyData), len(keyData))
		}
		if item.KeyClass != KeyClassSymmetric {
			t.Errorf("item.KeyClass = %q, want %q", item.KeyClass, KeyClassSymmetric)
		}
		if item.KeyType != KeyTypeAES {
			t.Errorf("item.KeyType = %q, want %q", item.KeyType, KeyTypeAES)
		}
		if item.KeySizeInBits != 256 {
			t.Errorf("item.KeySizeInBits = %d, want 256", item.KeySizeInBits)
		}
		if !item.Extractable {
			t.Error("item.Extractable = false, want true")
		}
	})

	t.Run("delete", func(t *testing.T) {
		err := kc.DeleteKey(label)
		if err != nil {
			t.Fatalf("DeleteKey() failed: %v", err)
		}

		// Verify deletion
		_, err = kc.GetKey(label)
		if !IsItemNotFound(err) {
			t.Errorf("GetKey() after delete: got err = %v, want ErrItemNotFound", err)
		}
	})
}

func TestIdentity_CRUD(t *testing.T) {
	kc := openTestKeychain(t)

	label := "test-identity-crud"

	// Generate a test identity (certificate + private key as PKCS#12)
	p12Data, err := generateTestP12(label + ".example.com")
	if err != nil {
		t.Fatalf("Failed to generate test P12: %v", err)
	}
	p12Password := "test123"

	// Clean up any leftover items from previous test runs
	_ = kc.DeleteIdentity(label)

	t.Run("create", func(t *testing.T) {
		item := &IdentityItem{
			Label:      label,
			PKCS12Data: p12Data,
		}

		err := kc.AddIdentity(item, p12Password)
		if err != nil {
			t.Fatalf("AddIdentity() failed: %v", err)
		}
	})

	t.Run("read", func(t *testing.T) {
		item, err := kc.GetIdentity(label)
		if err != nil {
			t.Fatalf("GetIdentity() failed: %v", err)
		}

		if item.Label != label {
			t.Errorf("item.Label = %q, want %q", item.Label, label)
		}
		if len(item.CertificateData) == 0 {
			t.Error("item.CertificateData is empty")
		}
		if item.Subject == "" {
			t.Error("item.Subject is empty")
		}
		// Key type should be EC since we use ECDSA
		if item.KeyType != KeyTypeEC {
			t.Errorf("item.KeyType = %q, want %q", item.KeyType, KeyTypeEC)
		}
		if item.KeySizeInBits != 256 {
			t.Errorf("item.KeySizeInBits = %d, want 256", item.KeySizeInBits)
		}
	})

	t.Run("delete", func(t *testing.T) {
		err := kc.DeleteIdentity(label)
		if err != nil {
			t.Fatalf("DeleteIdentity() failed: %v", err)
		}

		// Verify deletion
		_, err = kc.GetIdentity(label)
		if !IsItemNotFound(err) {
			t.Errorf("GetIdentity() after delete: got err = %v, want ErrItemNotFound", err)
		}
	})
}

// generateTestP12 creates a self-signed certificate with private key as PKCS#12
func generateTestP12(cn string) ([]byte, error) {
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
	pfxData, err := pkcs12.Legacy.Encode(priv, cert, nil, "test123")
	if err != nil {
		return nil, err
	}

	return pfxData, nil
}
