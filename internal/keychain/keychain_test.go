//go:build darwin

package keychain

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
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
