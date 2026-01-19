//go:build darwin

package keychain

import (
	"errors"
	"testing"
)

func TestStatusToError(t *testing.T) {
	tests := []struct {
		name     string
		status   int32
		wantErr  error
		wantNil  bool
	}{
		{
			name:    "errSecSuccess returns nil",
			status:  errSecSuccess,
			wantNil: true,
		},
		{
			name:    "errSecParam returns ErrInvalidParameter",
			status:  errSecParam,
			wantErr: ErrInvalidParameter,
		},
		{
			name:    "errSecAllocate returns ErrMemoryAllocation",
			status:  errSecAllocate,
			wantErr: ErrMemoryAllocation,
		},
		{
			name:    "errSecDuplicateItem returns ErrItemAlreadyExists",
			status:  errSecDuplicateItem,
			wantErr: ErrItemAlreadyExists,
		},
		{
			name:    "errSecItemNotFound returns ErrItemNotFound",
			status:  errSecItemNotFound,
			wantErr: ErrItemNotFound,
		},
		{
			name:    "errSecAuthFailed returns ErrAuthenticationFailed",
			status:  errSecAuthFailed,
			wantErr: ErrAuthenticationFailed,
		},
		{
			name:    "errSecInteractionNotAllowed returns ErrInteractionNotAllowed",
			status:  errSecInteractionNotAllowed,
			wantErr: ErrInteractionNotAllowed,
		},
		{
			name:    "errSecNoSuchKeychain returns ErrKeychainNotFound",
			status:  errSecNoSuchKeychain,
			wantErr: ErrKeychainNotFound,
		},
		{
			name:    "errSecInvalidKeychain returns ErrInvalidKeychain",
			status:  errSecInvalidKeychain,
			wantErr: ErrInvalidKeychain,
		},
		{
			name:    "errSecDuplicateKeychain returns ErrDuplicateKeychain",
			status:  errSecDuplicateKeychain,
			wantErr: ErrDuplicateKeychain,
		},
		{
			name:    "errSecKeychainLocked returns ErrKeychainLocked",
			status:  errSecKeychainLocked,
			wantErr: ErrKeychainLocked,
		},
		{
			name:    "errSecDataTooLarge returns ErrDataTooLarge",
			status:  errSecDataTooLarge,
			wantErr: ErrDataTooLarge,
		},
		{
			name:    "errSecNoSuchAttr returns ErrNoSuchAttribute",
			status:  errSecNoSuchAttr,
			wantErr: ErrNoSuchAttribute,
		},
		{
			name:    "errSecDecode returns ErrDecodeError",
			status:  errSecDecode,
			wantErr: ErrDecodeError,
		},
		{
			name:    "unknown status returns ErrUnknown",
			status:  -99999,
			wantErr: ErrUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := statusToError(tt.status)
			if tt.wantNil {
				if got != nil {
					t.Errorf("statusToError(%d) = %v, want nil", tt.status, got)
				}
				return
			}
			if got != tt.wantErr {
				t.Errorf("statusToError(%d) = %v, want %v", tt.status, got, tt.wantErr)
			}
		})
	}
}

func TestNewError(t *testing.T) {
	t.Run("errSecSuccess returns nil", func(t *testing.T) {
		err := newError(errSecSuccess)
		if err != nil {
			t.Errorf("newError(errSecSuccess) = %v, want nil", err)
		}
	})

	t.Run("error contains code and message", func(t *testing.T) {
		err := newError(errSecItemNotFound)
		if err == nil {
			t.Fatal("newError(errSecItemNotFound) = nil, want error")
		}

		kerr, ok := err.(*Error)
		if !ok {
			t.Fatalf("newError returned %T, want *Error", err)
		}

		if kerr.Code != errSecItemNotFound {
			t.Errorf("Error.Code = %d, want %d", kerr.Code, errSecItemNotFound)
		}

		if kerr.Message == "" {
			t.Error("Error.Message is empty")
		}
	})

	t.Run("error unwraps to base error", func(t *testing.T) {
		err := newError(errSecItemNotFound)
		if !errors.Is(err, ErrItemNotFound) {
			t.Errorf("errors.Is(err, ErrItemNotFound) = false, want true")
		}
	})
}

func TestErrorString(t *testing.T) {
	err := &Error{
		Code:    errSecItemNotFound,
		Message: "keychain item not found",
	}
	expected := "keychain error -25300: keychain item not found"
	if got := err.Error(); got != expected {
		t.Errorf("Error.Error() = %q, want %q", got, expected)
	}
}

func TestIsItemNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"ErrItemNotFound", ErrItemNotFound, true},
		{"wrapped ErrItemNotFound", newError(errSecItemNotFound), true},
		{"other error", ErrAuthenticationFailed, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsItemNotFound(tt.err); got != tt.want {
				t.Errorf("IsItemNotFound(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestIsItemAlreadyExists(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"ErrItemAlreadyExists", ErrItemAlreadyExists, true},
		{"wrapped ErrItemAlreadyExists", newError(errSecDuplicateItem), true},
		{"other error", ErrAuthenticationFailed, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsItemAlreadyExists(tt.err); got != tt.want {
				t.Errorf("IsItemAlreadyExists(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestIsAuthenticationFailed(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"ErrAuthenticationFailed", ErrAuthenticationFailed, true},
		{"wrapped ErrAuthenticationFailed", newError(errSecAuthFailed), true},
		{"other error", ErrItemNotFound, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsAuthenticationFailed(tt.err); got != tt.want {
				t.Errorf("IsAuthenticationFailed(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestIsKeychainLocked(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"ErrKeychainLocked", ErrKeychainLocked, true},
		{"wrapped ErrKeychainLocked", newError(errSecKeychainLocked), true},
		{"other error", ErrItemNotFound, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsKeychainLocked(tt.err); got != tt.want {
				t.Errorf("IsKeychainLocked(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
