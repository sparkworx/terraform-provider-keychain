package keychain

import (
	"errors"
	"fmt"
)

// Common keychain errors mapped from Security.framework OSStatus codes.
var (
	ErrItemAlreadyExists      = errors.New("keychain item already exists")
	ErrItemNotFound           = errors.New("keychain item not found")
	ErrAuthenticationFailed   = errors.New("keychain authentication failed")
	ErrInteractionNotAllowed  = errors.New("keychain interaction not allowed")
	ErrKeychainNotFound       = errors.New("keychain not found")
	ErrInvalidParameter       = errors.New("invalid parameter")
	ErrMemoryAllocation       = errors.New("memory allocation failed")
	ErrKeychainLocked         = errors.New("keychain is locked")
	ErrDuplicateKeychain      = errors.New("duplicate keychain")
	ErrInvalidKeychain        = errors.New("invalid keychain")
	ErrDataTooLarge           = errors.New("data too large")
	ErrNoSuchAttribute        = errors.New("no such attribute")
	ErrDecodeError            = errors.New("unable to decode data")
	ErrUnknown                = errors.New("unknown keychain error")
)

// OSStatus codes from Security.framework
const (
	errSecSuccess               = 0
	errSecUnimplemented         = -4
	errSecParam                 = -50
	errSecAllocate              = -108
	errSecNotAvailable          = -25291
	errSecDuplicateItem         = -25299
	errSecItemNotFound          = -25300
	errSecInteractionNotAllowed = -25308
	errSecDecode                = -26275
	errSecAuthFailed            = -25293
	errSecNoSuchKeychain        = -25294
	errSecInvalidKeychain       = -25295
	errSecDuplicateKeychain     = -25296
	errSecKeychainLocked        = -25298
	errSecDataTooLarge          = -25301
	errSecNoSuchAttr            = -25303
)

// Error represents a keychain error with the underlying OSStatus code.
type Error struct {
	Code    int32
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("keychain error %d: %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error {
	return statusToError(e.Code)
}

// statusToError converts an OSStatus code to a Go error.
func statusToError(status int32) error {
	switch status {
	case errSecSuccess:
		return nil
	case errSecParam:
		return ErrInvalidParameter
	case errSecAllocate:
		return ErrMemoryAllocation
	case errSecDuplicateItem:
		return ErrItemAlreadyExists
	case errSecItemNotFound:
		return ErrItemNotFound
	case errSecAuthFailed:
		return ErrAuthenticationFailed
	case errSecInteractionNotAllowed:
		return ErrInteractionNotAllowed
	case errSecNoSuchKeychain:
		return ErrKeychainNotFound
	case errSecInvalidKeychain:
		return ErrInvalidKeychain
	case errSecDuplicateKeychain:
		return ErrDuplicateKeychain
	case errSecKeychainLocked:
		return ErrKeychainLocked
	case errSecDataTooLarge:
		return ErrDataTooLarge
	case errSecNoSuchAttr:
		return ErrNoSuchAttribute
	case errSecDecode:
		return ErrDecodeError
	default:
		return ErrUnknown
	}
}

// newError creates a new Error from an OSStatus code.
func newError(status int32) error {
	if status == errSecSuccess {
		return nil
	}
	baseErr := statusToError(status)
	return &Error{
		Code:    status,
		Message: baseErr.Error(),
	}
}

// IsItemNotFound returns true if the error indicates the item was not found.
func IsItemNotFound(err error) bool {
	return errors.Is(err, ErrItemNotFound)
}

// IsItemAlreadyExists returns true if the error indicates a duplicate item.
func IsItemAlreadyExists(err error) bool {
	return errors.Is(err, ErrItemAlreadyExists)
}

// IsAuthenticationFailed returns true if the error indicates auth failure.
func IsAuthenticationFailed(err error) bool {
	return errors.Is(err, ErrAuthenticationFailed)
}

// IsKeychainLocked returns true if the error indicates a locked keychain.
func IsKeychainLocked(err error) bool {
	return errors.Is(err, ErrKeychainLocked)
}
