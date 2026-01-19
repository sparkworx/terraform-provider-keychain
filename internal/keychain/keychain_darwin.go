//go:build darwin

package keychain

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Security -framework CoreFoundation

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>

// Helper to create CFString from C string
static CFStringRef createCFString(const char *str) {
    if (str == NULL || str[0] == '\0') {
        return NULL;
    }
    return CFStringCreateWithCString(kCFAllocatorDefault, str, kCFStringEncodingUTF8);
}

// Helper to create CFData from bytes
static CFDataRef createCFData(const void *bytes, size_t length) {
    if (bytes == NULL || length == 0) {
        return NULL;
    }
    return CFDataCreate(kCFAllocatorDefault, (const UInt8 *)bytes, (CFIndex)length);
}

// Helper to convert CFString to C string (caller must free)
static char* cfStringToCString(CFStringRef str) {
    if (str == NULL) {
        return NULL;
    }
    CFIndex length = CFStringGetLength(str);
    CFIndex maxSize = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;
    char *buffer = (char *)malloc(maxSize);
    if (buffer == NULL) {
        return NULL;
    }
    if (!CFStringGetCString(str, buffer, maxSize, kCFStringEncodingUTF8)) {
        free(buffer);
        return NULL;
    }
    return buffer;
}

// Helper to get bytes from CFData
static const void* cfDataGetBytes(CFDataRef data, size_t *length) {
    if (data == NULL) {
        *length = 0;
        return NULL;
    }
    *length = (size_t)CFDataGetLength(data);
    return CFDataGetBytePtr(data);
}

// Open a keychain by path
static OSStatus openKeychain(const char *path, SecKeychainRef *keychain) {
    if (path == NULL || path[0] == '\0') {
        return SecKeychainCopyDefault(keychain);
    }
    return SecKeychainOpen(path, keychain);
}

// Unlock a keychain
static OSStatus unlockKeychain(SecKeychainRef keychain, const char *password) {
    if (password == NULL) {
        return SecKeychainUnlock(keychain, 0, NULL, FALSE);
    }
    return SecKeychainUnlock(keychain, (UInt32)strlen(password), password, TRUE);
}

// Lock a keychain
static OSStatus lockKeychain(SecKeychainRef keychain) {
    return SecKeychainLock(keychain);
}

// Add a generic password
static OSStatus addGenericPassword(
    SecKeychainRef keychain,
    const char *service,
    const char *account,
    const void *password,
    size_t passwordLen,
    const char *label,
    const char *description
) {
    CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    CFDictionarySetValue(attrs, kSecClass, kSecClassGenericPassword);

    if (keychain != NULL) {
        CFArrayRef keychains = CFArrayCreate(kCFAllocatorDefault, (const void **)&keychain, 1, &kCFTypeArrayCallBacks);
        CFDictionarySetValue(attrs, kSecMatchSearchList, keychains);
        CFDictionarySetValue(attrs, kSecUseKeychain, keychain);
        CFRelease(keychains);
    }

    CFStringRef cfService = createCFString(service);
    if (cfService) {
        CFDictionarySetValue(attrs, kSecAttrService, cfService);
    }

    CFStringRef cfAccount = createCFString(account);
    if (cfAccount) {
        CFDictionarySetValue(attrs, kSecAttrAccount, cfAccount);
    }

    CFDataRef cfPassword = createCFData(password, passwordLen);
    if (cfPassword) {
        CFDictionarySetValue(attrs, kSecValueData, cfPassword);
    }

    CFStringRef cfLabel = createCFString(label);
    if (cfLabel) {
        CFDictionarySetValue(attrs, kSecAttrLabel, cfLabel);
    }

    CFStringRef cfDesc = createCFString(description);
    if (cfDesc) {
        CFDictionarySetValue(attrs, kSecAttrDescription, cfDesc);
    }

    OSStatus status = SecItemAdd(attrs, NULL);

    if (cfService) CFRelease(cfService);
    if (cfAccount) CFRelease(cfAccount);
    if (cfPassword) CFRelease(cfPassword);
    if (cfLabel) CFRelease(cfLabel);
    if (cfDesc) CFRelease(cfDesc);
    CFRelease(attrs);

    return status;
}

// Get a generic password
static OSStatus getGenericPassword(
    SecKeychainRef keychain,
    const char *service,
    const char *account,
    void **password,
    size_t *passwordLen,
    char **outLabel,
    char **outDescription
) {
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecReturnAttributes, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);

    if (keychain != NULL) {
        CFArrayRef keychains = CFArrayCreate(kCFAllocatorDefault, (const void **)&keychain, 1, &kCFTypeArrayCallBacks);
        CFDictionarySetValue(query, kSecMatchSearchList, keychains);
        CFRelease(keychains);
    }

    CFStringRef cfService = createCFString(service);
    if (cfService) {
        CFDictionarySetValue(query, kSecAttrService, cfService);
    }

    CFStringRef cfAccount = createCFString(account);
    if (cfAccount) {
        CFDictionarySetValue(query, kSecAttrAccount, cfAccount);
    }

    CFDictionaryRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, (CFTypeRef *)&result);

    if (cfService) CFRelease(cfService);
    if (cfAccount) CFRelease(cfAccount);
    CFRelease(query);

    if (status != errSecSuccess || result == NULL) {
        return status;
    }

    // Extract password data
    CFDataRef pwData = (CFDataRef)CFDictionaryGetValue(result, kSecValueData);
    if (pwData) {
        *passwordLen = (size_t)CFDataGetLength(pwData);
        *password = malloc(*passwordLen);
        if (*password) {
            memcpy(*password, CFDataGetBytePtr(pwData), *passwordLen);
        }
    }

    // Extract label
    CFStringRef labelRef = (CFStringRef)CFDictionaryGetValue(result, kSecAttrLabel);
    if (labelRef && outLabel) {
        *outLabel = cfStringToCString(labelRef);
    }

    // Extract description
    CFStringRef descRef = (CFStringRef)CFDictionaryGetValue(result, kSecAttrDescription);
    if (descRef && outDescription) {
        *outDescription = cfStringToCString(descRef);
    }

    CFRelease(result);
    return status;
}

// Update a generic password
static OSStatus updateGenericPassword(
    SecKeychainRef keychain,
    const char *service,
    const char *account,
    const void *password,
    size_t passwordLen,
    const char *label,
    const char *description
) {
    // Build the query to find the item
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);

    if (keychain != NULL) {
        CFArrayRef keychains = CFArrayCreate(kCFAllocatorDefault, (const void **)&keychain, 1, &kCFTypeArrayCallBacks);
        CFDictionarySetValue(query, kSecMatchSearchList, keychains);
        CFRelease(keychains);
    }

    CFStringRef cfService = createCFString(service);
    if (cfService) {
        CFDictionarySetValue(query, kSecAttrService, cfService);
    }

    CFStringRef cfAccount = createCFString(account);
    if (cfAccount) {
        CFDictionarySetValue(query, kSecAttrAccount, cfAccount);
    }

    // Build the attributes to update
    CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    CFDataRef cfPassword = createCFData(password, passwordLen);
    if (cfPassword) {
        CFDictionarySetValue(attrs, kSecValueData, cfPassword);
    }

    CFStringRef cfLabel = createCFString(label);
    if (cfLabel) {
        CFDictionarySetValue(attrs, kSecAttrLabel, cfLabel);
    }

    CFStringRef cfDesc = createCFString(description);
    if (cfDesc) {
        CFDictionarySetValue(attrs, kSecAttrDescription, cfDesc);
    }

    OSStatus status = SecItemUpdate(query, attrs);

    if (cfService) CFRelease(cfService);
    if (cfAccount) CFRelease(cfAccount);
    if (cfPassword) CFRelease(cfPassword);
    if (cfLabel) CFRelease(cfLabel);
    if (cfDesc) CFRelease(cfDesc);
    CFRelease(query);
    CFRelease(attrs);

    return status;
}

// Delete a generic password
static OSStatus deleteGenericPassword(
    SecKeychainRef keychain,
    const char *service,
    const char *account
) {
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);

    if (keychain != NULL) {
        CFArrayRef keychains = CFArrayCreate(kCFAllocatorDefault, (const void **)&keychain, 1, &kCFTypeArrayCallBacks);
        CFDictionarySetValue(query, kSecMatchSearchList, keychains);
        CFRelease(keychains);
    }

    CFStringRef cfService = createCFString(service);
    if (cfService) {
        CFDictionarySetValue(query, kSecAttrService, cfService);
    }

    CFStringRef cfAccount = createCFString(account);
    if (cfAccount) {
        CFDictionarySetValue(query, kSecAttrAccount, cfAccount);
    }

    OSStatus status = SecItemDelete(query);

    if (cfService) CFRelease(cfService);
    if (cfAccount) CFRelease(cfAccount);
    CFRelease(query);

    return status;
}

// Add an internet password
static OSStatus addInternetPassword(
    SecKeychainRef keychain,
    const char *server,
    const char *account,
    const void *password,
    size_t passwordLen,
    const char *protocol,
    int port,
    const char *path,
    const char *authType,
    const char *securityDomain,
    const char *label
) {
    CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    CFDictionarySetValue(attrs, kSecClass, kSecClassInternetPassword);

    if (keychain != NULL) {
        CFArrayRef keychains = CFArrayCreate(kCFAllocatorDefault, (const void **)&keychain, 1, &kCFTypeArrayCallBacks);
        CFDictionarySetValue(attrs, kSecMatchSearchList, keychains);
        CFDictionarySetValue(attrs, kSecUseKeychain, keychain);
        CFRelease(keychains);
    }

    CFStringRef cfServer = createCFString(server);
    if (cfServer) {
        CFDictionarySetValue(attrs, kSecAttrServer, cfServer);
    }

    CFStringRef cfAccount = createCFString(account);
    if (cfAccount) {
        CFDictionarySetValue(attrs, kSecAttrAccount, cfAccount);
    }

    CFDataRef cfPassword = createCFData(password, passwordLen);
    if (cfPassword) {
        CFDictionarySetValue(attrs, kSecValueData, cfPassword);
    }

    CFStringRef cfProtocol = createCFString(protocol);
    if (cfProtocol) {
        CFDictionarySetValue(attrs, kSecAttrProtocol, cfProtocol);
    }

    if (port > 0) {
        CFNumberRef cfPort = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &port);
        if (cfPort) {
            CFDictionarySetValue(attrs, kSecAttrPort, cfPort);
            CFRelease(cfPort);
        }
    }

    CFStringRef cfPath = createCFString(path);
    if (cfPath) {
        CFDictionarySetValue(attrs, kSecAttrPath, cfPath);
    }

    CFStringRef cfAuthType = createCFString(authType);
    if (cfAuthType) {
        CFDictionarySetValue(attrs, kSecAttrAuthenticationType, cfAuthType);
    }

    CFStringRef cfSecDomain = createCFString(securityDomain);
    if (cfSecDomain) {
        CFDictionarySetValue(attrs, kSecAttrSecurityDomain, cfSecDomain);
    }

    CFStringRef cfLabel = createCFString(label);
    if (cfLabel) {
        CFDictionarySetValue(attrs, kSecAttrLabel, cfLabel);
    }

    OSStatus status = SecItemAdd(attrs, NULL);

    if (cfServer) CFRelease(cfServer);
    if (cfAccount) CFRelease(cfAccount);
    if (cfPassword) CFRelease(cfPassword);
    if (cfProtocol) CFRelease(cfProtocol);
    if (cfPath) CFRelease(cfPath);
    if (cfAuthType) CFRelease(cfAuthType);
    if (cfSecDomain) CFRelease(cfSecDomain);
    if (cfLabel) CFRelease(cfLabel);
    CFRelease(attrs);

    return status;
}

// Get an internet password
static OSStatus getInternetPassword(
    SecKeychainRef keychain,
    const char *server,
    const char *account,
    const char *protocol,
    int port,
    void **password,
    size_t *passwordLen,
    char **outPath,
    char **outAuthType,
    char **outSecurityDomain,
    char **outLabel
) {
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    CFDictionarySetValue(query, kSecClass, kSecClassInternetPassword);
    CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecReturnAttributes, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);

    if (keychain != NULL) {
        CFArrayRef keychains = CFArrayCreate(kCFAllocatorDefault, (const void **)&keychain, 1, &kCFTypeArrayCallBacks);
        CFDictionarySetValue(query, kSecMatchSearchList, keychains);
        CFRelease(keychains);
    }

    CFStringRef cfServer = createCFString(server);
    if (cfServer) {
        CFDictionarySetValue(query, kSecAttrServer, cfServer);
    }

    CFStringRef cfAccount = createCFString(account);
    if (cfAccount) {
        CFDictionarySetValue(query, kSecAttrAccount, cfAccount);
    }

    CFStringRef cfProtocol = createCFString(protocol);
    if (cfProtocol) {
        CFDictionarySetValue(query, kSecAttrProtocol, cfProtocol);
    }

    if (port > 0) {
        CFNumberRef cfPort = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &port);
        if (cfPort) {
            CFDictionarySetValue(query, kSecAttrPort, cfPort);
            CFRelease(cfPort);
        }
    }

    CFDictionaryRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, (CFTypeRef *)&result);

    if (cfServer) CFRelease(cfServer);
    if (cfAccount) CFRelease(cfAccount);
    if (cfProtocol) CFRelease(cfProtocol);
    CFRelease(query);

    if (status != errSecSuccess || result == NULL) {
        return status;
    }

    // Extract password data
    CFDataRef pwData = (CFDataRef)CFDictionaryGetValue(result, kSecValueData);
    if (pwData) {
        *passwordLen = (size_t)CFDataGetLength(pwData);
        *password = malloc(*passwordLen);
        if (*password) {
            memcpy(*password, CFDataGetBytePtr(pwData), *passwordLen);
        }
    }

    // Extract path
    CFStringRef pathRef = (CFStringRef)CFDictionaryGetValue(result, kSecAttrPath);
    if (pathRef && outPath) {
        *outPath = cfStringToCString(pathRef);
    }

    // Extract auth type
    CFStringRef authRef = (CFStringRef)CFDictionaryGetValue(result, kSecAttrAuthenticationType);
    if (authRef && outAuthType) {
        *outAuthType = cfStringToCString(authRef);
    }

    // Extract security domain
    CFStringRef secDomainRef = (CFStringRef)CFDictionaryGetValue(result, kSecAttrSecurityDomain);
    if (secDomainRef && outSecurityDomain) {
        *outSecurityDomain = cfStringToCString(secDomainRef);
    }

    // Extract label
    CFStringRef labelRef = (CFStringRef)CFDictionaryGetValue(result, kSecAttrLabel);
    if (labelRef && outLabel) {
        *outLabel = cfStringToCString(labelRef);
    }

    CFRelease(result);
    return status;
}

// Update an internet password
static OSStatus updateInternetPassword(
    SecKeychainRef keychain,
    const char *server,
    const char *account,
    const char *protocol,
    int port,
    const void *password,
    size_t passwordLen,
    const char *path,
    const char *authType,
    const char *securityDomain,
    const char *label
) {
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    CFDictionarySetValue(query, kSecClass, kSecClassInternetPassword);

    if (keychain != NULL) {
        CFArrayRef keychains = CFArrayCreate(kCFAllocatorDefault, (const void **)&keychain, 1, &kCFTypeArrayCallBacks);
        CFDictionarySetValue(query, kSecMatchSearchList, keychains);
        CFRelease(keychains);
    }

    CFStringRef cfServer = createCFString(server);
    if (cfServer) {
        CFDictionarySetValue(query, kSecAttrServer, cfServer);
    }

    CFStringRef cfAccount = createCFString(account);
    if (cfAccount) {
        CFDictionarySetValue(query, kSecAttrAccount, cfAccount);
    }

    CFStringRef cfProtocol = createCFString(protocol);
    if (cfProtocol) {
        CFDictionarySetValue(query, kSecAttrProtocol, cfProtocol);
    }

    if (port > 0) {
        CFNumberRef cfPort = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &port);
        if (cfPort) {
            CFDictionarySetValue(query, kSecAttrPort, cfPort);
            CFRelease(cfPort);
        }
    }

    // Build attributes to update
    CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    CFDataRef cfPassword = createCFData(password, passwordLen);
    if (cfPassword) {
        CFDictionarySetValue(attrs, kSecValueData, cfPassword);
    }

    CFStringRef cfPath = createCFString(path);
    if (cfPath) {
        CFDictionarySetValue(attrs, kSecAttrPath, cfPath);
    }

    CFStringRef cfAuthType = createCFString(authType);
    if (cfAuthType) {
        CFDictionarySetValue(attrs, kSecAttrAuthenticationType, cfAuthType);
    }

    CFStringRef cfSecDomain = createCFString(securityDomain);
    if (cfSecDomain) {
        CFDictionarySetValue(attrs, kSecAttrSecurityDomain, cfSecDomain);
    }

    CFStringRef cfLabel = createCFString(label);
    if (cfLabel) {
        CFDictionarySetValue(attrs, kSecAttrLabel, cfLabel);
    }

    OSStatus status = SecItemUpdate(query, attrs);

    if (cfServer) CFRelease(cfServer);
    if (cfAccount) CFRelease(cfAccount);
    if (cfProtocol) CFRelease(cfProtocol);
    if (cfPassword) CFRelease(cfPassword);
    if (cfPath) CFRelease(cfPath);
    if (cfAuthType) CFRelease(cfAuthType);
    if (cfSecDomain) CFRelease(cfSecDomain);
    if (cfLabel) CFRelease(cfLabel);
    CFRelease(query);
    CFRelease(attrs);

    return status;
}

// Delete an internet password
static OSStatus deleteInternetPassword(
    SecKeychainRef keychain,
    const char *server,
    const char *account,
    const char *protocol,
    int port
) {
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    CFDictionarySetValue(query, kSecClass, kSecClassInternetPassword);

    if (keychain != NULL) {
        CFArrayRef keychains = CFArrayCreate(kCFAllocatorDefault, (const void **)&keychain, 1, &kCFTypeArrayCallBacks);
        CFDictionarySetValue(query, kSecMatchSearchList, keychains);
        CFRelease(keychains);
    }

    CFStringRef cfServer = createCFString(server);
    if (cfServer) {
        CFDictionarySetValue(query, kSecAttrServer, cfServer);
    }

    CFStringRef cfAccount = createCFString(account);
    if (cfAccount) {
        CFDictionarySetValue(query, kSecAttrAccount, cfAccount);
    }

    CFStringRef cfProtocol = createCFString(protocol);
    if (cfProtocol) {
        CFDictionarySetValue(query, kSecAttrProtocol, cfProtocol);
    }

    if (port > 0) {
        CFNumberRef cfPort = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &port);
        if (cfPort) {
            CFDictionarySetValue(query, kSecAttrPort, cfPort);
            CFRelease(cfPort);
        }
    }

    OSStatus status = SecItemDelete(query);

    if (cfServer) CFRelease(cfServer);
    if (cfAccount) CFRelease(cfAccount);
    if (cfProtocol) CFRelease(cfProtocol);
    CFRelease(query);

    return status;
}

*/
import "C"
import (
	"unsafe"
)

// open opens a keychain at the specified path.
func open(path string) (*Keychain, error) {
	var cPath *C.char
	if path != "" {
		cPath = C.CString(path)
		defer C.free(unsafe.Pointer(cPath))
	}

	var handle C.SecKeychainRef
	status := C.openKeychain(cPath, &handle)
	if status != C.errSecSuccess {
		return nil, newError(int32(status))
	}

	return &Keychain{
		path:   path,
		handle: uintptr(handle),
	}, nil
}

// close releases the keychain resources.
func (k *Keychain) close() error {
	if k.handle != 0 {
		C.CFRelease(C.CFTypeRef(k.handle))
		k.handle = 0
	}
	return nil
}

// unlock unlocks the keychain with the given password.
func (k *Keychain) unlock(password string) error {
	var cPassword *C.char
	if password != "" {
		cPassword = C.CString(password)
		defer C.free(unsafe.Pointer(cPassword))
	}

	status := C.unlockKeychain(C.SecKeychainRef(k.handle), cPassword)
	if status != C.errSecSuccess {
		return newError(int32(status))
	}
	return nil
}

// lock locks the keychain.
func (k *Keychain) lock() error {
	status := C.lockKeychain(C.SecKeychainRef(k.handle))
	if status != C.errSecSuccess {
		return newError(int32(status))
	}
	return nil
}

// addGenericPassword adds a generic password item to the keychain.
func (k *Keychain) addGenericPassword(item *GenericPasswordItem) error {
	cService := C.CString(item.Service)
	defer C.free(unsafe.Pointer(cService))

	cAccount := C.CString(item.Account)
	defer C.free(unsafe.Pointer(cAccount))

	var cLabel *C.char
	if item.Label != "" {
		cLabel = C.CString(item.Label)
		defer C.free(unsafe.Pointer(cLabel))
	}

	var cDesc *C.char
	if item.Description != "" {
		cDesc = C.CString(item.Description)
		defer C.free(unsafe.Pointer(cDesc))
	}

	status := C.addGenericPassword(
		C.SecKeychainRef(k.handle),
		cService,
		cAccount,
		unsafe.Pointer(&item.Password[0]),
		C.size_t(len(item.Password)),
		cLabel,
		cDesc,
	)
	if status != C.errSecSuccess {
		return newError(int32(status))
	}
	return nil
}

// getGenericPassword retrieves a generic password item from the keychain.
func (k *Keychain) getGenericPassword(service, account string) (*GenericPasswordItem, error) {
	cService := C.CString(service)
	defer C.free(unsafe.Pointer(cService))

	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cAccount))

	var password unsafe.Pointer
	var passwordLen C.size_t
	var cLabel, cDesc *C.char

	status := C.getGenericPassword(
		C.SecKeychainRef(k.handle),
		cService,
		cAccount,
		&password,
		&passwordLen,
		&cLabel,
		&cDesc,
	)
	if status != C.errSecSuccess {
		return nil, newError(int32(status))
	}

	item := &GenericPasswordItem{
		Service: service,
		Account: account,
	}

	if password != nil && passwordLen > 0 {
		item.Password = C.GoBytes(password, C.int(passwordLen))
		C.free(password)
	}

	if cLabel != nil {
		item.Label = C.GoString(cLabel)
		C.free(unsafe.Pointer(cLabel))
	}

	if cDesc != nil {
		item.Description = C.GoString(cDesc)
		C.free(unsafe.Pointer(cDesc))
	}

	return item, nil
}

// updateGenericPassword updates an existing generic password item.
func (k *Keychain) updateGenericPassword(item *GenericPasswordItem) error {
	cService := C.CString(item.Service)
	defer C.free(unsafe.Pointer(cService))

	cAccount := C.CString(item.Account)
	defer C.free(unsafe.Pointer(cAccount))

	var cLabel *C.char
	if item.Label != "" {
		cLabel = C.CString(item.Label)
		defer C.free(unsafe.Pointer(cLabel))
	}

	var cDesc *C.char
	if item.Description != "" {
		cDesc = C.CString(item.Description)
		defer C.free(unsafe.Pointer(cDesc))
	}

	status := C.updateGenericPassword(
		C.SecKeychainRef(k.handle),
		cService,
		cAccount,
		unsafe.Pointer(&item.Password[0]),
		C.size_t(len(item.Password)),
		cLabel,
		cDesc,
	)
	if status != C.errSecSuccess {
		return newError(int32(status))
	}
	return nil
}

// deleteGenericPassword deletes a generic password item from the keychain.
func (k *Keychain) deleteGenericPassword(service, account string) error {
	cService := C.CString(service)
	defer C.free(unsafe.Pointer(cService))

	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cAccount))

	status := C.deleteGenericPassword(
		C.SecKeychainRef(k.handle),
		cService,
		cAccount,
	)
	if status != C.errSecSuccess {
		return newError(int32(status))
	}
	return nil
}

// addInternetPassword adds an internet password item to the keychain.
func (k *Keychain) addInternetPassword(item *InternetPasswordItem) error {
	cServer := C.CString(item.Server)
	defer C.free(unsafe.Pointer(cServer))

	cAccount := C.CString(item.Account)
	defer C.free(unsafe.Pointer(cAccount))

	cProtocol := C.CString(string(item.Protocol))
	defer C.free(unsafe.Pointer(cProtocol))

	var cPath *C.char
	if item.Path != "" {
		cPath = C.CString(item.Path)
		defer C.free(unsafe.Pointer(cPath))
	}

	var cAuthType *C.char
	if item.AuthenticationType != "" {
		cAuthType = C.CString(string(item.AuthenticationType))
		defer C.free(unsafe.Pointer(cAuthType))
	}

	var cSecDomain *C.char
	if item.SecurityDomain != "" {
		cSecDomain = C.CString(item.SecurityDomain)
		defer C.free(unsafe.Pointer(cSecDomain))
	}

	var cLabel *C.char
	if item.Label != "" {
		cLabel = C.CString(item.Label)
		defer C.free(unsafe.Pointer(cLabel))
	}

	status := C.addInternetPassword(
		C.SecKeychainRef(k.handle),
		cServer,
		cAccount,
		unsafe.Pointer(&item.Password[0]),
		C.size_t(len(item.Password)),
		cProtocol,
		C.int(item.Port),
		cPath,
		cAuthType,
		cSecDomain,
		cLabel,
	)
	if status != C.errSecSuccess {
		return newError(int32(status))
	}
	return nil
}

// getInternetPassword retrieves an internet password item from the keychain.
func (k *Keychain) getInternetPassword(server, account string, protocol Protocol, port int) (*InternetPasswordItem, error) {
	cServer := C.CString(server)
	defer C.free(unsafe.Pointer(cServer))

	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cAccount))

	cProtocol := C.CString(string(protocol))
	defer C.free(unsafe.Pointer(cProtocol))

	var password unsafe.Pointer
	var passwordLen C.size_t
	var cPath, cAuthType, cSecDomain, cLabel *C.char

	status := C.getInternetPassword(
		C.SecKeychainRef(k.handle),
		cServer,
		cAccount,
		cProtocol,
		C.int(port),
		&password,
		&passwordLen,
		&cPath,
		&cAuthType,
		&cSecDomain,
		&cLabel,
	)
	if status != C.errSecSuccess {
		return nil, newError(int32(status))
	}

	item := &InternetPasswordItem{
		Server:   server,
		Account:  account,
		Protocol: protocol,
		Port:     port,
	}

	if password != nil && passwordLen > 0 {
		item.Password = C.GoBytes(password, C.int(passwordLen))
		C.free(password)
	}

	if cPath != nil {
		item.Path = C.GoString(cPath)
		C.free(unsafe.Pointer(cPath))
	}

	if cAuthType != nil {
		item.AuthenticationType = AuthenticationType(C.GoString(cAuthType))
		C.free(unsafe.Pointer(cAuthType))
	}

	if cSecDomain != nil {
		item.SecurityDomain = C.GoString(cSecDomain)
		C.free(unsafe.Pointer(cSecDomain))
	}

	if cLabel != nil {
		item.Label = C.GoString(cLabel)
		C.free(unsafe.Pointer(cLabel))
	}

	return item, nil
}

// updateInternetPassword updates an existing internet password item.
func (k *Keychain) updateInternetPassword(item *InternetPasswordItem) error {
	cServer := C.CString(item.Server)
	defer C.free(unsafe.Pointer(cServer))

	cAccount := C.CString(item.Account)
	defer C.free(unsafe.Pointer(cAccount))

	cProtocol := C.CString(string(item.Protocol))
	defer C.free(unsafe.Pointer(cProtocol))

	var cPath *C.char
	if item.Path != "" {
		cPath = C.CString(item.Path)
		defer C.free(unsafe.Pointer(cPath))
	}

	var cAuthType *C.char
	if item.AuthenticationType != "" {
		cAuthType = C.CString(string(item.AuthenticationType))
		defer C.free(unsafe.Pointer(cAuthType))
	}

	var cSecDomain *C.char
	if item.SecurityDomain != "" {
		cSecDomain = C.CString(item.SecurityDomain)
		defer C.free(unsafe.Pointer(cSecDomain))
	}

	var cLabel *C.char
	if item.Label != "" {
		cLabel = C.CString(item.Label)
		defer C.free(unsafe.Pointer(cLabel))
	}

	status := C.updateInternetPassword(
		C.SecKeychainRef(k.handle),
		cServer,
		cAccount,
		cProtocol,
		C.int(item.Port),
		unsafe.Pointer(&item.Password[0]),
		C.size_t(len(item.Password)),
		cPath,
		cAuthType,
		cSecDomain,
		cLabel,
	)
	if status != C.errSecSuccess {
		return newError(int32(status))
	}
	return nil
}

// deleteInternetPassword deletes an internet password item from the keychain.
func (k *Keychain) deleteInternetPassword(server, account string, protocol Protocol, port int) error {
	cServer := C.CString(server)
	defer C.free(unsafe.Pointer(cServer))

	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cAccount))

	cProtocol := C.CString(string(protocol))
	defer C.free(unsafe.Pointer(cProtocol))

	status := C.deleteInternetPassword(
		C.SecKeychainRef(k.handle),
		cServer,
		cAccount,
		cProtocol,
		C.int(port),
	)
	if status != C.errSecSuccess {
		return newError(int32(status))
	}
	return nil
}

// Certificate, Key, and Identity operations - stubs for now
// These require more complex handling with SecCertificate, SecKey, and SecIdentity

func (k *Keychain) addCertificate(item *CertificateItem) error {
	// TODO: Implement certificate addition
	return ErrUnknown
}

func (k *Keychain) getCertificate(label string) (*CertificateItem, error) {
	// TODO: Implement certificate retrieval
	return nil, ErrUnknown
}

func (k *Keychain) deleteCertificate(label string) error {
	// TODO: Implement certificate deletion
	return ErrUnknown
}

func (k *Keychain) addKey(item *KeyItem) error {
	// TODO: Implement key addition
	return ErrUnknown
}

func (k *Keychain) getKey(label string) (*KeyItem, error) {
	// TODO: Implement key retrieval
	return nil, ErrUnknown
}

func (k *Keychain) deleteKey(label string) error {
	// TODO: Implement key deletion
	return ErrUnknown
}

func (k *Keychain) addIdentity(item *IdentityItem, password string) error {
	// TODO: Implement identity addition (PKCS#12 import)
	return ErrUnknown
}

func (k *Keychain) getIdentity(label string) (*IdentityItem, error) {
	// TODO: Implement identity retrieval
	return nil, ErrUnknown
}

func (k *Keychain) deleteIdentity(label string) error {
	// TODO: Implement identity deletion
	return ErrUnknown
}
