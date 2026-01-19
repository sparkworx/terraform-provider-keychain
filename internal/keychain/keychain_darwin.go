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

// Add a certificate to the keychain
static OSStatus addCertificate(
    SecKeychainRef keychain,
    const void *certData,
    size_t certDataLen,
    const char *label
) {
    // Create SecCertificate from DER data
    CFDataRef cfCertData = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)certData, (CFIndex)certDataLen);
    if (cfCertData == NULL) {
        return errSecParam;
    }

    SecCertificateRef cert = SecCertificateCreateWithData(kCFAllocatorDefault, cfCertData);
    if (cert == NULL) {
        CFRelease(cfCertData);
        return errSecParam;
    }

    // Build attributes dictionary for adding
    CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    CFDictionarySetValue(attrs, kSecClass, kSecClassCertificate);
    CFDictionarySetValue(attrs, kSecValueRef, cert);

    if (keychain != NULL) {
        CFDictionarySetValue(attrs, kSecUseKeychain, keychain);
    }

    // Add the certificate first
    OSStatus status = SecItemAdd(attrs, NULL);
    CFRelease(attrs);

    if (status != errSecSuccess && status != errSecDuplicateItem) {
        CFRelease(cert);
        CFRelease(cfCertData);
        return status;
    }

    // Now update the label using a separate query
    // This is needed because kSecAttrLabel can't be set during add with kSecValueRef
    if (label != NULL && label[0] != '\0') {
        CFMutableDictionaryRef query = CFDictionaryCreateMutable(
            kCFAllocatorDefault, 0,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks
        );
        CFDictionarySetValue(query, kSecClass, kSecClassCertificate);
        CFDictionarySetValue(query, kSecValueRef, cert);

        if (keychain != NULL) {
            CFArrayRef keychains = CFArrayCreate(kCFAllocatorDefault, (const void **)&keychain, 1, &kCFTypeArrayCallBacks);
            CFDictionarySetValue(query, kSecMatchSearchList, keychains);
            CFRelease(keychains);
        }

        CFMutableDictionaryRef updateAttrs = CFDictionaryCreateMutable(
            kCFAllocatorDefault, 0,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks
        );

        CFStringRef cfLabel = createCFString(label);
        if (cfLabel) {
            CFDictionarySetValue(updateAttrs, kSecAttrLabel, cfLabel);
        }

        OSStatus updateStatus = SecItemUpdate(query, updateAttrs);

        if (cfLabel) CFRelease(cfLabel);
        CFRelease(updateAttrs);
        CFRelease(query);

        // Ignore update failures - the cert was added successfully
        (void)updateStatus;
    }

    CFRelease(cert);
    CFRelease(cfCertData);

    return errSecSuccess;
}

// Get a certificate from the keychain by label
static OSStatus getCertificate(
    SecKeychainRef keychain,
    const char *label,
    void **certData,
    size_t *certDataLen,
    char **outSubject
) {
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    CFDictionarySetValue(query, kSecClass, kSecClassCertificate);
    CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecReturnAttributes, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);

    if (keychain != NULL) {
        CFArrayRef keychains = CFArrayCreate(kCFAllocatorDefault, (const void **)&keychain, 1, &kCFTypeArrayCallBacks);
        CFDictionarySetValue(query, kSecMatchSearchList, keychains);
        CFRelease(keychains);
    }

    CFStringRef cfLabel = createCFString(label);
    if (cfLabel) {
        CFDictionarySetValue(query, kSecAttrLabel, cfLabel);
    }

    CFDictionaryRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, (CFTypeRef *)&result);

    if (cfLabel) CFRelease(cfLabel);
    CFRelease(query);

    if (status != errSecSuccess || result == NULL) {
        return status;
    }

    // Get the certificate reference
    SecCertificateRef certRef = (SecCertificateRef)CFDictionaryGetValue(result, kSecValueRef);
    if (certRef == NULL) {
        CFRelease(result);
        return errSecItemNotFound;
    }

    // Get DER data
    CFDataRef derData = SecCertificateCopyData(certRef);
    if (derData) {
        *certDataLen = (size_t)CFDataGetLength(derData);
        *certData = malloc(*certDataLen);
        if (*certData) {
            memcpy(*certData, CFDataGetBytePtr(derData), *certDataLen);
        }
        CFRelease(derData);
    }

    // Get subject summary
    if (outSubject) {
        CFStringRef subjectSummary = SecCertificateCopySubjectSummary(certRef);
        if (subjectSummary) {
            *outSubject = cfStringToCString(subjectSummary);
            CFRelease(subjectSummary);
        }
    }

    CFRelease(result);
    return status;
}

// Delete a certificate from the keychain by label
static OSStatus deleteCertificate(
    SecKeychainRef keychain,
    const char *label
) {
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    CFDictionarySetValue(query, kSecClass, kSecClassCertificate);

    if (keychain != NULL) {
        CFArrayRef keychains = CFArrayCreate(kCFAllocatorDefault, (const void **)&keychain, 1, &kCFTypeArrayCallBacks);
        CFDictionarySetValue(query, kSecMatchSearchList, keychains);
        CFRelease(keychains);
    }

    CFStringRef cfLabel = createCFString(label);
    if (cfLabel) {
        CFDictionarySetValue(query, kSecAttrLabel, cfLabel);
    }

    OSStatus status = SecItemDelete(query);

    if (cfLabel) CFRelease(cfLabel);
    CFRelease(query);

    return status;
}

// Helper to convert key class string to CFType
static CFTypeRef keyClassToCFType(const char *keyClass) {
    if (keyClass == NULL) return NULL;
    if (strcmp(keyClass, "public") == 0) return kSecAttrKeyClassPublic;
    if (strcmp(keyClass, "private") == 0) return kSecAttrKeyClassPrivate;
    if (strcmp(keyClass, "symmetric") == 0) return kSecAttrKeyClassSymmetric;
    return NULL;
}

// Helper to convert key type string to CFType
static CFTypeRef keyTypeToCFType(const char *keyType) {
    if (keyType == NULL) return NULL;
    if (strcmp(keyType, "rsa") == 0) return kSecAttrKeyTypeRSA;
    if (strcmp(keyType, "ec") == 0) return kSecAttrKeyTypeEC;
    if (strcmp(keyType, "aes") == 0) return kSecAttrKeyTypeAES;
    return NULL;
}

// Helper to convert CFType to key class string (caller must free)
static char* cfTypeToKeyClass(CFTypeRef keyClass) {
    if (keyClass == NULL) return NULL;
    if (CFEqual(keyClass, kSecAttrKeyClassPublic)) return strdup("public");
    if (CFEqual(keyClass, kSecAttrKeyClassPrivate)) return strdup("private");
    if (CFEqual(keyClass, kSecAttrKeyClassSymmetric)) return strdup("symmetric");
    return NULL;
}

// Helper to convert CFType to key type string (caller must free)
static char* cfTypeToKeyType(CFTypeRef keyType) {
    if (keyType == NULL) return NULL;
    if (CFEqual(keyType, kSecAttrKeyTypeRSA)) return strdup("rsa");
    if (CFEqual(keyType, kSecAttrKeyTypeEC)) return strdup("ec");
    if (CFEqual(keyType, kSecAttrKeyTypeECSECPrimeRandom)) return strdup("ec");
    if (CFEqual(keyType, kSecAttrKeyTypeAES)) return strdup("aes");
    return NULL;
}

// Add a key to the keychain
// We store keys as generic password items with a special service prefix
// This is a common workaround since kSecClassKey requires specific key formats
// Service: "__keychain_key__:<keyClass>:<keyType>:<keySize>"
// Account: label
static OSStatus addKey(
    SecKeychainRef keychain,
    const void *keyData,
    size_t keyDataLen,
    const char *label,
    const char *keyClass,
    const char *keyType,
    int keySizeInBits,
    int extractable,
    int permanent,
    const char *applicationTag
) {
    // Build a service string that encodes the key metadata
    char service[256];
    snprintf(service, sizeof(service), "__keychain_key__:%s:%s:%d:%d",
             keyClass ? keyClass : "",
             keyType ? keyType : "",
             keySizeInBits,
             extractable ? 1 : 0);

    CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    CFDictionarySetValue(attrs, kSecClass, kSecClassGenericPassword);

    if (keychain != NULL) {
        CFDictionarySetValue(attrs, kSecUseKeychain, keychain);
    }

    CFStringRef cfService = createCFString(service);
    if (cfService) {
        CFDictionarySetValue(attrs, kSecAttrService, cfService);
    }

    CFStringRef cfAccount = createCFString(label);
    if (cfAccount) {
        CFDictionarySetValue(attrs, kSecAttrAccount, cfAccount);
    }

    CFDataRef cfKeyData = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)keyData, (CFIndex)keyDataLen);
    if (cfKeyData) {
        CFDictionarySetValue(attrs, kSecValueData, cfKeyData);
    }

    CFStringRef cfLabel = createCFString(label);
    if (cfLabel) {
        CFDictionarySetValue(attrs, kSecAttrLabel, cfLabel);
    }

    // Store application tag in the description field if provided
    CFStringRef cfAppTag = createCFString(applicationTag);
    if (cfAppTag) {
        CFDictionarySetValue(attrs, kSecAttrDescription, cfAppTag);
    }

    OSStatus status = SecItemAdd(attrs, NULL);

    if (cfService) CFRelease(cfService);
    if (cfAccount) CFRelease(cfAccount);
    if (cfKeyData) CFRelease(cfKeyData);
    if (cfLabel) CFRelease(cfLabel);
    if (cfAppTag) CFRelease(cfAppTag);
    CFRelease(attrs);

    return status;
}

// Get a key from the keychain by label
// Keys are stored as generic passwords with service prefix "__keychain_key__"
// We use a two-step process: first find the item, then get its data
static OSStatus getKey(
    SecKeychainRef keychain,
    const char *label,
    void **keyData,
    size_t *keyDataLen,
    char **outKeyClass,
    char **outKeyType,
    int *outKeySizeInBits,
    int *outExtractable
) {
    // Initialize outputs
    *keyData = NULL;
    *keyDataLen = 0;
    if (outKeyClass) *outKeyClass = NULL;
    if (outKeyType) *outKeyType = NULL;
    if (outKeySizeInBits) *outKeySizeInBits = 0;
    if (outExtractable) *outExtractable = 1;

    // First, find items with this account (label) and get their attributes
    CFMutableDictionaryRef searchQuery = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    CFDictionarySetValue(searchQuery, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(searchQuery, kSecReturnAttributes, kCFBooleanTrue);
    CFDictionarySetValue(searchQuery, kSecMatchLimit, kSecMatchLimitAll);

    if (keychain != NULL) {
        CFArrayRef keychains = CFArrayCreate(kCFAllocatorDefault, (const void **)&keychain, 1, &kCFTypeArrayCallBacks);
        CFDictionarySetValue(searchQuery, kSecMatchSearchList, keychains);
        CFRelease(keychains);
    }

    // Search by account (which is the label)
    CFStringRef cfAccount = createCFString(label);
    if (cfAccount) {
        CFDictionarySetValue(searchQuery, kSecAttrAccount, cfAccount);
    }

    CFTypeRef searchResults = NULL;
    OSStatus status = SecItemCopyMatching(searchQuery, &searchResults);

    if (cfAccount) CFRelease(cfAccount);
    CFRelease(searchQuery);

    if (status != errSecSuccess || searchResults == NULL) {
        return status;
    }

    // Find the item with service starting with "__keychain_key__"
    CFStringRef foundService = NULL;
    CFArrayRef resultsArray = NULL;
    if (CFGetTypeID(searchResults) == CFArrayGetTypeID()) {
        resultsArray = (CFArrayRef)searchResults;
    } else if (CFGetTypeID(searchResults) == CFDictionaryGetTypeID()) {
        // Single result came back as dictionary
        CFDictionaryRef item = (CFDictionaryRef)searchResults;
        CFStringRef serviceRef = (CFStringRef)CFDictionaryGetValue(item, kSecAttrService);
        if (serviceRef) {
            char *serviceStr = cfStringToCString(serviceRef);
            if (serviceStr && strncmp(serviceStr, "__keychain_key__:", 17) == 0) {
                foundService = serviceRef;
                CFRetain(foundService);
                // Parse metadata
                char keyClassStr[32] = "";
                char keyTypeStr[32] = "";
                int keySize = 0;
                int extractableVal = 1;
                if (sscanf(serviceStr, "__keychain_key__:%31[^:]:%31[^:]:%d:%d",
                           keyClassStr, keyTypeStr, &keySize, &extractableVal) >= 3) {
                    if (outKeyClass && keyClassStr[0] != '\0') *outKeyClass = strdup(keyClassStr);
                    if (outKeyType && keyTypeStr[0] != '\0') *outKeyType = strdup(keyTypeStr);
                    if (outKeySizeInBits) *outKeySizeInBits = keySize;
                    if (outExtractable) *outExtractable = extractableVal;
                }
            }
            if (serviceStr) free(serviceStr);
        }
        CFRelease(searchResults);
    } else {
        CFRelease(searchResults);
        return errSecItemNotFound;
    }

    // Process array results
    if (resultsArray != NULL) {
        CFIndex count = CFArrayGetCount(resultsArray);
        for (CFIndex i = 0; i < count; i++) {
            CFDictionaryRef item = (CFDictionaryRef)CFArrayGetValueAtIndex(resultsArray, i);
            CFStringRef serviceRef = (CFStringRef)CFDictionaryGetValue(item, kSecAttrService);
            if (serviceRef) {
                char *serviceStr = cfStringToCString(serviceRef);
                if (serviceStr && strncmp(serviceStr, "__keychain_key__:", 17) == 0) {
                    foundService = serviceRef;
                    CFRetain(foundService);
                    // Parse metadata
                    char keyClassStr[32] = "";
                    char keyTypeStr[32] = "";
                    int keySize = 0;
                    int extractableVal = 1;
                    if (sscanf(serviceStr, "__keychain_key__:%31[^:]:%31[^:]:%d:%d",
                               keyClassStr, keyTypeStr, &keySize, &extractableVal) >= 3) {
                        if (outKeyClass && keyClassStr[0] != '\0') *outKeyClass = strdup(keyClassStr);
                        if (outKeyType && keyTypeStr[0] != '\0') *outKeyType = strdup(keyTypeStr);
                        if (outKeySizeInBits) *outKeySizeInBits = keySize;
                        if (outExtractable) *outExtractable = extractableVal;
                    }
                    free(serviceStr);
                    break;
                }
                if (serviceStr) free(serviceStr);
            }
        }
        CFRelease(resultsArray);
    }

    if (foundService == NULL) {
        return errSecItemNotFound;
    }

    // Now fetch the data with a specific query
    CFMutableDictionaryRef dataQuery = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    CFDictionarySetValue(dataQuery, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(dataQuery, kSecReturnData, kCFBooleanTrue);
    CFDictionarySetValue(dataQuery, kSecMatchLimit, kSecMatchLimitOne);

    if (keychain != NULL) {
        CFArrayRef keychains = CFArrayCreate(kCFAllocatorDefault, (const void **)&keychain, 1, &kCFTypeArrayCallBacks);
        CFDictionarySetValue(dataQuery, kSecMatchSearchList, keychains);
        CFRelease(keychains);
    }

    CFDictionarySetValue(dataQuery, kSecAttrService, foundService);

    CFStringRef cfAcc = createCFString(label);
    if (cfAcc) {
        CFDictionarySetValue(dataQuery, kSecAttrAccount, cfAcc);
    }

    CFDataRef cfKeyData = NULL;
    status = SecItemCopyMatching(dataQuery, (CFTypeRef *)&cfKeyData);

    if (cfAcc) CFRelease(cfAcc);
    CFRelease(dataQuery);
    CFRelease(foundService);

    if (status != errSecSuccess || cfKeyData == NULL) {
        return status;
    }

    // Extract key data
    *keyDataLen = (size_t)CFDataGetLength(cfKeyData);
    *keyData = malloc(*keyDataLen);
    if (*keyData) {
        memcpy(*keyData, CFDataGetBytePtr(cfKeyData), *keyDataLen);
    }
    CFRelease(cfKeyData);

    return errSecSuccess;
}

// Delete a key from the keychain by label
// Keys are stored as generic passwords with service prefix "__keychain_key__"
static OSStatus deleteKey(
    SecKeychainRef keychain,
    const char *label
) {
    // First, find the key to get its full service name
    CFMutableDictionaryRef searchQuery = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    CFDictionarySetValue(searchQuery, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(searchQuery, kSecReturnAttributes, kCFBooleanTrue);
    CFDictionarySetValue(searchQuery, kSecMatchLimit, kSecMatchLimitAll);

    if (keychain != NULL) {
        CFArrayRef keychains = CFArrayCreate(kCFAllocatorDefault, (const void **)&keychain, 1, &kCFTypeArrayCallBacks);
        CFDictionarySetValue(searchQuery, kSecMatchSearchList, keychains);
        CFRelease(keychains);
    }

    CFStringRef cfAccount = createCFString(label);
    if (cfAccount) {
        CFDictionarySetValue(searchQuery, kSecAttrAccount, cfAccount);
    }

    CFArrayRef results = NULL;
    OSStatus status = SecItemCopyMatching(searchQuery, (CFTypeRef *)&results);

    if (cfAccount) CFRelease(cfAccount);
    CFRelease(searchQuery);

    if (status != errSecSuccess || results == NULL) {
        return status;
    }

    // Find and delete the item with service starting with "__keychain_key__"
    OSStatus deleteStatus = errSecItemNotFound;
    CFIndex count = CFArrayGetCount(results);
    for (CFIndex i = 0; i < count; i++) {
        CFDictionaryRef item = (CFDictionaryRef)CFArrayGetValueAtIndex(results, i);
        CFStringRef serviceRef = (CFStringRef)CFDictionaryGetValue(item, kSecAttrService);
        if (serviceRef) {
            char *serviceStr = cfStringToCString(serviceRef);
            if (serviceStr && strncmp(serviceStr, "__keychain_key__:", 17) == 0) {
                free(serviceStr);

                // Build delete query with exact service
                CFMutableDictionaryRef deleteQuery = CFDictionaryCreateMutable(
                    kCFAllocatorDefault, 0,
                    &kCFTypeDictionaryKeyCallBacks,
                    &kCFTypeDictionaryValueCallBacks
                );

                CFDictionarySetValue(deleteQuery, kSecClass, kSecClassGenericPassword);

                if (keychain != NULL) {
                    CFArrayRef keychains = CFArrayCreate(kCFAllocatorDefault, (const void **)&keychain, 1, &kCFTypeArrayCallBacks);
                    CFDictionarySetValue(deleteQuery, kSecMatchSearchList, keychains);
                    CFRelease(keychains);
                }

                CFDictionarySetValue(deleteQuery, kSecAttrService, serviceRef);

                CFStringRef cfAcc = createCFString(label);
                if (cfAcc) {
                    CFDictionarySetValue(deleteQuery, kSecAttrAccount, cfAcc);
                }

                deleteStatus = SecItemDelete(deleteQuery);

                if (cfAcc) CFRelease(cfAcc);
                CFRelease(deleteQuery);
                break;
            }
            if (serviceStr) free(serviceStr);
        }
    }

    CFRelease(results);
    return deleteStatus;
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

// Certificate operations

func (k *Keychain) addCertificate(item *CertificateItem) error {
	if len(item.CertificateData) == 0 {
		return ErrInvalidParameter
	}

	var cLabel *C.char
	if item.Label != "" {
		cLabel = C.CString(item.Label)
		defer C.free(unsafe.Pointer(cLabel))
	}

	status := C.addCertificate(
		C.SecKeychainRef(k.handle),
		unsafe.Pointer(&item.CertificateData[0]),
		C.size_t(len(item.CertificateData)),
		cLabel,
	)
	if status != C.errSecSuccess {
		return newError(int32(status))
	}
	return nil
}

func (k *Keychain) getCertificate(label string) (*CertificateItem, error) {
	cLabel := C.CString(label)
	defer C.free(unsafe.Pointer(cLabel))

	var certData unsafe.Pointer
	var certDataLen C.size_t
	var cSubject *C.char

	status := C.getCertificate(
		C.SecKeychainRef(k.handle),
		cLabel,
		&certData,
		&certDataLen,
		&cSubject,
	)
	if status != C.errSecSuccess {
		return nil, newError(int32(status))
	}

	item := &CertificateItem{
		Label: label,
	}

	if certData != nil && certDataLen > 0 {
		item.CertificateData = C.GoBytes(certData, C.int(certDataLen))
		C.free(certData)
	}

	if cSubject != nil {
		item.Subject = C.GoString(cSubject)
		C.free(unsafe.Pointer(cSubject))
	}

	return item, nil
}

func (k *Keychain) deleteCertificate(label string) error {
	cLabel := C.CString(label)
	defer C.free(unsafe.Pointer(cLabel))

	status := C.deleteCertificate(
		C.SecKeychainRef(k.handle),
		cLabel,
	)
	if status != C.errSecSuccess {
		return newError(int32(status))
	}
	return nil
}

func (k *Keychain) addKey(item *KeyItem) error {
	if len(item.KeyData) == 0 {
		return ErrInvalidParameter
	}

	var cLabel *C.char
	if item.Label != "" {
		cLabel = C.CString(item.Label)
		defer C.free(unsafe.Pointer(cLabel))
	}

	var cKeyClass *C.char
	if item.KeyClass != "" {
		cKeyClass = C.CString(keyClassToString(item.KeyClass))
		defer C.free(unsafe.Pointer(cKeyClass))
	}

	var cKeyType *C.char
	if item.KeyType != "" {
		cKeyType = C.CString(keyTypeToString(item.KeyType))
		defer C.free(unsafe.Pointer(cKeyType))
	}

	var cAppTag *C.char
	if item.ApplicationTag != "" {
		cAppTag = C.CString(item.ApplicationTag)
		defer C.free(unsafe.Pointer(cAppTag))
	}

	extractable := 0
	if item.Extractable {
		extractable = 1
	}

	permanent := 0
	if item.Permanent {
		permanent = 1
	}

	status := C.addKey(
		C.SecKeychainRef(k.handle),
		unsafe.Pointer(&item.KeyData[0]),
		C.size_t(len(item.KeyData)),
		cLabel,
		cKeyClass,
		cKeyType,
		C.int(item.KeySizeInBits),
		C.int(extractable),
		C.int(permanent),
		cAppTag,
	)
	if status != C.errSecSuccess {
		return newError(int32(status))
	}
	return nil
}

func (k *Keychain) getKey(label string) (*KeyItem, error) {
	cLabel := C.CString(label)
	defer C.free(unsafe.Pointer(cLabel))

	var keyData unsafe.Pointer
	var keyDataLen C.size_t
	var cKeyClass, cKeyType *C.char
	var keySizeInBits, extractable C.int

	status := C.getKey(
		C.SecKeychainRef(k.handle),
		cLabel,
		&keyData,
		&keyDataLen,
		&cKeyClass,
		&cKeyType,
		&keySizeInBits,
		&extractable,
	)
	if status != C.errSecSuccess {
		return nil, newError(int32(status))
	}

	item := &KeyItem{
		Label:         label,
		KeySizeInBits: int(keySizeInBits),
		Extractable:   extractable != 0,
	}

	if keyData != nil && keyDataLen > 0 {
		item.KeyData = C.GoBytes(keyData, C.int(keyDataLen))
		C.free(keyData)
	}

	if cKeyClass != nil {
		item.KeyClass = stringToKeyClass(C.GoString(cKeyClass))
		C.free(unsafe.Pointer(cKeyClass))
	}

	if cKeyType != nil {
		item.KeyType = stringToKeyType(C.GoString(cKeyType))
		C.free(unsafe.Pointer(cKeyType))
	}

	return item, nil
}

func (k *Keychain) deleteKey(label string) error {
	cLabel := C.CString(label)
	defer C.free(unsafe.Pointer(cLabel))

	status := C.deleteKey(
		C.SecKeychainRef(k.handle),
		cLabel,
	)
	if status != C.errSecSuccess {
		return newError(int32(status))
	}
	return nil
}

// Helper functions for key class and type conversion
func keyClassToString(kc KeyClass) string {
	switch kc {
	case KeyClassPublic:
		return "public"
	case KeyClassPrivate:
		return "private"
	case KeyClassSymmetric:
		return "symmetric"
	default:
		return string(kc)
	}
}

func stringToKeyClass(s string) KeyClass {
	switch s {
	case "public":
		return KeyClassPublic
	case "private":
		return KeyClassPrivate
	case "symmetric":
		return KeyClassSymmetric
	default:
		return KeyClass(s)
	}
}

func keyTypeToString(kt KeyType) string {
	switch kt {
	case KeyTypeRSA:
		return "rsa"
	case KeyTypeEC:
		return "ec"
	case KeyTypeAES:
		return "aes"
	default:
		return string(kt)
	}
}

func stringToKeyType(s string) KeyType {
	switch s {
	case "rsa":
		return KeyTypeRSA
	case "ec":
		return KeyTypeEC
	case "aes":
		return KeyTypeAES
	default:
		return KeyType(s)
	}
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
