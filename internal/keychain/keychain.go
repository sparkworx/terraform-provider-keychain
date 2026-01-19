package keychain

// Keychain provides access to a macOS keychain.
type Keychain struct {
	path   string
	handle uintptr
}

// Open opens a keychain at the specified path.
// If path is empty, the default keychain is used.
func Open(path string) (*Keychain, error) {
	return open(path)
}

// Close releases the keychain resources.
func (k *Keychain) Close() error {
	return k.close()
}

// Unlock unlocks the keychain with the given password.
func (k *Keychain) Unlock(password string) error {
	return k.unlock(password)
}

// Lock locks the keychain.
func (k *Keychain) Lock() error {
	return k.lock()
}

// Path returns the path to the keychain file.
func (k *Keychain) Path() string {
	return k.path
}

// Generic Password Operations

// AddGenericPassword adds a generic password item to the keychain.
func (k *Keychain) AddGenericPassword(item *GenericPasswordItem) error {
	return k.addGenericPassword(item)
}

// GetGenericPassword retrieves a generic password item from the keychain.
func (k *Keychain) GetGenericPassword(service, account string) (*GenericPasswordItem, error) {
	return k.getGenericPassword(service, account)
}

// UpdateGenericPassword updates an existing generic password item.
func (k *Keychain) UpdateGenericPassword(item *GenericPasswordItem) error {
	return k.updateGenericPassword(item)
}

// DeleteGenericPassword deletes a generic password item from the keychain.
func (k *Keychain) DeleteGenericPassword(service, account string) error {
	return k.deleteGenericPassword(service, account)
}

// Internet Password Operations

// AddInternetPassword adds an internet password item to the keychain.
func (k *Keychain) AddInternetPassword(item *InternetPasswordItem) error {
	return k.addInternetPassword(item)
}

// GetInternetPassword retrieves an internet password item from the keychain.
func (k *Keychain) GetInternetPassword(server, account string, protocol Protocol, port int) (*InternetPasswordItem, error) {
	return k.getInternetPassword(server, account, protocol, port)
}

// UpdateInternetPassword updates an existing internet password item.
func (k *Keychain) UpdateInternetPassword(item *InternetPasswordItem) error {
	return k.updateInternetPassword(item)
}

// DeleteInternetPassword deletes an internet password item from the keychain.
func (k *Keychain) DeleteInternetPassword(server, account string, protocol Protocol, port int) error {
	return k.deleteInternetPassword(server, account, protocol, port)
}

// Certificate Operations

// AddCertificate adds a certificate to the keychain.
func (k *Keychain) AddCertificate(item *CertificateItem) error {
	return k.addCertificate(item)
}

// GetCertificate retrieves a certificate from the keychain by label.
func (k *Keychain) GetCertificate(label string) (*CertificateItem, error) {
	return k.getCertificate(label)
}

// DeleteCertificate deletes a certificate from the keychain.
func (k *Keychain) DeleteCertificate(label string) error {
	return k.deleteCertificate(label)
}

// Key Operations

// AddKey adds a cryptographic key to the keychain.
func (k *Keychain) AddKey(item *KeyItem) error {
	return k.addKey(item)
}

// GetKey retrieves a key from the keychain by label.
func (k *Keychain) GetKey(label string) (*KeyItem, error) {
	return k.getKey(label)
}

// DeleteKey deletes a key from the keychain.
func (k *Keychain) DeleteKey(label string) error {
	return k.deleteKey(label)
}

// Identity Operations

// AddIdentity adds an identity (certificate + private key) to the keychain.
func (k *Keychain) AddIdentity(item *IdentityItem, password string) error {
	return k.addIdentity(item, password)
}

// GetIdentity retrieves an identity from the keychain by label.
func (k *Keychain) GetIdentity(label string) (*IdentityItem, error) {
	return k.getIdentity(label)
}

// DeleteIdentity deletes an identity from the keychain.
func (k *Keychain) DeleteIdentity(label string) error {
	return k.deleteIdentity(label)
}
