package keychain

import "time"

// ItemClass represents the type of keychain item (kSecClass).
type ItemClass string

const (
	ItemClassGenericPassword  ItemClass = "genp"
	ItemClassInternetPassword ItemClass = "inet"
	ItemClassCertificate      ItemClass = "cert"
	ItemClassKey              ItemClass = "keys"
	ItemClassIdentity         ItemClass = "idnt"
)

// Protocol represents the protocol for internet passwords (kSecAttrProtocol).
type Protocol string

const (
	ProtocolHTTP   Protocol = "http"
	ProtocolHTTPS  Protocol = "htps"
	ProtocolFTP    Protocol = "ftp "
	ProtocolSSH    Protocol = "ssh "
	ProtocolSMB    Protocol = "smb "
	ProtocolAFP    Protocol = "afp "
	ProtocolLDAP   Protocol = "ldap"
	ProtocolLDAPS  Protocol = "ldps"
)

// AuthenticationType represents the authentication type (kSecAttrAuthenticationType).
type AuthenticationType string

const (
	AuthTypeHTTPBasic  AuthenticationType = "http"
	AuthTypeHTTPDigest AuthenticationType = "httd"
	AuthTypeHTMLForm   AuthenticationType = "form"
	AuthTypeDefault    AuthenticationType = "dflt"
)

// KeyClass represents the class of cryptographic key (kSecAttrKeyClass).
type KeyClass string

const (
	KeyClassPublic    KeyClass = "0"
	KeyClassPrivate   KeyClass = "1"
	KeyClassSymmetric KeyClass = "2"
)

// KeyType represents the type of cryptographic key (kSecAttrKeyType).
type KeyType string

const (
	KeyTypeRSA KeyType = "42"
	KeyTypeEC  KeyType = "73"
	KeyTypeAES KeyType = "aes"
)

// GenericPasswordItem represents a generic password keychain item.
type GenericPasswordItem struct {
	Service     string
	Account     string
	Password    []byte
	Label       string
	Description string
	AccessGroup string
	CreatedAt   time.Time
	ModifiedAt  time.Time
}

// InternetPasswordItem represents an internet password keychain item.
type InternetPasswordItem struct {
	Server             string
	Account            string
	Password           []byte
	Protocol           Protocol
	Port               int
	Path               string
	AuthenticationType AuthenticationType
	SecurityDomain     string
	Label              string
	CreatedAt          time.Time
	ModifiedAt         time.Time
}

// CertificateItem represents a certificate keychain item.
type CertificateItem struct {
	Label             string
	CertificateData   []byte
	Subject           string
	Issuer            string
	SerialNumber      string
	NotBefore         time.Time
	NotAfter          time.Time
	FingerprintSHA1   string
	FingerprintSHA256 string
}

// KeyItem represents a cryptographic key keychain item.
type KeyItem struct {
	Label          string
	KeyData        []byte
	KeyClass       KeyClass
	KeyType        KeyType
	KeySizeInBits  int
	Extractable    bool
	Permanent      bool
	ApplicationTag string
}

// IdentityItem represents an identity (certificate + private key) keychain item.
type IdentityItem struct {
	Label             string
	PKCS12Data        []byte
	CertificateData   []byte
	Subject           string
	Issuer            string
	SerialNumber      string
	NotBefore         time.Time
	NotAfter          time.Time
	FingerprintSHA1   string
	FingerprintSHA256 string
	KeyType           KeyType
	KeySizeInBits     int
}

// Query represents search criteria for keychain items.
type Query struct {
	Class              ItemClass
	Service            string
	Account            string
	Server             string
	Protocol           Protocol
	Port               int
	Path               string
	AuthenticationType AuthenticationType
	Label              string
	MatchLimit         int
	ReturnData         bool
	ReturnAttributes   bool
}
