# Read an existing identity from the macOS Keychain
data "keychain_identity" "example" {
  label = "Code Signing Identity"
}

output "subject" {
  value = data.keychain_identity.example.subject
}

output "issuer" {
  value = data.keychain_identity.example.issuer
}

output "serial_number" {
  value = data.keychain_identity.example.serial_number
}

output "not_before" {
  value = data.keychain_identity.example.not_before
}

output "not_after" {
  value = data.keychain_identity.example.not_after
}

output "key_type" {
  value = data.keychain_identity.example.key_type
}

output "key_size_bits" {
  value = data.keychain_identity.example.key_size_bits
}

output "fingerprint_sha256" {
  value = data.keychain_identity.example.fingerprint_sha256
}
