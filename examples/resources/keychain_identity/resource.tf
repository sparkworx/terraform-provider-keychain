# Import an identity (certificate + private key) into the macOS Keychain
resource "keychain_identity" "example" {
  label       = "Code Signing Identity"
  pkcs12_data = filebase64("${path.module}/identity.p12")
  password    = var.p12_password
}

variable "p12_password" {
  type      = string
  sensitive = true
}

# Computed attributes available after creation:
output "subject" {
  value = keychain_identity.example.subject
}

output "issuer" {
  value = keychain_identity.example.issuer
}

output "not_after" {
  value = keychain_identity.example.not_after
}

output "key_type" {
  value = keychain_identity.example.key_type
}

output "fingerprint_sha256" {
  value = keychain_identity.example.fingerprint_sha256
}
