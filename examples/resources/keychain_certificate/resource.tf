# Import a certificate into the macOS Keychain
resource "keychain_certificate" "example" {
  label       = "My CA Certificate"
  certificate = file("${path.module}/ca-cert.pem")
}

# Computed attributes available after creation:
output "subject" {
  value = keychain_certificate.example.subject
}

output "issuer" {
  value = keychain_certificate.example.issuer
}

output "not_after" {
  value = keychain_certificate.example.not_after
}

output "fingerprint_sha256" {
  value = keychain_certificate.example.fingerprint_sha256
}
