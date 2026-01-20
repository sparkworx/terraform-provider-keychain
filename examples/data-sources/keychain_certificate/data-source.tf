# Read an existing certificate from the macOS Keychain
data "keychain_certificate" "example" {
  label = "My CA Certificate"
}

output "subject" {
  value = data.keychain_certificate.example.subject
}

output "issuer" {
  value = data.keychain_certificate.example.issuer
}

output "serial_number" {
  value = data.keychain_certificate.example.serial_number
}

output "not_before" {
  value = data.keychain_certificate.example.not_before
}

output "not_after" {
  value = data.keychain_certificate.example.not_after
}

output "fingerprint_sha1" {
  value = data.keychain_certificate.example.fingerprint_sha1
}

output "fingerprint_sha256" {
  value = data.keychain_certificate.example.fingerprint_sha256
}

output "certificate" {
  value     = data.keychain_certificate.example.certificate
  sensitive = true
}
