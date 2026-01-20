# Import a cryptographic key into the macOS Keychain
resource "keychain_key" "example" {
  label         = "My Signing Key"
  key_data      = var.private_key_pem
  key_class     = "private"
  key_type      = "rsa"
  key_size_bits = 2048

  # Optional attributes
  extractable     = false
  application_tag = "com.example.signing"
}

variable "private_key_pem" {
  type      = string
  sensitive = true
}

output "key_type" {
  value = keychain_key.example.key_type
}

output "key_size_bits" {
  value = keychain_key.example.key_size_bits
}
