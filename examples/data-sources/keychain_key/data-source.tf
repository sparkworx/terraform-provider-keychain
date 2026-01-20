# Read an existing key from the macOS Keychain
data "keychain_key" "example" {
  label = "My Signing Key"
}

output "key_class" {
  value = data.keychain_key.example.key_class
}

output "key_type" {
  value = data.keychain_key.example.key_type
}

output "key_size_bits" {
  value = data.keychain_key.example.key_size_bits
}

output "extractable" {
  value = data.keychain_key.example.extractable
}

output "key_data" {
  value     = data.keychain_key.example.key_data
  sensitive = true
}
