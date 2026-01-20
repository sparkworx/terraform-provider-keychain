# Read an existing generic password from the macOS Keychain
data "keychain_generic_password" "example" {
  service = "existing-service"
  account = "existing-account"
}

output "password" {
  value     = data.keychain_generic_password.example.password
  sensitive = true
}

output "label" {
  value = data.keychain_generic_password.example.label
}
