# Manage a generic password in the macOS Keychain
resource "keychain_generic_password" "example" {
  service  = "my-application"
  account  = "api-user"
  password = var.api_password

  # Optional attributes
  label       = "My Application API Key"
  description = "API key for production environment"
}

variable "api_password" {
  type      = string
  sensitive = true
}

output "service" {
  value = keychain_generic_password.example.service
}
