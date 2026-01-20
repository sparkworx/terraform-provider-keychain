# Read an existing internet password from the macOS Keychain
data "keychain_internet_password" "example" {
  server   = "api.example.com"
  account  = "existing-user"
  protocol = "https"
}

output "password" {
  value     = data.keychain_internet_password.example.password
  sensitive = true
}

output "port" {
  value = data.keychain_internet_password.example.port
}

output "path" {
  value = data.keychain_internet_password.example.path
}
