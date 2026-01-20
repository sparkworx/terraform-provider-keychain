# Manage an internet password in the macOS Keychain
resource "keychain_internet_password" "example" {
  server   = "api.example.com"
  account  = "deploy-user"
  protocol = "https"
  password = var.deploy_password

  # Optional attributes
  port                = 443
  path                = "/v1"
  label               = "Example API Credentials"
  authentication_type = "httpBasic"
}

variable "deploy_password" {
  type      = string
  sensitive = true
}

output "server" {
  value = keychain_internet_password.example.server
}
