# Configure the Keychain provider
provider "keychain" {
  # Optional: Path to a specific keychain file
  # Defaults to the user's default keychain if not specified
  # keychain_path = "/Users/username/Library/Keychains/MyKeychain.keychain-db"

  # Optional: Password to unlock a locked keychain
  # Can also be set via KEYCHAIN_PASSWORD environment variable
  # password = var.keychain_password
}
