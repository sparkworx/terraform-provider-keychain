#!/bin/bash
#
# Creates a test keychain for terraform-provider-keychain development.
#

set -euo pipefail

KEYCHAIN_NAME="terraform-provider-keychain-test.keychain-db"
KEYCHAIN_PATH="$HOME/Library/Keychains/$KEYCHAIN_NAME"

echo "Test keychain path: $KEYCHAIN_PATH"
echo

# Check if keychain already exists using security tool
if security show-keychain-info "$KEYCHAIN_PATH" >/dev/null 2>&1; then
    echo "Keychain already exists. Nothing to do."
    exit 0
fi

echo "Creating test keychain..."
echo "You will be prompted to set a password for the keychain."
echo

# Create the keychain - security will prompt for password
security create-keychain "$KEYCHAIN_PATH"

echo
echo "Keychain created successfully at: $KEYCHAIN_PATH"
echo
echo "To use this keychain with the provider, set:"
echo "  keychain_path = \"$KEYCHAIN_PATH\""
