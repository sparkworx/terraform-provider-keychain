#!/bin/bash
#
# Creates a test keychain for terraform-provider-keychain development.
#
# Usage:
#   ./create-test-keychain.sh           # Interactive mode (prompts for password)
#   ./create-test-keychain.sh --ci      # Non-interactive mode (uses "test" as password)
#

set -euo pipefail

KEYCHAIN_NAME="terraform-provider-keychain-test.keychain-db"
KEYCHAIN_PATH="$HOME/Library/Keychains/$KEYCHAIN_NAME"
KEYCHAIN_PASSWORD="test"
CI_MODE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --ci)
            CI_MODE=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--ci]"
            exit 1
            ;;
    esac
done

echo "Test keychain path: $KEYCHAIN_PATH"
echo

# Check if keychain already exists using security tool
if security show-keychain-info "$KEYCHAIN_PATH" >/dev/null 2>&1; then
    echo "Keychain already exists."
    if $CI_MODE; then
        echo "Unlocking keychain for CI..."
        security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"
    fi
    exit 0
fi

echo "Creating test keychain..."

if $CI_MODE; then
    # Non-interactive mode: use fixed password
    security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"

    # Set keychain settings to prevent auto-lock (useful for CI)
    security set-keychain-settings "$KEYCHAIN_PATH"

    # Unlock the keychain
    security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"
else
    # Interactive mode: prompt for password
    echo "You will be prompted to set a password for the keychain."
    echo
    security create-keychain "$KEYCHAIN_PATH"
fi

echo
echo "Keychain created successfully at: $KEYCHAIN_PATH"
echo
echo "To use this keychain with the provider, set:"
echo "  keychain_path = \"$KEYCHAIN_PATH\""
if $CI_MODE; then
    echo "  password = \"$KEYCHAIN_PASSWORD\""
fi
