#!/bin/sh

# Exit immediately if a command exits with a non-zero status
set -e

PRV_KEY="tessera-private.pem"
PUB_KEY="tessera-public.pem"

echo "Checking for Tessera signing keys..."

# Check if both keys already exist
if [ -f "$PRV_KEY" ] && [ -f "$PUB_KEY" ]; then
    echo "Keys already exist. Skipping generation."
    exit 0
fi

echo "Generating new ECDSA prime256v1 keypair for Tessera..."

# Generate the private key
openssl ecparam -genkey -name prime256v1 -noout -out "$PRV_KEY"

# Extract the public key
openssl ec -in "$PRV_KEY" -pubout -out "$PUB_KEY"

# Secure the private key permissions
chmod 600 "$PRV_KEY"

echo "Successfully generated $PRV_KEY and $PUB_KEY"