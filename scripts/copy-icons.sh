#!/bin/bash
# Copy icons from icons directory to static directory
# Run this after updating icons

set -e

cd "$(dirname "$0")/.."

# Ensure icons directory exists
if [ ! -d "icons" ]; then
    echo "Error: icons directory not found"
    exit 1
fi

# Copy icons
cp icons/cloistr-signer.svg internal/web/static/favicon.svg
cp icons/favicon/cloistr-signer-16.svg internal/web/static/favicon-16.svg

echo "Icons copied to internal/web/static/"
