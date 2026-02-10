#!/bin/bash
# Copy icons from assets submodule to static directory
# Run this after cloning or when icons are updated

set -e

cd "$(dirname "$0")/.."

# Ensure submodule is initialized
if [ ! -d "assets/icons" ]; then
    echo "Initializing submodules..."
    git submodule update --init --recursive
fi

# Copy icons
cp assets/icons/cloistr-signer.svg internal/web/static/favicon.svg
cp assets/icons/favicon/cloistr-signer-16.svg internal/web/static/favicon-16.svg

echo "Icons copied to internal/web/static/"
