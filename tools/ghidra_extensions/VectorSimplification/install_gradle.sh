#!/bin/bash
# Install Gradle 8.10.2 locally for building Ghidra extensions
# This is needed because Debian's packaged Gradle may be too old

set -e

GRADLE_VERSION="8.10.2"
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/gradle"
GRADLE_URL="https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip"

echo "Installing Gradle ${GRADLE_VERSION} to ${INSTALL_DIR}..."

# Download Gradle
TEMP_ZIP="/tmp/gradle-${GRADLE_VERSION}.zip"

if command -v wget &> /dev/null; then
    wget -O "$TEMP_ZIP" "$GRADLE_URL"
elif command -v curl &> /dev/null; then
    curl -L -o "$TEMP_ZIP" "$GRADLE_URL"
else
    echo "Error: wget or curl required"
    exit 1
fi

# Extract
rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
unzip -q "$TEMP_ZIP" -d "$INSTALL_DIR"

# Move files up one level
mv "$INSTALL_DIR/gradle-${GRADLE_VERSION}"/* "$INSTALL_DIR/"
rmdir "$INSTALL_DIR/gradle-${GRADLE_VERSION}"

# Cleanup
rm -f "$TEMP_ZIP"

echo "Gradle ${GRADLE_VERSION} installed to: ${INSTALL_DIR}"
echo "Using: ${INSTALL_DIR}/bin/gradle"

# Verify
"$INSTALL_DIR/bin/gradle" --version
