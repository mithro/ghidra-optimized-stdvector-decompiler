#!/bin/bash
# Build script for VectorSimplification Ghidra extension

set -e

# Find Ghidra installation
GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-$HOME/tools/ghidra}"

if [ ! -d "$GHIDRA_INSTALL_DIR" ]; then
    echo "Error: Ghidra installation not found at $GHIDRA_INSTALL_DIR"
    echo "Set GHIDRA_INSTALL_DIR environment variable or install Ghidra at ~/tools/ghidra/"
    exit 1
fi

echo "Using Ghidra installation: $GHIDRA_INSTALL_DIR"

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "Building VectorSimplification extension..."
echo ""

# Find Gradle - try multiple sources
GRADLE_CMD=""

# 1. Check for Gradle wrapper in current directory
if [ -f "./gradlew" ]; then
    GRADLE_CMD="./gradlew"
    echo "Using Gradle wrapper: ./gradlew"
# 2. Check if gradle is in PATH
elif command -v gradle &> /dev/null; then
    GRADLE_CMD="gradle"
    echo "Using system Gradle: $(which gradle)"
# 3. Check common installation locations
elif [ -f "/opt/gradle/bin/gradle" ]; then
    GRADLE_CMD="/opt/gradle/bin/gradle"
    echo "Using Gradle from: /opt/gradle/bin/gradle"
else
    echo ""
    echo "ERROR: Gradle not found!"
    echo ""
    echo "Gradle is required to build the extension. Please install it:"
    echo ""
    echo "  Ubuntu/Debian:"
    echo "    sudo apt-get update"
    echo "    sudo apt-get install gradle"
    echo ""
    echo "  Or download from: https://gradle.org/releases/"
    echo ""
    exit 1
fi

# Build using Gradle
$GRADLE_CMD -PGHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR" distributeExtension

echo ""
echo "========================================================================"
echo "Build complete!"
echo ""

# Find the output
DIST_FILE=$(ls -t dist/*.zip 2>/dev/null | head -1)
if [ -n "$DIST_FILE" ]; then
    echo "Extension package: $DIST_FILE"
    echo ""
    echo "To install:"
    echo "1. Unzip to $GHIDRA_INSTALL_DIR/Extensions/Ghidra/"
    echo "2. Restart Ghidra"
    echo "3. File → Configure → Check 'VectorSimplification'"
    echo ""
    echo "Or copy directly:"
    echo "    cp $DIST_FILE $GHIDRA_INSTALL_DIR/Extensions/Ghidra/"
else
    echo "Warning: Could not find output package in dist/"
fi
echo "========================================================================"
