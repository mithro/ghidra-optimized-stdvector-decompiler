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

# Build using Gradle
gradle -PGHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR" distributeExtension

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
