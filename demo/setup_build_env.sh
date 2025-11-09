#!/bin/bash
# One-time setup script for building MSVC-compatible demo binaries
# This script installs the toolchain and downloads MSVC headers/SDK

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MSVC_DIR="${MSVC_DIR:-$HOME/.msvc}"

echo "========================================================================="
echo "Demo Build Environment Setup"
echo "========================================================================="
echo ""
echo "This script will:"
echo "  1. Install clang-20 and lld linker"
echo "  2. Download MSVC 14.44 headers and Windows SDK 10.0.26100 (~2.7GB)"
echo "  3. Set up directory structure"
echo ""
echo "Requirements:"
echo "  - Ubuntu 24.04 or compatible Linux distribution"
echo "  - ~9 GB disk space"
echo "  - Internet connection"
echo ""
echo "Installation directory: $MSVC_DIR"
echo ""

# Step 1: Install prerequisites
echo ""
echo "[1/4] Checking prerequisites..."

# Check which packages are missing
MISSING_PKGS=""
for pkg in python3 msitools ca-certificates wget git curl; do
	if ! dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
		MISSING_PKGS="$MISSING_PKGS $pkg"
	fi
done

if [ -n "$MISSING_PKGS" ]; then
	echo "Installing missing packages:$MISSING_PKGS"
	sudo apt-get update -qq
	sudo apt-get install -y $MISSING_PKGS
else
	echo "✓ All prerequisites already installed"
fi

# Step 2: Install clang-20
echo ""
echo "[2/4] Checking clang-20..."
if ! command -v clang-cl-20 &> /dev/null; then
    # Check if clang-20 packages are already installed
    MISSING_CLANG=""
    for pkg in clang-20 lld-20; do
        if ! dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
            MISSING_CLANG="$MISSING_CLANG $pkg"
        fi
    done

    if [ -n "$MISSING_CLANG" ]; then
        echo "Installing LLVM 20 packages:$MISSING_CLANG"
        sudo apt-get install -y $MISSING_CLANG
    else
        echo "✓ LLVM 20 packages already installed"
    fi

    # Create clang-cl-20 symlink if needed
    if [ ! -e /usr/bin/clang-cl-20 ]; then
        echo "Creating clang-cl-20 symlink..."
        sudo ln -s /usr/lib/llvm-20/bin/clang /usr/bin/clang-cl-20
    fi

    echo "✓ clang-20 configured: $(clang-cl-20 --version | head -1)"
else
    echo "✓ clang-cl-20 already installed: $(clang-cl-20 --version | head -1)"
fi

# Step 3: Download msvc-wine tool
echo ""
echo "[3/4] Setting up msvc-wine toolchain downloader..."
TOOLS_DIR="$SCRIPT_DIR/build_setup/tools"
if [ ! -d "$TOOLS_DIR/msvc-wine" ]; then
    echo "Cloning msvc-wine repository..."
    mkdir -p "$TOOLS_DIR"
    git clone https://github.com/mstorsjo/msvc-wine.git "$TOOLS_DIR/msvc-wine"
else
    echo "✓ msvc-wine already available"
fi

# Step 4: Download MSVC toolchain and Windows SDK
echo ""
echo "[4/4] Downloading MSVC toolchain and Windows SDK..."
if [ ! -f "$MSVC_DIR/Windows Kits/10/Include/10.0.26100.0/ucrt/malloc.h" ]; then
    echo "Downloading MSVC 14.44 and Windows SDK 10.0.26100..."
    echo "This will download ~2.7 GB and may take 10-30 minutes..."
    echo ""

    cd "$TOOLS_DIR/msvc-wine"
    python3 ./vsdownload.py --accept-license --dest "$MSVC_DIR"

    echo ""
    echo "Verifying installation..."
    if [ -f "$MSVC_DIR/Windows Kits/10/Include/10.0.26100.0/ucrt/malloc.h" ]; then
        echo "✓ Windows SDK headers installed"
    else
        echo "✗ ERROR: Windows SDK headers not found"
        echo "  Expected: $MSVC_DIR/Windows Kits/10/Include/10.0.26100.0/ucrt/malloc.h"
        exit 1
    fi

    # Fix library case sensitivity (kernel32.lib -> kernel32.Lib)
    echo "Fixing library case-sensitivity..."
    LIB_DIR="$MSVC_DIR/Windows Kits/10/Lib/10.0.26100.0/um/x64"
    if [ -f "$LIB_DIR/kernel32.Lib" ] && [ ! -e "$LIB_DIR/kernel32.lib" ]; then
        ln -s kernel32.Lib "$LIB_DIR/kernel32.lib"
    fi
else
    echo "✓ MSVC toolchain already downloaded"
fi

# Verify Ghidra installation
echo ""
echo "Checking for Ghidra installation..."

# Check if GHIDRA_INSTALL_DIR is set, otherwise try default location
DEFAULT_GHIDRA="$HOME/tools/ghidra"
if [ -z "$GHIDRA_INSTALL_DIR" ]; then
    # Not set - check default location
    if [ -d "$DEFAULT_GHIDRA" ] && [ -f "$DEFAULT_GHIDRA/ghidraRun" ]; then
        echo "✓ Ghidra found at default location: $DEFAULT_GHIDRA"
        echo "  The Makefile will use this automatically"
        echo "  Or set: export GHIDRA_INSTALL_DIR=$DEFAULT_GHIDRA"
    else
        echo "⚠ Warning: GHIDRA_INSTALL_DIR not set and Ghidra not found at default location"
        echo "  Default location checked: $DEFAULT_GHIDRA"
        echo "  To install Ghidra, run: ../setup.sh"
        echo "  Or set manually: export GHIDRA_INSTALL_DIR=/path/to/ghidra"
    fi
else
    # GHIDRA_INSTALL_DIR is set - verify it exists
    if [ -d "$GHIDRA_INSTALL_DIR" ] && [ -f "$GHIDRA_INSTALL_DIR/ghidraRun" ]; then
        echo "✓ Ghidra found at: $GHIDRA_INSTALL_DIR"
    else
        echo "✗ ERROR: GHIDRA_INSTALL_DIR points to invalid directory"
        echo "  $GHIDRA_INSTALL_DIR"
        echo "  Expected to find: ghidraRun"
    fi
fi

# Summary
echo ""
echo "========================================================================="
echo "Setup Complete!"
echo "========================================================================="
echo ""
echo "Environment configured:"
echo "  ✓ clang-cl-19 installed"
echo "  ✓ MSVC 14.44 headers"
echo "  ✓ Windows SDK 10.0.26100"
echo "  ✓ Toolchain location: $MSVC_DIR"
echo ""
echo "Next steps:"
echo "  1. Verify setup:  make check-env"
echo "  2. Build demos:   make"
echo "  3. Create Ghidra projects: make ghidra-projects"
echo "  4. Run tests:     make test"
echo ""
echo "See README.md for more information."
