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
echo "  1. Install clang-19 and lld linker"
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
read -p "Continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Setup cancelled."
    exit 0
fi

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

# Step 2: Install clang-19
echo ""
echo "[2/4] Checking clang-19..."
if ! command -v clang-cl-19 &> /dev/null; then
    # Check if clang-19 packages are already installed
    MISSING_CLANG=""
    for pkg in clang-19 lld-19; do
        if ! dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
            MISSING_CLANG="$MISSING_CLANG $pkg"
        fi
    done

    if [ -n "$MISSING_CLANG" ]; then
        echo "Installing LLVM 19 packages:$MISSING_CLANG"
        sudo apt-get install -y $MISSING_CLANG
    else
        echo "✓ LLVM 19 packages already installed"
    fi

    # Create clang-cl-19 symlink if needed
    if [ ! -e /usr/bin/clang-cl-19 ]; then
        echo "Creating clang-cl-19 symlink..."
        sudo ln -s /usr/lib/llvm-19/bin/clang /usr/bin/clang-cl-19
    fi

    echo "✓ clang-19 configured: $(clang-cl-19 --version | head -1)"
else
    echo "✓ clang-cl-19 already installed: $(clang-cl-19 --version | head -1)"
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
if [ -z "$GHIDRA_INSTALL_DIR" ]; then
    echo "⚠ Warning: GHIDRA_INSTALL_DIR not set"
    echo "  You'll need to set this before running 'make ghidra-projects' or 'make test'"
    echo "  Example: export GHIDRA_INSTALL_DIR=/path/to/ghidra"
else
    if [ -d "$GHIDRA_INSTALL_DIR" ]; then
        echo "✓ Ghidra found at: $GHIDRA_INSTALL_DIR"
    else
        echo "✗ ERROR: GHIDRA_INSTALL_DIR points to non-existent directory"
        echo "  $GHIDRA_INSTALL_DIR"
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
