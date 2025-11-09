#!/bin/bash
# Root/sudo operations for setting up the build environment
# This script installs system packages and creates system-wide symlinks

set -e

echo "========================================================================="
echo "Demo Build Environment Setup - Root Operations"
echo "========================================================================="
echo ""
echo "This script will:"
echo "  1. Install prerequisite packages (python3, msitools, etc.)"
echo "  2. Install clang-20 and lld-20"
echo "  3. Create clang-cl-20 symlink"
echo ""
echo "This requires sudo/root privileges."
echo ""

# Check if we have root privileges
if [ "$EUID" -ne 0 ] && ! sudo -n true 2>/dev/null; then
    echo "This script requires sudo privileges."
    echo "You will be prompted for your password."
    echo ""
fi

# Step 1: Install prerequisites
echo "[1/2] Checking prerequisites..."

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
echo "[2/2] Checking clang-20..."
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

echo ""
echo "========================================================================="
echo "Root operations complete!"
echo "========================================================================="
echo ""
echo "Next: Run setup_build_env_user.sh to download MSVC toolchain (no sudo required)"
echo ""
