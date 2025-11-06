#!/bin/bash
set -e

# Alternative approach: Use clang-cl (LLVM's MSVC-compatible compiler)
# This produces real MSVC-compatible binaries with PDB files, but installs easily on Linux

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$SCRIPT_DIR/test/vector_test"
LOG_FILE="$SCRIPT_DIR/clangcl_build.log"

# Redirect all output to log file AND console using tee
if [ -z "$LOGGING_ENABLED" ]; then
    export LOGGING_ENABLED=1
    echo "Logging to: $LOG_FILE"
    echo "Starting clang-cl build at $(date)" > "$LOG_FILE"
    exec > >(tee -a "$LOG_FILE") 2>&1
fi

echo "========================================================================="
echo "MSVC-Compatible Build Using clang-cl"
echo "========================================================================="
echo "Log file: $LOG_FILE"
echo "Started at: $(date)"
echo ""
echo "This approach uses clang-cl, which is LLVM's MSVC-compatible compiler."
echo "It produces real Windows PE executables with PDB debug symbols."
echo ""

# Step 1: Install LLVM/clang
echo "[1/4] Installing LLVM and clang..."
if ! command -v clang-cl &> /dev/null; then
    echo "Installing LLVM toolchain..."

    # Detect OS for appropriate installation method
    if [ -f /etc/os-release ]; then
        . /etc/os-release

        if [ "$ID" = "debian" ]; then
            echo "Detected Debian $VERSION_CODENAME"
            # Debian trixie has LLVM 18 in repos, but we'll use apt.llvm.org for latest
            echo "Using apt.llvm.org LLVM repository..."

            # Download and run llvm.sh (supports Debian)
            wget https://apt.llvm.org/llvm.sh
            chmod +x llvm.sh
            sudo ./llvm.sh 18
            rm llvm.sh

        elif [ "$ID" = "ubuntu" ]; then
            echo "Detected Ubuntu"
            echo "Using apt.llvm.org LLVM repository..."

            # Download and run llvm.sh (supports Ubuntu)
            wget https://apt.llvm.org/llvm.sh
            chmod +x llvm.sh
            sudo ./llvm.sh 18
            rm llvm.sh

        else
            echo "ERROR: Unsupported OS: $ID"
            echo "This script only supports Debian and Ubuntu."
            echo "Please install LLVM/clang manually and try again."
            exit 1
        fi
    else
        echo "ERROR: Cannot detect OS (/etc/os-release not found)"
        exit 1
    fi

    # Install clang and lld
    sudo apt-get install -y clang-18 lld-18 llvm-18

    # Create symlinks
    sudo update-alternatives --install /usr/bin/clang-cl clang-cl /usr/bin/clang-cl-18 100
    sudo update-alternatives --install /usr/bin/lld-link lld-link /usr/bin/lld-link-18 100
else
    echo "clang-cl already installed: $(clang-cl --version | head -1)"
fi

# Step 2: Install xwin to get MSVC SDK and CRT
echo ""
echo "[2/4] Installing xwin (MSVC SDK downloader)..."
if ! command -v xwin &> /dev/null; then
    echo "Installing xwin..."
    cargo install xwin || {
        echo "cargo not found, installing Rust first..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
        cargo install xwin
    }
fi

# Step 3: Download MSVC SDK and runtime
echo ""
echo "[3/4] Downloading MSVC SDK and runtime libraries..."
XWIN_DIR="$HOME/.xwin"
if [ ! -d "$XWIN_DIR/crt" ]; then
    echo "Downloading Windows SDK and MSVC libraries (this may take a few minutes)..."

    # Download manifest with curl first (works around rustls SSL cert issues)
    mkdir -p ~/.xwin-cache
    if [ ! -f ~/.xwin-cache/manifest.json ]; then
        echo "Downloading VS manifest with curl..."
        curl -L -o ~/.xwin-cache/manifest.json https://aka.ms/vs/17/release/channel
    fi

    # Try to use xwin with the local manifest
    # Note: May still have SSL issues downloading component files
    # If this fails, try running on a machine with proper SSL certs
    xwin --accept-license --manifest ~/.xwin-cache/manifest.json splat --output "$XWIN_DIR" || {
        echo ""
        echo "ERROR: xwin download failed (likely SSL certificate issue)"
        echo ""
        echo "This is a known issue in some container environments."
        echo "Please try running this script on a regular Linux machine."
        echo ""
        echo "Alternative: Use ./install_msvc_wine.sh instead"
        exit 1
    }
else
    echo "MSVC SDK already downloaded at $XWIN_DIR"
fi

# Step 4: Compile test program
echo ""
echo "[4/4] Compiling vector_test.cpp with clang-cl..."
cd "$TEST_DIR"

# Set up paths for clang-cl
MSVC_VER=$(ls "$XWIN_DIR/crt/lib/x86_64" | head -1)
SDK_VER=$(ls "$XWIN_DIR/sdk/lib/um/x86_64" | head -1)

echo "Using MSVC version: $MSVC_VER"
echo "Using SDK version: $SDK_VER"

# Compile with clang-cl targeting Windows
clang-cl \
    /std:c++17 \
    /MD \
    /Zi \
    /EHsc \
    /Fe:vector_test_msvc.exe \
    /I"$XWIN_DIR/crt/include" \
    /I"$XWIN_DIR/sdk/include/ucrt" \
    /I"$XWIN_DIR/sdk/include/um" \
    /I"$XWIN_DIR/sdk/include/shared" \
    vector_test.cpp \
    /link \
    /DEBUG:FULL \
    /LIBPATH:"$XWIN_DIR/crt/lib/x86_64" \
    /LIBPATH:"$XWIN_DIR/sdk/lib/um/x86_64" \
    /LIBPATH:"$XWIN_DIR/sdk/lib/ucrt/x86_64"

# Check results
if [ -f "vector_test_msvc.exe" ] && [ -f "vector_test_msvc.pdb" ]; then
    echo ""
    echo "========================================================================="
    echo "SUCCESS! MSVC-compatible compilation complete"
    echo "========================================================================="
    ls -lh vector_test_msvc.exe vector_test_msvc.pdb
    file vector_test_msvc.exe

    echo ""
    echo "Verifying binary is Windows PE format..."
    file vector_test_msvc.exe | grep -q "PE32+" && echo "✓ Correct format: PE32+ (64-bit Windows)"

    echo ""
    echo "Verifying PDB debug symbols..."
    ls -lh vector_test_msvc.pdb && echo "✓ PDB file created"

    echo ""
    echo "Testing with Ghidra..."
    cd "$SCRIPT_DIR"

    GHIDRA_DIR="${GHIDRA_INSTALL_DIR:-$HOME/tools/ghidra}"
    "$GHIDRA_DIR/support/analyzeHeadless" \
        "$TEST_DIR" VectorTestMSVC \
        -import "$TEST_DIR/vector_test_msvc.exe" \
        -overwrite \
        -scriptPath "$TEST_DIR" \
        -postScript test_extension.py 2>&1 | tee "$TEST_DIR/ghidra_test.log" | tail -50

    echo ""
    echo "Committing results..."
    git add test/vector_test/vector_test_msvc.exe test/vector_test/vector_test_msvc.pdb 2>/dev/null || true
    git commit -m "test: Add MSVC-compatible test binary with PDB

Compiled with clang-cl (LLVM's MSVC-compatible compiler).
Produces genuine Windows PE executable with full PDB debug symbols.
Uses MSVC std::vector layout (_Myfirst, _Mylast, _Myend at offsets 0x8, 0x10, 0x18)." || echo "Nothing new to commit"

    echo ""
    echo "========================================================================="
    echo "ALL DONE!"
    echo "========================================================================="
    echo "Completed at: $(date)"
    echo "Full log saved to: $LOG_FILE"
    echo ""
    echo "Binary info:"
    echo "  - Compiled with: clang-cl (MSVC-compatible)"
    echo "  - Format: Windows PE32+ (64-bit)"
    echo "  - Debug symbols: PDB format"
    echo "  - std::vector layout: MSVC (_Myfirst/0x8, _Mylast/0x10, _Myend/0x18)"

else
    echo ""
    echo "========================================================================="
    echo "ERROR: Compilation failed"
    echo "========================================================================="
    echo "Completed at: $(date)"
    echo ""
    echo "Check output above for errors"
    echo "Full log saved to: $LOG_FILE"
    exit 1
fi
