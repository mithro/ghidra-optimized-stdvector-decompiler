#!/bin/bash
set -e

# Build MSVC-compatible test binary using clang-cl-19 with msvc-wine
# This script downloads MSVC headers/libs and compiles vector_test.cpp

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$SCRIPT_DIR/test/vector_test"
LOG_FILE="$SCRIPT_DIR/build_msvc.log"

# Redirect all output to log file AND console
if [ -z "$LOGGING_ENABLED" ]; then
    export LOGGING_ENABLED=1
    echo "Logging to: $LOG_FILE"
    echo "Starting MSVC build at $(date)" > "$LOG_FILE"
    exec > >(tee -a "$LOG_FILE") 2>&1
fi

echo "========================================================================="
echo "Building MSVC-Compatible Binary with clang-cl-19"
echo "========================================================================="
echo "This script:"
echo "  1. Downloads MSVC 14.44 headers and Windows SDK 10.0.26100"
echo "  2. Installs clang-19 (required for MSVC 14.44 headers)"
echo "  3. Compiles vector_test.cpp with optimizations (/O2 /OPT:REF /OPT:ICF)"
echo "  4. Generates Windows PE32+ binary with full PDB debug symbols"
echo ""
echo "Total download size: ~2.7 GB"
echo "Required disk space: ~9 GB"
echo ""

# Step 1: Install prerequisites
echo "[1/5] Installing prerequisites..."
apt-get update -qq
apt-get install -y python3 msitools ca-certificates wget git curl 2>&1 | tail -5

# Step 2: Clone msvc-wine for vsdownload.py
echo ""
echo "[2/5] Setting up msvc-wine toolchain downloader..."
if [ ! -d "$SCRIPT_DIR/tools/msvc-wine" ]; then
    echo "Cloning msvc-wine repository..."
    mkdir -p "$SCRIPT_DIR/tools"
    git clone https://github.com/mstorsjo/msvc-wine.git "$SCRIPT_DIR/tools/msvc-wine"
else
    echo "msvc-wine already cloned"
fi

# Step 3: Download MSVC and Windows SDK
echo ""
echo "[3/5] Downloading MSVC toolchain and Windows SDK..."
MSVC_DIR="$HOME/.msvc"
if [ ! -f "$MSVC_DIR/Windows Kits/10/Include/10.0.26100.0/ucrt/malloc.h" ]; then
    echo "Downloading MSVC 14.44 and Windows SDK 10.0.26100..."
    echo "This will download ~2.7 GB and may take 10-20 minutes..."

    cd "$SCRIPT_DIR/tools/msvc-wine"
    python3 ./vsdownload.py --accept-license --dest "$MSVC_DIR"

    echo ""
    echo "Download complete. Checking installation..."
    if [ -f "$MSVC_DIR/Windows Kits/10/Include/10.0.26100.0/ucrt/malloc.h" ]; then
        echo "✓ Windows SDK headers installed"
    else
        echo "✗ ERROR: Windows SDK headers not found"
        echo "  Expected: $MSVC_DIR/Windows Kits/10/Include/10.0.26100.0/ucrt/malloc.h"
        exit 1
    fi
else
    echo "MSVC toolchain already downloaded"
fi

# Step 4: Install clang-19
echo ""
echo "[4/5] Installing clang-19..."
if ! command -v clang-cl-19 &> /dev/null; then
    echo "Installing LLVM 19 from Ubuntu repositories..."

    # Install from Ubuntu 24.04 repositories (already has clang-19)
    apt-get install -y clang-19 lld-19 2>&1 | tail -10

    # Create clang-cl-19 symlink
    if [ ! -e /usr/bin/clang-cl-19 ]; then
        ln -s /usr/lib/llvm-19/bin/clang /usr/bin/clang-cl-19
    fi

    echo "✓ clang-19 installed: $(clang-cl-19 --version | head -1)"
else
    echo "✓ clang-cl-19 already installed: $(clang-cl-19 --version | head -1)"
fi

# Step 5: Fix library case sensitivity (kernel32.lib -> kernel32.Lib)
echo ""
echo "Fixing library case-sensitivity issues..."
LIB_DIR="$MSVC_DIR/Windows Kits/10/Lib/10.0.26100.0/um/x64"
if [ -f "$LIB_DIR/kernel32.Lib" ] && [ ! -e "$LIB_DIR/kernel32.lib" ]; then
    echo "Creating lowercase symlink for kernel32.lib..."
    ln -s kernel32.Lib "$LIB_DIR/kernel32.lib"
fi

# Step 6: Compile test binary
echo ""
echo "[5/5] Compiling vector_test.cpp..."
cd "$TEST_DIR"

MSVC_INCLUDE="$MSVC_DIR/unpack/VC/Tools/MSVC/14.44.35207/include"
SDK_INCLUDE="$MSVC_DIR/Windows Kits/10/Include/10.0.26100.0"
MSVC_LIB="$MSVC_DIR/unpack/VC/Tools/MSVC/14.44.35207/lib/x64"
SDK_LIB="$MSVC_DIR/Windows Kits/10/Lib/10.0.26100.0"

echo "MSVC Headers: $MSVC_INCLUDE"
echo "SDK Headers: $SDK_INCLUDE"
echo ""
echo "Compiling..."

clang-cl-19 \
    /std:c++17 \
    /O2 \
    /EHsc \
    /Zi \
    /MD \
    -fuse-ld=lld-link \
    -I"$MSVC_INCLUDE" \
    -I"$SDK_INCLUDE/ucrt" \
    -I"$SDK_INCLUDE/um" \
    -I"$SDK_INCLUDE/shared" \
    /Fe:vector_test_msvc.exe \
    vector_test.cpp \
    /link \
    /LIBPATH:"$MSVC_LIB" \
    /LIBPATH:"$SDK_LIB/ucrt/x64" \
    /LIBPATH:"$SDK_LIB/um/x64" \
    /DEBUG:FULL \
    /OPT:REF \
    /OPT:ICF

# Verify results
echo ""
if [ -f "vector_test_msvc.exe" ] && [ -f "vector_test_msvc.pdb" ]; then
    echo "========================================================================="
    echo "SUCCESS! Binary compiled successfully"
    echo "========================================================================="
    echo ""
    ls -lh vector_test_msvc.exe vector_test_msvc.pdb
    echo ""
    file vector_test_msvc.exe

    echo ""
    echo "Binary details:"
    echo "  - Compiler: clang-cl-19 (LLVM 19.1.1)"
    echo "  - MSVC headers: 14.44.35207"
    echo "  - Windows SDK: 10.0.26100.0"
    echo "  - Format: PE32+ executable (64-bit Windows)"
    echo "  - Optimization: /O2 (Release build with /OPT:REF /OPT:ICF)"
    echo "  - Debug symbols: Full PDB format"
    echo "  - std::vector layout: MSVC (_Myfirst/0x8, _Mylast/0x10, _Myend/0x18)"
    echo ""
    echo "Files created:"
    echo "  - vector_test_msvc.exe (Windows executable)"
    echo "  - vector_test_msvc.pdb (debug symbols)"
    echo ""
    echo "Completed at: $(date)"
    echo "Full log: $LOG_FILE"
else
    echo "========================================================================="
    echo "ERROR: Compilation failed"
    echo "========================================================================="
    echo ""
    echo "Check the log above for errors."
    echo "Full log: $LOG_FILE"
    exit 1
fi
