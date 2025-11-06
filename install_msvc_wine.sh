#!/bin/bash
set -e

# Install MSVC using msvc-wine (recommended approach)
# This downloads and unpacks MSVC components without running the installer

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$SCRIPT_DIR/test/vector_test"
MSVC_DIR="$HOME/.msvc"
LOG_FILE="$SCRIPT_DIR/msvc_wine_install.log"

# Redirect all output to log file AND console using tee
if [ -z "$LOGGING_ENABLED" ]; then
    export LOGGING_ENABLED=1
    echo "Logging to: $LOG_FILE"
    echo "Starting msvc-wine installation at $(date)" > "$LOG_FILE"
    exec > >(tee -a "$LOG_FILE") 2>&1
fi

echo "========================================================================="
echo "MSVC Installation Using msvc-wine"
echo "========================================================================="
echo "Log file: $LOG_FILE"
echo "Started at: $(date)"
echo ""
echo "This approach uses msvc-wine to download and unpack MSVC components"
echo "without running the Visual Studio installer in Wine."
echo ""

# Step 1: Install dependencies
echo "[1/5] Installing dependencies..."
echo ""

# Check for wine64
if ! command -v wine64 &> /dev/null; then
    echo "Installing Wine64..."
    sudo dpkg --add-architecture i386
    sudo mkdir -pm755 /etc/apt/keyrings
    sudo wget -O /etc/apt/keyrings/winehq-archive.key https://dl.winehq.org/wine-builds/winehq.key

    # Detect OS and use appropriate Wine repository
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [ "$ID" = "debian" ]; then
            echo "Detected Debian $VERSION_CODENAME, using Debian Wine repository..."

            # Enable contrib repository (required for winetricks on Debian)
            if ! grep -q "^deb .* ${VERSION_CODENAME} .* contrib" /etc/apt/sources.list; then
                echo "Enabling contrib repository for winetricks..."
                sudo sed -i.bak "s/^\(deb .* ${VERSION_CODENAME}.*\) main/\1 main contrib/" /etc/apt/sources.list
            fi

            sudo wget -NP /etc/apt/sources.list.d/ https://dl.winehq.org/wine-builds/debian/dists/${VERSION_CODENAME}/winehq-${VERSION_CODENAME}.sources
        elif [ "$ID" = "ubuntu" ]; then
            echo "Detected Ubuntu, using Ubuntu Wine repository..."
            sudo wget -NP /etc/apt/sources.list.d/ https://dl.winehq.org/wine-builds/ubuntu/dists/noble/winehq-noble.sources || \
                sudo wget -NP /etc/apt/sources.list.d/ https://dl.winehq.org/wine-builds/ubuntu/dists/jammy/winehq-jammy.sources
        else
            echo "ERROR: Unsupported OS: $ID"
            echo "This script only supports Debian and Ubuntu."
            echo "Please install Wine manually and try again."
            exit 1
        fi
    else
        echo "ERROR: Cannot detect OS (/etc/os-release not found)"
        exit 1
    fi

    sudo apt update
    sudo apt install -y --install-recommends winehq-stable
else
    echo "✓ Wine64 already installed: $(wine64 --version)"
fi

# Check for required packages
echo "Installing msitools, libgcab, python3..."
sudo apt-get install -y python3 msitools libgcab-1.0-0 ca-certificates winbind

# Step 2: Clone or update msvc-wine
echo ""
echo "[2/5] Setting up msvc-wine..."
MSVC_WINE_DIR="$SCRIPT_DIR/tools/msvc-wine"

if [ -d "$MSVC_WINE_DIR" ]; then
    echo "msvc-wine already cloned, updating..."
    cd "$MSVC_WINE_DIR"
    git pull
else
    echo "Cloning msvc-wine..."
    mkdir -p "$SCRIPT_DIR/tools"
    cd "$SCRIPT_DIR/tools"
    git clone https://github.com/mstorsjo/msvc-wine.git
    cd msvc-wine
fi

# Step 3: Download MSVC components
echo ""
echo "[3/5] Downloading MSVC and Windows SDK..."
echo "This will download approximately 1-2GB of data. Please be patient..."
echo ""

if [ ! -d "$MSVC_DIR/vc/tools" ]; then
    echo "Downloading to $MSVC_DIR ..."
    ./vsdownload.py --accept-license --dest "$MSVC_DIR"
    echo ""
    echo "✓ Download complete"
else
    echo "✓ MSVC already downloaded to $MSVC_DIR"
fi

# Step 4: Install msvc-wine wrappers
echo ""
echo "[4/5] Installing msvc-wine wrapper scripts..."
./install.sh "$MSVC_DIR"
echo "✓ Wrappers installed"

# Step 5: Compile test program
echo ""
echo "[5/5] Compiling vector_test.cpp with MSVC..."
cd "$TEST_DIR"

# Find the x64 compiler
MSVC_BIN="$MSVC_DIR/bin/x64"
if [ ! -d "$MSVC_BIN" ]; then
    echo "ERROR: MSVC bin directory not found at $MSVC_BIN"
    exit 1
fi

echo "Using MSVC from: $MSVC_BIN"
echo ""

# Set up environment
export PATH="$MSVC_BIN:$PATH"
export CC=cl
export CXX=cl
export WINEDEBUG=-all

# Verify cl.exe is available
if ! command -v cl &> /dev/null; then
    echo "ERROR: cl command not found in PATH"
    echo "PATH=$PATH"
    exit 1
fi

echo "Compiler version:"
cl 2>&1 | head -5

echo ""
echo "Compiling with MSVC..."

# Compile
cl /Zi /EHsc /std:c++17 /MD /Fe:vector_test_msvc.exe vector_test.cpp /link /DEBUG:FULL

# Check results
if [ -f "vector_test_msvc.exe" ] && [ -f "vector_test_msvc.pdb" ]; then
    echo ""
    echo "========================================================================="
    echo "SUCCESS! MSVC compilation complete"
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

    if [ -f "/root/tools/ghidra/support/analyzeHeadless" ]; then
        /root/tools/ghidra/support/analyzeHeadless \
            "$TEST_DIR" VectorTestMSVC \
            -import "$TEST_DIR/vector_test_msvc.exe" \
            -overwrite \
            -scriptPath "$TEST_DIR" \
            -postScript test_extension.py 2>&1 | tee "$TEST_DIR/ghidra_test.log" | tail -50
    else
        echo "Ghidra not found at /root/tools/ghidra, skipping test"
    fi

    echo ""
    echo "Committing results..."
    git add test/vector_test/vector_test_msvc.exe test/vector_test/vector_test_msvc.pdb 2>/dev/null || true
    git add tools/msvc-wine 2>/dev/null || true
    git commit -m "test: Add MSVC-compiled test binary with PDB

Compiled with genuine MSVC via msvc-wine.
Full debug symbols and native MSVC std::vector layout.

MSVC installed to: $MSVC_DIR
Uses msvc-wine from: https://github.com/mstorsjo/msvc-wine" || echo "Nothing new to commit"

    echo ""
    echo "========================================================================="
    echo "ALL DONE!"
    echo "========================================================================="
    echo "Completed at: $(date)"
    echo "Full log saved to: $LOG_FILE"
    echo ""
    echo "To compile more programs with MSVC:"
    echo "  export PATH=\"$MSVC_BIN:\$PATH\""
    echo "  export CC=cl CXX=cl"
    echo "  cl /EHsc /std:c++17 yourfile.cpp"

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
