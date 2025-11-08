#!/bin/bash
set -e

# Install MSVC using winetricks vstools2019 (alternative approach)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$SCRIPT_DIR"
WINE_PREFIX="$HOME/.wine_vstools"
LOG_FILE="$SCRIPT_DIR/winetricks_vstools.log"

# Redirect all output to log file AND console using tee
if [ -z "$LOGGING_ENABLED" ]; then
    export LOGGING_ENABLED=1
    echo "Logging to: $LOG_FILE"
    echo "Starting winetricks vstools2019 installation at $(date)" > "$LOG_FILE"
    exec > >(tee -a "$LOG_FILE") 2>&1
fi

echo "========================================================================="
echo "MSVC Installation Using Winetricks vstools2019"
echo "========================================================================="
echo "Log file: $LOG_FILE"
echo "Started at: $(date)"
echo ""

# Step 1: Install Wine and winetricks
echo "[1/3] Installing Wine and winetricks..."
if ! command -v wine &> /dev/null; then
    echo "Installing Wine..."
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
    sudo apt install -y --install-recommends winehq-stable winetricks
else
    echo "✓ Wine already installed: $(wine --version)"
    if ! command -v winetricks &> /dev/null; then
        sudo apt install -y winetricks
    fi
fi

# Step 2: Set up Wine prefix and install vstools2019
echo ""
echo "[2/3] Installing Visual Studio Build Tools 2019 via winetricks..."
export WINEPREFIX="$WINE_PREFIX"
export WINEARCH=win64
export WINEDEBUG=-all

echo "Wine prefix: $WINE_PREFIX"
echo ""
echo "This will download and install VS Build Tools 2019."
echo "Running in unattended mode (no GUI)..."
echo "This may take 15-30 minutes..."
echo ""

# Install vstools2019 in unattended mode with --force to bypass SHA256 checks
# Microsoft frequently updates installers, causing hash mismatches
winetricks --unattended --force vstools2019

echo ""
echo "Installation complete. Waiting for processes to settle..."
sleep 10
wineserver -k || true
sleep 5

# Step 3: Find cl.exe and compile
echo ""
echo "[3/3] Finding MSVC compiler and building test..."

# Find cl.exe
echo "Searching for cl.exe..."
CL_EXE=$(find "$WINE_PREFIX" -name "cl.exe" -path "*/x64/*" 2>/dev/null | head -1) || true

if [ -z "$CL_EXE" ]; then
    echo "Searching for any cl.exe..."
    CL_EXE=$(find "$WINE_PREFIX" -name "cl.exe" 2>/dev/null | grep -i "x64\|amd64" | head -1) || true
fi

if [ -z "$CL_EXE" ]; then
    echo ""
    echo "========================================================================="
    echo "ERROR: cl.exe not found after installation"
    echo "========================================================================="
    echo ""
    echo "Installed files in Wine prefix:"
    find "$WINE_PREFIX" -type f -name "*.exe" 2>/dev/null | grep -i "visual\|build\|vc" | head -20
    echo ""
    echo "This may mean vstools2019 didn't install correctly."
    echo "Try the msvc-wine approach instead: ./install_msvc_wine.sh"
    exit 1
fi

echo "✓ Found MSVC compiler: $CL_EXE"
CL_DIR=$(dirname "$CL_EXE")

# Compile the test
echo ""
echo "Compiling vector_test.cpp with MSVC..."
cd "$TEST_DIR"

# Create batch file for compilation
CL_WIN_PATH=$(echo "$CL_DIR" | sed "s|$WINE_PREFIX/drive_c|C:|" | sed 's|/|\\|g')

cat > compile.bat << 'EOF'
@echo off
echo Setting up MSVC environment...
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
echo Compiling...
cl.exe /Zi /EHsc /std:c++17 /MD /Fe:vector_test_msvc.exe vector_test.cpp /link /DEBUG:FULL
echo Done.
EOF

echo "Running compilation in Wine..."
WINEPREFIX="$WINE_PREFIX" wine cmd /c compile.bat 2>&1 | tee compile.log

# Check results
if [ -f "vector_test_msvc.exe" ] && [ -f "vector_test_msvc.pdb" ]; then
    echo ""
    echo "========================================================================="
    echo "SUCCESS! MSVC compilation complete"
    echo "========================================================================="
    ls -lh vector_test_msvc.exe vector_test_msvc.pdb
    file vector_test_msvc.exe

    echo ""
    echo "Testing with Ghidra..."
    cd "$SCRIPT_DIR"

    GHIDRA_DIR="${GHIDRA_INSTALL_DIR:-$HOME/tools/ghidra}"
    if [ -f "$GHIDRA_DIR/support/analyzeHeadless" ]; then
        "$GHIDRA_DIR/support/analyzeHeadless" \
            "$TEST_DIR" VectorTestMSVC \
            -import "$TEST_DIR/vector_test_msvc.exe" \
            -overwrite \
            -scriptPath "$TEST_DIR" \
            -postScript test_extension.py 2>&1 | tee "$TEST_DIR/ghidra_test.log" | tail -50
    fi

    echo ""
    echo "Committing results..."
    git add examples/vector_test/vector_test_msvc.exe examples/vector_test/vector_test_msvc.pdb 2>/dev/null || true
    git commit -m "test: Add MSVC-compiled test binary with PDB

Compiled with VS Build Tools 2019 via winetricks vstools2019.
Full debug symbols and MSVC std::vector layout." || echo "Nothing new to commit"

    echo ""
    echo "========================================================================="
    echo "ALL DONE!"
    echo "========================================================================="
    echo "Completed at: $(date)"
    echo "Full log saved to: $LOG_FILE"

else
    echo ""
    echo "========================================================================="
    echo "ERROR: Compilation failed"
    echo "========================================================================="
    echo "Check compile.log for details"
    cat compile.log || true
    exit 1
fi
