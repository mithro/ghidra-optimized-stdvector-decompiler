#!/bin/bash
set -e

# Script to install MSVC++ Build Tools in Wine and compile test binary
# This creates a proper MSVC-compiled binary with PDB for testing the Ghidra extension

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$SCRIPT_DIR/test/vector_test"
WINE_PREFIX="$HOME/.wine_msvc"

echo "========================================================================="
echo "MSVC++ Build Tools Installation and Test Compilation"
echo "========================================================================="
echo ""

# Step 1: Install Wine if not present
echo "[1/6] Checking Wine installation..."
if ! command -v wine &> /dev/null; then
    echo "Wine not found. Installing..."
    sudo dpkg --add-architecture i386
    sudo mkdir -pm755 /etc/apt/keyrings
    sudo wget -O /etc/apt/keyrings/winehq-archive.key https://dl.winehq.org/wine-builds/winehq.key
    sudo wget -NP /etc/apt/sources.list.d/ https://dl.winehq.org/wine-builds/ubuntu/dists/noble/winehq-noble.sources
    sudo apt update
    sudo apt install -y --install-recommends winehq-stable
else
    echo "Wine already installed: $(wine --version)"
fi

# Step 2: Set up Wine prefix
echo ""
echo "[2/6] Setting up Wine prefix..."
export WINEPREFIX="$WINE_PREFIX"
export WINEARCH=win64
export WINEDEBUG=-all  # Suppress Wine debug output

if [ ! -d "$WINE_PREFIX" ]; then
    echo "Creating Wine prefix at $WINE_PREFIX..."
    wineboot -u
    echo "Waiting for Wine to initialize..."
    sleep 5
fi

# Step 3: Download Visual Studio Build Tools installer
echo ""
echo "[3/6] Downloading Visual Studio Build Tools..."
BUILDTOOLS_DIR="$SCRIPT_DIR/tools/msvc_buildtools"
mkdir -p "$BUILDTOOLS_DIR"

if [ ! -f "$BUILDTOOLS_DIR/vs_BuildTools.exe" ]; then
    echo "Downloading vs_BuildTools.exe..."
    wget -O "$BUILDTOOLS_DIR/vs_BuildTools.exe" \
        "https://aka.ms/vs/17/release/vs_BuildTools.exe"
else
    echo "Build Tools installer already downloaded"
fi

# Step 4: Install MSVC Build Tools
echo ""
echo "[4/6] Installing MSVC Build Tools (this may take 10-15 minutes)..."
MSVC_INSTALL="$WINE_PREFIX/drive_c/BuildTools"

if [ ! -d "$MSVC_INSTALL" ]; then
    echo "Running Visual Studio Build Tools installer..."
    echo "Installing: C++ build tools, Windows SDK, CMake, MSBuild"

    wine "$BUILDTOOLS_DIR/vs_BuildTools.exe" \
        --quiet --wait --norestart --nocache \
        --installPath "C:\\BuildTools" \
        --add Microsoft.VisualStudio.Workload.VCTools \
        --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 \
        --add Microsoft.VisualStudio.Component.Windows11SDK.22000 \
        --includeRecommended || {
        echo "WARNING: Installer may have failed. Checking installation..."
    }

    echo "Waiting for installation to complete..."
    sleep 10
else
    echo "MSVC Build Tools already installed at $MSVC_INSTALL"
fi

# Step 5: Find cl.exe and set up environment
echo ""
echo "[5/6] Locating MSVC compiler..."

# Find cl.exe in the Wine prefix
CL_EXE=$(find "$WINE_PREFIX/drive_c/BuildTools" -name "cl.exe" -path "*/x64/*" 2>/dev/null | head -1)

if [ -z "$CL_EXE" ]; then
    echo "ERROR: Could not find cl.exe in Wine prefix"
    echo "Trying alternative installation method..."

    # Alternative: Use chocolatey to install VC++ build tools
    echo "Installing Chocolatey in Wine..."
    wine powershell -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"

    echo "Installing visualstudio2022buildtools via Chocolatey..."
    wine choco install -y visualstudio2022buildtools --package-parameters "--add Microsoft.VisualStudio.Workload.VCTools"

    # Try finding cl.exe again
    CL_EXE=$(find "$WINE_PREFIX/drive_c" -name "cl.exe" -path "*/x64/*" 2>/dev/null | head -1)

    if [ -z "$CL_EXE" ]; then
        echo "ERROR: Still cannot find cl.exe after alternative installation"
        echo "You may need to install Visual Studio Build Tools manually in Wine"
        exit 1
    fi
fi

echo "Found MSVC compiler: $CL_EXE"

# Get the directory containing cl.exe
CL_DIR=$(dirname "$CL_EXE")
CL_WIN_PATH=$(echo "$CL_DIR" | sed "s|$WINE_PREFIX/drive_c|C:|" | sed 's|/|\\|g')

# Find Windows SDK
SDK_DIR=$(find "$WINE_PREFIX/drive_c" -type d -name "Windows Kits" 2>/dev/null | head -1)
if [ -n "$SDK_DIR" ]; then
    SDK_INCLUDE=$(find "$SDK_DIR" -type d -name "Include" | head -1)
    SDK_LIB=$(find "$SDK_DIR" -type d -name "Lib" | head -1)
fi

# Step 6: Compile the test program
echo ""
echo "[6/6] Compiling test program with MSVC..."
cd "$TEST_DIR"

# Create a batch file to set up environment and compile
cat > compile.bat << 'EOF'
@echo off
echo Setting up MSVC environment...

REM Set up paths (these will be filled in by the script)
set PATH=%CL_PATH%;%PATH%
set INCLUDE=%INCLUDE_PATH%
set LIB=%LIB_PATH%

echo Compiling vector_test.cpp...
cl.exe /Zi /EHsc /std:c++17 /Fe:vector_test_msvc.exe vector_test.cpp /link /DEBUG:FULL

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo Build successful!
    echo ========================================
    echo Binary: vector_test_msvc.exe
    echo PDB: vector_test_msvc.pdb
) else (
    echo.
    echo ========================================
    echo Build FAILED!
    echo ========================================
    exit /b %ERRORLEVEL%
)
EOF

# Update the batch file with actual paths
sed -i "s|%CL_PATH%|$CL_WIN_PATH|g" compile.bat
if [ -n "$SDK_INCLUDE" ]; then
    SDK_INCLUDE_WIN=$(echo "$SDK_INCLUDE" | sed "s|$WINE_PREFIX/drive_c|C:|" | sed 's|/|\\|g')
    sed -i "s|%INCLUDE_PATH%|$SDK_INCLUDE_WIN|g" compile.bat
fi
if [ -n "$SDK_LIB" ]; then
    SDK_LIB_WIN=$(echo "$SDK_LIB" | sed "s|$WINE_PREFIX/drive_c|C:|" | sed 's|/|\\|g')
    sed -i "s|%LIB_PATH%|$SDK_LIB_WIN|g" compile.bat
fi

# Run the compilation
echo "Executing: wine cmd /c compile.bat"
wine cmd /c compile.bat

# Check if compilation succeeded
if [ -f "vector_test_msvc.exe" ] && [ -f "vector_test_msvc.pdb" ]; then
    echo ""
    echo "========================================================================="
    echo "SUCCESS! MSVC compilation complete"
    echo "========================================================================="
    ls -lh vector_test_msvc.exe vector_test_msvc.pdb

    echo ""
    echo "File information:"
    file vector_test_msvc.exe

    echo ""
    echo "[7/6] Testing with Ghidra..."
    cd "$SCRIPT_DIR"

    # Import into Ghidra and test
    /root/tools/ghidra/support/analyzeHeadless \
        "$TEST_DIR" VectorTestMSVC \
        -import "$TEST_DIR/vector_test_msvc.exe" \
        -overwrite \
        -scriptPath "$TEST_DIR" \
        -postScript test_extension.py 2>&1 | tail -50

    echo ""
    echo "[8/6] Committing MSVC-compiled test binary..."
    cd "$SCRIPT_DIR"
    git add test/vector_test/vector_test_msvc.exe test/vector_test/vector_test_msvc.pdb
    git add test/vector_test/compile.bat
    git commit -m "test: Add MSVC-compiled test binary with PDB

Compiled with Visual Studio Build Tools in Wine:
- Full debug symbols (PDB)
- MSVC ABI and std::vector layout
- 64-bit x86-64 PE executable

This provides a proper test case for the VectorSimplification
extension with real MSVC types and offsets." || echo "Nothing to commit"

    echo ""
    echo "========================================================================="
    echo "ALL DONE!"
    echo "========================================================================="
    echo "MSVC-compiled binary: test/vector_test/vector_test_msvc.exe"
    echo "PDB debug info: test/vector_test/vector_test_msvc.pdb"
    echo ""
    echo "You can now test the Ghidra extension with a real MSVC binary!"

else
    echo ""
    echo "========================================================================="
    echo "ERROR: Compilation failed!"
    echo "========================================================================="
    echo "Check compile.bat and try running manually in Wine"
    exit 1
fi
