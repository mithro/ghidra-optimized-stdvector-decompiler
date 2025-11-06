#!/bin/bash
set -e

# Fixed script to install MSVC++ Build Tools in Wine with proper .NET dependencies

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$SCRIPT_DIR/test/vector_test"
WINE_PREFIX="$HOME/.wine_msvc"
LOG_FILE="$SCRIPT_DIR/msvc_install.log"

# Redirect all output to log file AND console using tee
# Only do this if we're not already logging (prevent recursive execution)
if [ -z "$LOGGING_ENABLED" ]; then
    export LOGGING_ENABLED=1
    echo "Logging to: $LOG_FILE"
    echo "Starting MSVC installation at $(date)" > "$LOG_FILE"
    exec > >(tee -a "$LOG_FILE") 2>&1
fi

echo "========================================================================="
echo "MSVC++ Build Tools Installation (Fixed Version)"
echo "========================================================================="
echo "Log file: $LOG_FILE"
echo "Started at: $(date)"
echo ""

# Step 1: Install Wine and winetricks
echo "[1/7] Installing Wine and winetricks..."
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

            # Enable contrib repository (required for winetricks)
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
    echo "Wine already installed: $(wine --version)"
    if ! command -v winetricks &> /dev/null; then
        sudo apt install -y winetricks
    fi
fi

# Step 2: Set up Wine prefix
echo ""
echo "[2/7] Setting up Wine prefix..."
export WINEPREFIX="$WINE_PREFIX"
export WINEARCH=win64
export WINEDEBUG=-all

if [ ! -d "$WINE_PREFIX" ]; then
    echo "Creating Wine prefix at $WINE_PREFIX..."
    wineboot -u
    sleep 5
fi

# Step 3: Install .NET Framework 4.8
echo ""
echo "[3/7] Installing .NET Framework 4.8 (required for VS installer)..."
echo "This may take 5-10 minutes..."

if [ ! -f "$WINE_PREFIX/drive_c/windows/Microsoft.NET/Framework64/v4.0.30319/mscorlib.dll" ]; then
    echo "Installing dotnet48 via winetricks..."
    # Use --force to bypass SHA256 checks (Microsoft updates packages frequently)
    winetricks -q --force dotnet48
    echo "Waiting for .NET installation to settle..."
    sleep 10
else
    echo ".NET Framework already installed"
fi

# Step 4: Install Visual C++ redistributables
echo ""
echo "[4/7] Installing Visual C++ redistributables..."
# Use --force to bypass SHA256 checks (Microsoft updates packages frequently)
winetricks -q --force vcrun2019

# Step 5: Download Build Tools
echo ""
echo "[5/7] Downloading Visual Studio Build Tools..."
BUILDTOOLS_DIR="$SCRIPT_DIR/tools/msvc_buildtools"
mkdir -p "$BUILDTOOLS_DIR"

if [ ! -f "$BUILDTOOLS_DIR/vs_BuildTools.exe" ]; then
    echo "Downloading vs_BuildTools.exe..."
    wget -O "$BUILDTOOLS_DIR/vs_BuildTools.exe" \
        "https://aka.ms/vs/17/release/vs_BuildTools.exe"
fi

# Step 6: Install MSVC Build Tools
echo ""
echo "[6/7] Installing MSVC Build Tools..."
echo "This will take 10-15 minutes. Please be patient..."

MSVC_INSTALL="$WINE_PREFIX/drive_c/BuildTools"

if [ ! -d "$MSVC_INSTALL/VC/Tools/MSVC" ]; then
    echo "Running Visual Studio Build Tools installer with .NET support..."

    # Run installer with all necessary components
    wine "$BUILDTOOLS_DIR/vs_BuildTools.exe" \
        --quiet --wait --norestart --nocache \
        --installPath "C:\\BuildTools" \
        --add Microsoft.VisualStudio.Workload.VCTools \
        --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 \
        --add Microsoft.VisualStudio.Component.Windows11SDK.22000 \
        --includeRecommended 2>&1 | tee "$BUILDTOOLS_DIR/install.log"

    INSTALL_EXIT=$?
    echo ""
    echo "Installer exit code: $INSTALL_EXIT"

    # Wait for background processes
    echo "Waiting for installation to complete..."
    sleep 30

    # Kill any hanging installer processes (don't fail if wineserver returns error)
    echo "Stopping wine server..."
    wineserver -k || true
    sleep 5
else
    echo "MSVC Build Tools already installed"
fi

# Step 7: Verify installation and compile
echo ""
echo "========================================================================="
echo "[7/7] Verifying MSVC installation and compiling test..."
echo "========================================================================="

# Find cl.exe
echo "Searching for cl.exe in $WINE_PREFIX/drive_c/BuildTools ..."
CL_EXE=$(find "$WINE_PREFIX/drive_c/BuildTools" -name "cl.exe" -path "*/x64/*" 2>/dev/null | head -1)

if [ -z "$CL_EXE" ]; then
    echo "ERROR: cl.exe not found after installation"
    echo ""
    echo "Troubleshooting suggestions:"
    echo "1. Check install log: $BUILDTOOLS_DIR/install.log"
    echo "2. The installer may need more time. Try running:"
    echo "   find $WINE_PREFIX -name 'cl.exe' 2>/dev/null"
    echo "3. You may need to manually install Visual Studio in Wine"
    echo ""

    # Try to find ANY cl.exe as fallback
    echo "Searching entire Wine prefix for any cl.exe..."
    CL_EXE=$(find "$WINE_PREFIX" -name "cl.exe" 2>/dev/null | grep -i "x64" | head -1)

    if [ -z "$CL_EXE" ]; then
        echo "Still cannot find cl.exe. Installation failed."
        echo ""
        echo "Alternative: Use Windows or cross-compiler"
        exit 1
    fi
fi

echo "Found MSVC compiler: $CL_EXE"
CL_DIR=$(dirname "$CL_EXE")
echo "Compiler directory: $CL_DIR"

# Find SDK paths
echo "Searching for Windows SDK..."
SDK_DIR=$(find "$WINE_PREFIX/drive_c" -type d -path "*/Windows Kits/10" 2>/dev/null | head -1) || true
if [ -n "$SDK_DIR" ]; then
    SDK_VERSION=$(ls -1 "$SDK_DIR/Include" 2>/dev/null | grep "^10" | sort -V | tail -1) || true
    if [ -n "$SDK_VERSION" ]; then
        SDK_INCLUDE="$SDK_DIR/Include/$SDK_VERSION"
        SDK_LIB="$SDK_DIR/Lib/$SDK_VERSION"
        echo "Found Windows SDK: $SDK_VERSION"
    fi
fi

# Compile the test
echo ""
echo "Compiling vector_test.cpp with MSVC..."
cd "$TEST_DIR"

# Create batch file with proper paths
CL_WIN_PATH=$(echo "$CL_DIR" | sed "s|$WINE_PREFIX/drive_c|C:|" | sed 's|/|\\|g')
CL_PARENT=$(dirname "$CL_DIR")
CL_PARENT_WIN=$(echo "$CL_PARENT" | sed "s|$WINE_PREFIX/drive_c|C:|" | sed 's|/|\\|g')

cat > compile.bat << EOF
@echo off
echo Compiling with MSVC...
set PATH=$CL_WIN_PATH;%PATH%
EOF

if [ -n "$SDK_INCLUDE" ]; then
    SDK_INCLUDE_WIN=$(echo "$SDK_INCLUDE" | sed "s|$WINE_PREFIX/drive_c|C:|" | sed 's|/|\\|g')
    SDK_LIB_WIN=$(echo "$SDK_LIB" | sed "s|$WINE_PREFIX/drive_c|C:|" | sed 's|/|\\|g')
    cat >> compile.bat << EOF
set INCLUDE=$CL_PARENT_WIN\\include;$SDK_INCLUDE_WIN\\ucrt;$SDK_INCLUDE_WIN\\um;$SDK_INCLUDE_WIN\\shared
set LIB=$CL_PARENT_WIN\\lib\\x64;$SDK_LIB_WIN\\ucrt\\x64;$SDK_LIB_WIN\\um\\x64
EOF
fi

cat >> compile.bat << 'EOF'

cl.exe /Zi /EHsc /std:c++17 /MD /Fe:vector_test_msvc.exe vector_test.cpp /link /DEBUG:FULL

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo Build SUCCESS!
    echo ========================================
) else (
    echo.
    echo ========================================
    echo Build FAILED with error %ERRORLEVEL%
    echo ========================================
    exit /b %ERRORLEVEL%
)
EOF

echo "Running compilation..."
wine cmd /c compile.bat 2>&1 | tee compile.log

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
    "$GHIDRA_DIR/support/analyzeHeadless" \
        "$TEST_DIR" VectorTestMSVC \
        -import "$TEST_DIR/vector_test_msvc.exe" \
        -overwrite \
        -scriptPath "$TEST_DIR" \
        -postScript test_extension.py 2>&1 | tee "$TEST_DIR/ghidra_test.log" | tail -50

    echo ""
    echo "Committing results..."
    git add test/vector_test/vector_test_msvc.exe test/vector_test/vector_test_msvc.pdb 2>/dev/null || true
    git add test/vector_test/compile.bat tools/msvc_buildtools 2>/dev/null || true
    git commit -m "test: Add MSVC-compiled test binary with PDB

Compiled with Visual Studio Build Tools via Wine.
Full debug symbols and MSVC std::vector layout." || echo "Nothing new to commit"

    echo ""
    echo "========================================================================="
    echo "ALL DONE!"
    echo "========================================================================="
    echo "Completed at: $(date)"
    echo "Full log saved to: $LOG_FILE"
    echo ""
    echo "You can share the log with: cat $LOG_FILE"

else
    echo ""
    echo "========================================================================="
    echo "ERROR: Compilation failed"
    echo "========================================================================="
    echo "Completed at: $(date)"
    echo "Check compile.log for details"
    echo "Full log saved to: $LOG_FILE"
    echo ""
    echo "You can share the log with: cat $LOG_FILE"
    cat compile.log
    exit 1
fi
