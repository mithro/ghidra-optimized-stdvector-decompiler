#!/bin/bash

# Diagnostic script to check what the Wine MSVC installer actually installed

WINE_PREFIX="$HOME/.wine_msvc"

echo "========================================================================="
echo "Wine MSVC Installation Diagnostic"
echo "========================================================================="
echo ""

echo "1. Checking Wine prefix..."
if [ -d "$WINE_PREFIX" ]; then
    echo "✓ Wine prefix exists at: $WINE_PREFIX"
    echo "  Size: $(du -sh "$WINE_PREFIX" | cut -f1)"
else
    echo "✗ Wine prefix not found at: $WINE_PREFIX"
    exit 1
fi

echo ""
echo "2. Checking BuildTools directory..."
if [ -d "$WINE_PREFIX/drive_c/BuildTools" ]; then
    echo "✓ BuildTools directory exists"
    echo "  Contents:"
    ls -la "$WINE_PREFIX/drive_c/BuildTools/"
    echo ""
    echo "  Subdirectories:"
    find "$WINE_PREFIX/drive_c/BuildTools" -maxdepth 2 -type d 2>/dev/null | head -20
else
    echo "✗ BuildTools directory not found"
fi

echo ""
echo "3. Searching for any MSVC-related files..."
echo "  Searching for cl.exe anywhere in Wine prefix..."
CL_PATHS=$(find "$WINE_PREFIX" -name "cl.exe" 2>/dev/null)
if [ -n "$CL_PATHS" ]; then
    echo "✓ Found cl.exe at:"
    echo "$CL_PATHS"
else
    echo "✗ No cl.exe found"
fi

echo ""
echo "  Searching for any .exe files in BuildTools..."
find "$WINE_PREFIX/drive_c/BuildTools" -name "*.exe" 2>/dev/null | head -20

echo ""
echo "4. Checking VC Tools directory structure..."
if [ -d "$WINE_PREFIX/drive_c/BuildTools/VC" ]; then
    echo "✓ VC directory exists"
    ls -la "$WINE_PREFIX/drive_c/BuildTools/VC/"
else
    echo "✗ VC directory not found"
fi

echo ""
echo "5. Checking install logs..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/tools/msvc_buildtools/install.log" ]; then
    echo "✓ Install log found"
    echo "  Last 50 lines:"
    tail -50 "$SCRIPT_DIR/tools/msvc_buildtools/install.log"
else
    echo "✗ Install log not found"
fi

echo ""
echo "6. Checking what was actually installed in Wine prefix..."
echo "  Largest directories in drive_c:"
du -sh "$WINE_PREFIX/drive_c"/* 2>/dev/null | sort -rh | head -10

echo ""
echo "========================================================================="
echo "Diagnostic complete"
echo "========================================================================="
