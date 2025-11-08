#!/bin/bash
# Test script to verify enhanced setup components

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Testing enhanced setup script components..."
echo ""

# Test 1: Verify all scripts exist
echo "Test 1: Checking file structure..."
for file in scripts/common.sh scripts/install_java.sh scripts/install_ghidra.sh setup.sh; do
    if [ -f "$file" ]; then
        echo "  ✓ $file exists"
    else
        echo "  ✗ $file missing"
        exit 1
    fi
done

# Test 2: Verify syntax of all scripts
echo ""
echo "Test 2: Verifying script syntax..."
for file in scripts/common.sh scripts/install_java.sh scripts/install_ghidra.sh setup.sh; do
    if bash -n "$file" 2>&1; then
        echo "  ✓ $file syntax OK"
    else
        echo "  ✗ $file has syntax errors"
        exit 1
    fi
done

# Test 3: Verify scripts can be sourced
echo ""
echo "Test 3: Verifying scripts can be sourced..."
if source scripts/common.sh && type print_status &>/dev/null; then
    echo "  ✓ common.sh sourced successfully"
else
    echo "  ✗ common.sh failed to source"
    exit 1
fi

if source scripts/install_java.sh && type check_java_version &>/dev/null; then
    echo "  ✓ install_java.sh sourced successfully"
else
    echo "  ✗ install_java.sh failed to source"
    exit 1
fi

if source scripts/install_ghidra.sh && type check_ghidra_installed &>/dev/null; then
    echo "  ✓ install_ghidra.sh sourced successfully"
else
    echo "  ✗ install_ghidra.sh failed to source"
    exit 1
fi

# Test 4: Verify Java detection works
echo ""
echo "Test 4: Verifying Java detection..."
if check_java_version; then
    echo "  ✓ Java detection works"
else
    echo "  ⚠ Java not detected (expected if Java < 21 or not installed)"
fi

# Test 5: Verify Ghidra detection works
echo ""
echo "Test 5: Verifying Ghidra detection..."
if check_ghidra_installed; then
    echo "  ✓ Ghidra detection works"
else
    echo "  ⚠ Ghidra not detected (expected if not installed)"
fi

echo ""
echo "All tests passed! ✓"
