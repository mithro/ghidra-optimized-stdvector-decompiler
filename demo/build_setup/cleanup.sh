#!/bin/bash
# Cleanup script for MSVC build environment installations
# Removes files and directories created by setup_build_env.sh, setup_clangcl.sh, and setup_msvc_wine.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "========================================================================="
echo "MSVC Build Environment Cleanup"
echo "========================================================================="
echo ""
echo "This script will remove build environment files installed by:"
echo "  - setup_build_env.sh"
echo "  - setup_clangcl.sh"
echo "  - setup_msvc_wine.sh"
echo ""

# Function to get directory size
get_size() {
    if [ -d "$1" ]; then
        du -sh "$1" 2>/dev/null | cut -f1
    else
        echo "0"
    fi
}

# Function to confirm deletion
confirm_delete() {
    local path="$1"
    local size="$2"

    if [ -e "$path" ]; then
        echo "  ✓ Found: $path ($size)"
        return 0
    else
        echo "  ✗ Not found: $path"
        return 1
    fi
}

# Directories to clean
MSVC_DIR="${MSVC_DIR:-$HOME/.msvc}"
WINE_PREFIX="$HOME/.wine_msvc"
TOOLS_DIR="$SCRIPT_DIR/tools"
WINETRICKS_CACHE="$HOME/.cache/winetricks"
BUILD_ARTIFACTS="$SCRIPT_DIR/../"

echo "Checking what will be deleted..."
echo ""

# Track what exists
TOTAL_SIZE=0
ITEMS_TO_DELETE=()

echo "[1] MSVC Headers and SDK"
if confirm_delete "$MSVC_DIR" "$(get_size "$MSVC_DIR")"; then
    ITEMS_TO_DELETE+=("$MSVC_DIR")
fi
echo ""

echo "[2] Wine MSVC Prefix"
if confirm_delete "$WINE_PREFIX" "$(get_size "$WINE_PREFIX")"; then
    ITEMS_TO_DELETE+=("$WINE_PREFIX")
fi
echo ""

echo "[3] Build Tools (msvc-wine, VS installer)"
if confirm_delete "$TOOLS_DIR" "$(get_size "$TOOLS_DIR")"; then
    ITEMS_TO_DELETE+=("$TOOLS_DIR")
fi
echo ""

echo "[4] Winetricks Cache"
if confirm_delete "$WINETRICKS_CACHE" "$(get_size "$WINETRICKS_CACHE")"; then
    echo "  Note: This is shared with other Wine applications"
    # Don't auto-add to deletion list - ask separately
fi
echo ""

echo "[5] Build Logs"
if [ -f "$SCRIPT_DIR/msvc_install.log" ]; then
    confirm_delete "$SCRIPT_DIR/msvc_install.log" "$(du -sh "$SCRIPT_DIR/msvc_install.log" 2>/dev/null | cut -f1)"
    ITEMS_TO_DELETE+=("$SCRIPT_DIR/msvc_install.log")
fi
if [ -f "$SCRIPT_DIR/build_msvc.log" ]; then
    confirm_delete "$SCRIPT_DIR/build_msvc.log" "$(du -sh "$SCRIPT_DIR/build_msvc.log" 2>/dev/null | cut -f1)"
    ITEMS_TO_DELETE+=("$SCRIPT_DIR/build_msvc.log")
fi
echo ""

# Calculate total size
echo "Calculating total size..."
TOTAL=0
for item in "${ITEMS_TO_DELETE[@]}"; do
    if [ -e "$item" ]; then
        SIZE_KB=$(du -sk "$item" 2>/dev/null | cut -f1)
        TOTAL=$((TOTAL + SIZE_KB))
    fi
done
TOTAL_MB=$((TOTAL / 1024))
# Calculate GB with fallback if bc not available
if command -v bc &> /dev/null; then
    TOTAL_GB=$(echo "scale=2; $TOTAL / 1024 / 1024" | bc)
else
    TOTAL_GB=$((TOTAL / 1024 / 1024))
fi

echo ""
echo "========================================================================="
echo "Summary"
echo "========================================================================="
echo "Items to delete: ${#ITEMS_TO_DELETE[@]}"
echo "Total disk space to free: ${TOTAL_MB} MB (~${TOTAL_GB} GB)"
echo ""

if [ ${#ITEMS_TO_DELETE[@]} -eq 0 ]; then
    echo "Nothing to clean up - no build environment files found."
    exit 0
fi

# Ask for confirmation
echo "Items that will be deleted:"
for item in "${ITEMS_TO_DELETE[@]}"; do
    echo "  - $item"
done
echo ""

# Check if winetricks cache should be deleted
DELETE_WINETRICKS_CACHE=false
if [ -d "$WINETRICKS_CACHE" ]; then
    CACHE_SIZE=$(get_size "$WINETRICKS_CACHE")
    echo "Additional optional cleanup:"
    echo "  - $WINETRICKS_CACHE ($CACHE_SIZE)"
    echo ""
    read -p "Delete winetricks cache? (shared with other Wine apps) [y/N]: " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        DELETE_WINETRICKS_CACHE=true
        ITEMS_TO_DELETE+=("$WINETRICKS_CACHE")
    fi
    echo ""
fi

read -p "Proceed with deletion? [y/N]: " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cleanup cancelled."
    exit 0
fi

# Perform deletion
echo ""
echo "Deleting files..."
DELETED_COUNT=0

for item in "${ITEMS_TO_DELETE[@]}"; do
    if [ -e "$item" ]; then
        echo "  Removing: $item"
        rm -rf "$item"
        DELETED_COUNT=$((DELETED_COUNT + 1))
    fi
done

echo ""
echo "========================================================================="
echo "Cleanup Complete!"
echo "========================================================================="
echo "Deleted $DELETED_COUNT item(s)"
echo "Freed approximately ${TOTAL_MB} MB (~${TOTAL_GB} GB) of disk space"
echo ""
echo "To reinstall the build environment, run:"
echo "  cd demo"
echo "  ./setup_build_env.sh"
echo ""
echo "Or for Wine MSVC:"
echo "  cd demo/build_setup"
echo "  ./setup_msvc_wine.sh"
echo ""
