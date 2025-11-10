#!/bin/bash
# One-time setup script for building MSVC-compatible demo binaries
# This orchestrates both root and user operations

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MSVC_DIR="${MSVC_DIR:-$HOME/.msvc}"

echo "========================================================================="
echo "Demo Build Environment Setup"
echo "========================================================================="
echo ""
echo "This script will:"
echo "  1. Install clang-20 and lld linker (requires sudo)"
echo "  2. Download MSVC 14.44 headers and Windows SDK 10.0.26100 (~2.7GB)"
echo "  3. Set up directory structure"
echo ""
echo "Requirements:"
echo "  - Ubuntu 24.04 or compatible Linux distribution"
echo "  - ~9 GB disk space"
echo "  - Internet connection"
echo ""
echo "Installation directory: $MSVC_DIR"
echo ""

# Parse command-line arguments
SKIP_ROOT=false
SKIP_USER=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-root)
            SKIP_ROOT=true
            shift
            ;;
        --skip-user)
            SKIP_USER=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --skip-root    Skip root/sudo operations (package installation)"
            echo "  --skip-user    Skip user operations (MSVC download)"
            echo "  --help         Show this help message"
            echo ""
            echo "Split scripts:"
            echo "  setup_build_env_root.sh  - Root operations only (requires sudo)"
            echo "  setup_build_env_user.sh  - User operations only (no sudo)"
            echo ""
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Run with --help for usage information"
            exit 1
            ;;
    esac
done

# Step 1: Run root operations
if [ "$SKIP_ROOT" = false ]; then
    echo "========================================================================="
    echo "STEP 1: Root Operations (requires sudo)"
    echo "========================================================================="
    echo ""
    bash "$SCRIPT_DIR/setup_build_env_root.sh"
    echo ""
else
    echo "Skipping root operations (--skip-root specified)"
    echo ""
fi

# Step 2: Run user operations
if [ "$SKIP_USER" = false ]; then
    echo "========================================================================="
    echo "STEP 2: User Operations (no sudo required)"
    echo "========================================================================="
    echo ""
    bash "$SCRIPT_DIR/setup_build_env_user.sh"
    echo ""
else
    echo "Skipping user operations (--skip-user specified)"
    echo ""
fi

# Final summary
if [ "$SKIP_ROOT" = false ] && [ "$SKIP_USER" = false ]; then
    echo "========================================================================="
    echo "Complete Setup Finished!"
    echo "========================================================================="
    echo ""
    echo "Both root and user operations completed successfully."
    echo ""
    echo "To run steps separately in the future:"
    echo "  Root operations: ./setup_build_env_root.sh"
    echo "  User operations: ./setup_build_env_user.sh"
    echo ""
fi
