#!/bin/bash
# Ghidra installation module for setup.sh

set -euo pipefail

# Source common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

# Configuration
INSTALL_DIR="${INSTALL_DIR:-$HOME/tools}"
GHIDRA_VERSION="${GHIDRA_VERSION:-11.4.2}"
GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-$INSTALL_DIR/ghidra}"

# Detect architecture
detect_architecture() {
    local arch=$(uname -m)
    case "$arch" in
        x86_64)
            echo "x64"
            ;;
        aarch64|arm64)
            print_warning "ARM architecture detected. Ghidra releases use different naming."
            echo "arm64"
            ;;
        *)
            print_warning "Unknown architecture: $arch. Assuming x64."
            echo "x64"
            ;;
    esac
}

# Build Ghidra download URL
get_ghidra_download_url() {
    local version="$1"
    local base_url="https://github.com/NationalSecurityAgency/ghidra/releases/download"
    local release_tag="Ghidra_${version}_build"

    # Standard filename pattern for most releases
    local filename="ghidra_${version}_PUBLIC_$(date +%Y%m%d).zip"

    # For well-known versions, use exact filenames
    case "$version" in
        11.4.2)
            filename="ghidra_11.4.2_PUBLIC_20250122.zip"
            ;;
        11.4.1)
            filename="ghidra_11.4.1_PUBLIC_20241105.zip"
            ;;
        11.4)
            filename="ghidra_11.4_PUBLIC_20241105.zip"
            ;;
    esac

    echo "${base_url}/${release_tag}/${filename}"
}

# Check if Ghidra is already installed
check_ghidra_installed() {
    if [ -f "$GHIDRA_INSTALL_DIR/ghidraRun" ]; then
        return 0
    else
        return 1
    fi
}

# Download and install Ghidra
install_ghidra() {
    local version="$1"
    local install_dir="$2"

    # Create parent directory if it doesn't exist
    mkdir -p "$(dirname "$install_dir")"

    # Check disk space (Ghidra needs ~500MB)
    check_disk_space "$(dirname "$install_dir")" 500

    # Create temporary directory for download
    local tmp_dir=$(mktemp -d)
    trap "rm -rf '$tmp_dir'" EXIT

    # Download Ghidra
    local download_url=$(get_ghidra_download_url "$version")
    local zip_file="$tmp_dir/ghidra.zip"

    print_info "Downloading Ghidra ${version}..."
    if ! download_file "$download_url" "$zip_file"; then
        fail "Failed to download Ghidra. Please download manually from:
  https://github.com/NationalSecurityAgency/ghidra/releases
Then extract to: $install_dir"
    fi

    # Extract to temporary location
    local extract_dir="$tmp_dir/extract"
    mkdir -p "$extract_dir"
    extract_archive "$zip_file" "$extract_dir"

    # Find the extracted Ghidra directory (it's usually ghidra_<version>_PUBLIC)
    local ghidra_dir=$(find "$extract_dir" -maxdepth 1 -type d -name "ghidra_*" | head -1)

    if [ -z "$ghidra_dir" ]; then
        fail "Could not find extracted Ghidra directory"
    fi

    # Create parent directory and move Ghidra to final location
    mkdir -p "$(dirname "$install_dir")"
    mv "$ghidra_dir" "$install_dir"

    print_status "Ghidra installed to: $install_dir"
}

# Main Ghidra installer function
run_ghidra_installer() {
    echo ""
    echo -e "${BLUE}Checking Ghidra installation...${NC}"

    if check_ghidra_installed; then
        print_status "Ghidra found at: $GHIDRA_INSTALL_DIR"
        return 0
    fi

    print_warning "Ghidra not found at: $GHIDRA_INSTALL_DIR"
    install_ghidra "$GHIDRA_VERSION" "$GHIDRA_INSTALL_DIR"

    # Verify installation
    if check_ghidra_installed; then
        print_status "Ghidra installation verified"
    else
        fail "Ghidra installation failed verification"
    fi

    # Export for use in parent script
    export GHIDRA_INSTALL_DIR
}

# Allow script to be sourced or run directly
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    run_ghidra_installer
fi
