#!/bin/bash
# Java installation module for setup.sh

set -euo pipefail

# Source common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

# Check if Java JDK is installed and meets minimum version
check_java_version() {
    if ! command -v java &> /dev/null; then
        return 1
    fi

    # Check for javac (Java compiler) - required for building
    if ! command -v javac &> /dev/null; then
        return 1
    fi

    # Parse Java version (handles both old "1.8" and new "21" formats)
    local version_output
    version_output=$(java -version 2>&1 | head -n 1)
    local java_version
    java_version=$(echo "$version_output" | sed -n 's/.*version "\(.*\)".*/\1/p' | cut -d'.' -f1)

    # Handle old version format (1.x)
    if [ "$java_version" = "1" ]; then
        java_version=$(echo "$version_output" | sed -n 's/.*version "1\.\([0-9]*\).*/\1/p')
    fi

    # Check if version is 21 or higher
    if [ "$java_version" -ge 21 ] 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Install Java using apt
install_java_apt() {
    print_info "Installing OpenJDK 21 via apt..."

    # Check sudo availability
    if ! has_sudo; then
        # Verify sudo is available (will prompt for password if needed)
        if ! sudo -v 2>/dev/null; then
            fail "Java installation requires sudo. Please run: sudo apt-get install openjdk-21-jdk"
        fi
    fi

    # Update package list
    print_info "Updating package list..."
    sudo apt-get update || fail "Failed to update package list"

    # Install Java
    print_info "Installing openjdk-21-jdk..."
    sudo apt-get install -y openjdk-21-jdk || fail "Failed to install Java"

    print_status "Java installed successfully"
}

# Main Java installer function
run_java_installer() {
    echo ""
    echo -e "${BLUE}Checking Java installation...${NC}"

    if check_java_version; then
        local version
        version=$(java -version 2>&1 | head -n 1 | cut -d'"' -f2)
        print_status "Java found: $version"
        return 0
    fi

    print_warning "Java 21+ not found"
    install_java_apt

    # Verify installation
    if check_java_version; then
        local version
        version=$(java -version 2>&1 | head -n 1 | cut -d'"' -f2)
        print_status "Java installation verified: $version"
    else
        fail "Java installation failed verification"
    fi
}

# Allow script to be sourced or run directly
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    run_java_installer
fi
