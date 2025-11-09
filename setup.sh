#!/bin/bash
# Automated setup script for Optimized Vector Decompiler Ghidra Plugin
# Builds and installs the extension with minimal configuration required

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
GHIDRA_VERSION="${GHIDRA_VERSION:-11.4.2}"
GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-$HOME/tools/ghidra}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKIP_BUILD=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--skip-build]"
            exit 1
            ;;
    esac
done

# Helper functions
print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE}      Optimized Vector Decompiler Ghidra Plugin - Setup${NC}"
echo -e "${BLUE}======================================================================${NC}"
echo ""

# Step 1: Check for Ghidra
echo -e "${BLUE}Step 1: Checking for Ghidra installation...${NC}"
if [ -d "$GHIDRA_INSTALL_DIR" ] && [ -f "$GHIDRA_INSTALL_DIR/ghidraRun" ]; then
    print_status "Ghidra found at: $GHIDRA_INSTALL_DIR"
else
    print_error "Ghidra not found at: $GHIDRA_INSTALL_DIR"
    echo ""
    print_info "Please install Ghidra 11.4.2 from:"
    echo "  https://github.com/NationalSecurityAgency/ghidra/releases"
    echo ""
    print_info "Or set GHIDRA_INSTALL_DIR to your Ghidra installation:"
    echo "  export GHIDRA_INSTALL_DIR=/path/to/ghidra"
    echo "  ./setup.sh"
    exit 1
fi

# Step 2: Check Java
echo ""
echo -e "${BLUE}Step 2: Checking Java installation...${NC}"
if command -v java &> /dev/null; then
    JAVA_VERSION=$(java -version 2>&1 | head -n 1 | cut -d'"' -f2)
    print_status "Java found: $JAVA_VERSION"
else
    print_error "Java not found. Ghidra requires Java 17 or later."
    print_info "Install with: sudo apt-get install openjdk-21-jdk"
    exit 1
fi

# Step 3: Create user directories
echo ""
echo -e "${BLUE}Step 3: Setting up Ghidra user directories...${NC}"
GHIDRA_USER_DIR="$HOME/.ghidra/.ghidra_${GHIDRA_VERSION}_PUBLIC"
mkdir -p "$GHIDRA_USER_DIR/Extensions"
mkdir -p "$GHIDRA_USER_DIR/ghidra_scripts"
print_status "User directories created"

# Step 4: Build extension
echo ""
EXTENSION_DIR="$SCRIPT_DIR/extension"

JAR_FILE="$EXTENSION_DIR/build/libs/OptimizedVectorDecompiler.jar"

if [ "$SKIP_BUILD" = true ]; then
    echo -e "${BLUE}Step 4: Skipping build (--skip-build specified)...${NC}"
    print_info "Using pre-built extension JAR"

    # Verify JAR exists
    if [ ! -f "$JAR_FILE" ]; then
        print_error "Pre-built JAR not found at: $JAR_FILE"
        print_info "Remove --skip-build to build from source"
        exit 1
    fi
    print_status "Found pre-built JAR"
else
    echo -e "${BLUE}Step 4: Building OptimizedVectorDecompiler extension...${NC}"
    cd "$EXTENSION_DIR"
    print_info "Building extension..."

    export GHIDRA_INSTALL_DIR

    if [ -f "build.sh" ]; then
        bash build.sh
    else
        print_error "Build script not found!"
        exit 1
    fi

    print_status "Extension built successfully"
fi

# Step 5: Install extension
echo ""
echo -e "${BLUE}Step 5: Installing extension...${NC}"

SYSTEM_EXT_DIR="$GHIDRA_INSTALL_DIR/Extensions/Ghidra"
DECOMPILER_LIB="$GHIDRA_INSTALL_DIR/Ghidra/Features/Decompiler/lib"

if [ "$SKIP_BUILD" = true ]; then
    # Skip build mode: Install JAR directly (JAR_FILE already set in Step 4)
    print_info "Installing JAR to system extensions..."
    mkdir -p "$SYSTEM_EXT_DIR"
    cp "$JAR_FILE" "$SYSTEM_EXT_DIR/"

    # Also copy to Decompiler lib for headless mode
    if [ -d "$DECOMPILER_LIB" ]; then
        print_info "Installing JAR for headless mode..."
        cp "$JAR_FILE" "$DECOMPILER_LIB/"
        print_status "JAR installed to Decompiler lib"
    fi
else
    # Normal mode: Extract from distribution ZIP
    DIST_FILE=$(ls -t "$EXTENSION_DIR/dist"/*.zip 2>/dev/null | head -1)

    if [ -z "$DIST_FILE" ]; then
        print_error "No extension package found in $EXTENSION_DIR/dist/"
        exit 1
    fi

    print_info "Found extension package: $(basename "$DIST_FILE")"

    # Install to Ghidra system extensions
    mkdir -p "$SYSTEM_EXT_DIR"

    print_info "Extracting to system extensions directory..."
    unzip -q -o "$DIST_FILE" -d "$SYSTEM_EXT_DIR/"

    # Also copy JAR to Decompiler lib for headless mode (JAR_FILE already set in Step 4)
    if [ -f "$JAR_FILE" ]; then
        if [ -d "$DECOMPILER_LIB" ]; then
            print_info "Installing JAR for headless mode..."
            cp "$JAR_FILE" "$DECOMPILER_LIB/"
            print_status "JAR installed to Decompiler lib"
        fi
    fi
fi

print_status "OptimizedVectorDecompiler extension installed"

# Step 6: Auto-enable extension
echo ""
echo -e "${BLUE}Step 6: Enabling extension...${NC}"
PREFS_DIR="$GHIDRA_USER_DIR/preferences"
mkdir -p "$PREFS_DIR"

EXTENSION_PREFS="$PREFS_DIR/ExtensionProvider"
if [ ! -f "$EXTENSION_PREFS" ]; then
    cat > "$EXTENSION_PREFS" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<FILE_INFO>
    <BASIC_INFO>
        <STATE NAME="Extension States" TYPE="string" VALUE="OptimizedVectorDecompiler:true;" />
    </BASIC_INFO>
</FILE_INFO>
EOF
    print_status "Extension auto-enabled for GUI mode"
else
    if grep -q "OptimizedVectorDecompiler" "$EXTENSION_PREFS"; then
        sed -i 's/OptimizedVectorDecompiler:[^;]*/OptimizedVectorDecompiler:true/g' "$EXTENSION_PREFS"
        print_status "Extension state updated to enabled"
    else
        sed -i 's/VALUE="\([^"]*\)"/VALUE="\1OptimizedVectorDecompiler:true;"/g' "$EXTENSION_PREFS"
        print_status "Extension added to enabled list"
    fi
fi

print_info "Extension is enabled for both GUI and headless modes"

# Step 7: Verification
echo ""
echo -e "${BLUE}Step 7: Verifying installation...${NC}"

if [ -d "$SYSTEM_EXT_DIR/OptimizedVectorDecompiler" ]; then
    print_status "OptimizedVectorDecompiler directory found"
else
    print_warning "OptimizedVectorDecompiler directory not found"
fi

if [ -f "$DECOMPILER_LIB/OptimizedVectorDecompiler.jar" ]; then
    print_status "OptimizedVectorDecompiler JAR installed"
else
    print_warning "OptimizedVectorDecompiler JAR not found in Decompiler lib"
fi

# Summary
echo ""
echo -e "${BLUE}======================================================================${NC}"
echo -e "${GREEN}                    Setup Complete!${NC}"
echo -e "${BLUE}======================================================================${NC}"
echo ""
echo "Ghidra installation: $GHIDRA_INSTALL_DIR"
echo "Extension installed: OptimizedVectorDecompiler"
echo -e "Extension status: ${GREEN}Automatically enabled${NC}"
echo ""
echo -e "${YELLOW}Using Ghidra GUI:${NC}"
echo "  Start Ghidra: $GHIDRA_INSTALL_DIR/ghidraRun"
echo "  The OptimizedVectorDecompiler extension is already enabled!"
echo ""
echo -e "${YELLOW}Using headless analysis:${NC}"
echo "  $GHIDRA_INSTALL_DIR/support/analyzeHeadless <project> <name> -import <binary>"
echo ""
echo -e "${YELLOW}Test the extension:${NC}"
echo "  cd $SCRIPT_DIR/examples/vector_test"
echo "  python test_transformation.py"
echo ""
echo -e "${BLUE}======================================================================${NC}"
