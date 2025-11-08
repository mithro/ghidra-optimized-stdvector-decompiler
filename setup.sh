#!/bin/bash
# Automated setup script for Optimized Vector Decompiler Ghidra Plugin
# Builds and installs the extension with minimal configuration required

set -euo pipefail

# Script directory
SETUP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source common utilities and installers
source "$SETUP_DIR/scripts/common.sh"
source "$SETUP_DIR/scripts/install_java.sh"
source "$SETUP_DIR/scripts/install_ghidra.sh"

# Restore SCRIPT_DIR for rest of setup.sh
SCRIPT_DIR="$SETUP_DIR"

# Configuration
INSTALL_DIR="${INSTALL_DIR:-$HOME/tools}"
GHIDRA_VERSION="${GHIDRA_VERSION:-11.4.2}"
GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-$INSTALL_DIR/ghidra}"

echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE}      Optimized Vector Decompiler Ghidra Plugin - Setup${NC}"
echo -e "${BLUE}======================================================================${NC}"
echo ""

# Install Java if needed
run_java_installer

# Install Ghidra if needed
run_ghidra_installer

# Step 1: Verify Ghidra installation
echo ""
echo -e "${BLUE}Step 1: Verifying Ghidra installation...${NC}"
if [ -d "$GHIDRA_INSTALL_DIR" ] && [ -f "$GHIDRA_INSTALL_DIR/ghidraRun" ]; then
    print_status "Ghidra verified at: $GHIDRA_INSTALL_DIR"
else
    fail "Ghidra installation failed. Please check errors above."
fi

# Step 2: Verify Java installation
echo ""
echo -e "${BLUE}Step 2: Verifying Java installation...${NC}"
if command -v java &> /dev/null; then
    JAVA_VERSION=$(java -version 2>&1 | head -n 1 | cut -d'"' -f2)
    print_status "Java verified: $JAVA_VERSION"
else
    fail "Java installation failed. Please check errors above."
fi

# Step 3: Create user directories
echo ""
echo -e "${BLUE}Step 3: Setting up Ghidra user directories...${NC}"
GHIDRA_USER_DIR="$HOME/.ghidra/.ghidra_${GHIDRA_VERSION}_PUBLIC"
mkdir -p "$GHIDRA_USER_DIR/Extensions"
mkdir -p "$GHIDRA_USER_DIR/ghidra_scripts"
print_status "User directories created"

# Step 4: Building OptimizedVectorDecompiler extension
echo ""
echo -e "${BLUE}Step 4: Building OptimizedVectorDecompiler extension...${NC}"
EXTENSION_DIR="$SCRIPT_DIR/extension"

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

# Step 5: Install extension
echo ""
echo -e "${BLUE}Step 5: Installing extension...${NC}"

# Find the latest built extension
DIST_FILE=$(ls -t "$EXTENSION_DIR/dist"/*.zip 2>/dev/null | head -1)

if [ -z "$DIST_FILE" ]; then
    print_error "No extension package found in $EXTENSION_DIR/dist/"
    exit 1
fi

print_info "Found extension package: $(basename "$DIST_FILE")"

# Install to Ghidra system extensions
SYSTEM_EXT_DIR="$GHIDRA_INSTALL_DIR/Extensions/Ghidra"
mkdir -p "$SYSTEM_EXT_DIR"

print_info "Extracting to system extensions directory..."
unzip -q -o "$DIST_FILE" -d "$SYSTEM_EXT_DIR/"

# Also copy JAR to Decompiler lib for headless mode
JAR_FILE="$EXTENSION_DIR/build/libs/OptimizedVectorDecompiler.jar"
if [ -f "$JAR_FILE" ]; then
    DECOMPILER_LIB="$GHIDRA_INSTALL_DIR/Ghidra/Features/Decompiler/lib"
    if [ -d "$DECOMPILER_LIB" ]; then
        print_info "Installing JAR for headless mode..."
        cp "$JAR_FILE" "$DECOMPILER_LIB/"
        print_status "JAR installed to Decompiler lib"
    fi
fi

print_status "OptimizedVectorDecompiler extension installed"

# Step 6: Enabling extension
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

# Step 7: Verifying installation
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
