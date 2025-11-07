#!/bin/bash
# Comprehensive Ghidra setup script
# Sets up Ghidra installation, all modules, and custom VectorSimplification extension

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
GHIDRA_VERSION="${GHIDRA_VERSION:-11.4.2}"
GHIDRA_RELEASE="${GHIDRA_RELEASE:-20250826}"
GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-$HOME/tools/ghidra}"
GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_RELEASE}.zip"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BLUE}========================================================================${NC}"
echo -e "${BLUE}                    Ghidra Setup Script${NC}"
echo -e "${BLUE}========================================================================${NC}"
echo ""

# Function to print status messages
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

# Detect package manager
detect_package_manager() {
    if command -v apt-get &> /dev/null; then
        echo "apt-get"
    elif command -v dnf &> /dev/null; then
        echo "dnf"
    elif command -v yum &> /dev/null; then
        echo "yum"
    elif command -v pacman &> /dev/null; then
        echo "pacman"
    else
        echo "unknown"
    fi
}

PKG_MANAGER=$(detect_package_manager)

# Function to install package
install_package() {
    local package=$1
    local install_name=${2:-$package}  # Allow different install name

    print_info "Attempting to install $package..."

    case $PKG_MANAGER in
        apt-get)
            sudo apt-get update && sudo apt-get install -y "$install_name"
            ;;
        dnf)
            sudo dnf install -y "$install_name"
            ;;
        yum)
            sudo yum install -y "$install_name"
            ;;
        pacman)
            sudo pacman -S --noconfirm "$install_name"
            ;;
        *)
            print_error "Unknown package manager. Please install $package manually."
            return 1
            ;;
    esac
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_warning "Not running as root. Some operations may require sudo."
fi

# Step 0: Check for basic tools (wget/curl, unzip)
echo ""
echo -e "${BLUE}Step 0: Checking basic dependencies...${NC}"

# Check for wget or curl
if ! command -v wget &> /dev/null && ! command -v curl &> /dev/null; then
    print_warning "Neither wget nor curl found."
    if [ -t 0 ]; then
        read -p "Install wget? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            install_package "wget" "wget" || exit 1
        else
            print_error "wget or curl required for downloading files. Exiting."
            exit 1
        fi
    else
        print_error "wget or curl required. Please install and try again."
        exit 1
    fi
fi

# Check for unzip
if ! command -v unzip &> /dev/null; then
    print_warning "unzip not found."
    if [ -t 0 ]; then
        read -p "Install unzip? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            install_package "unzip" "unzip" || exit 1
        else
            print_error "unzip required for extracting archives. Exiting."
            exit 1
        fi
    else
        print_error "unzip required. Please install and try again."
        exit 1
    fi
fi

print_status "Basic dependencies satisfied"

# Step 1: Check for Ghidra installation
echo ""
echo -e "${BLUE}Step 1: Checking Ghidra installation...${NC}"
if [ -d "$GHIDRA_INSTALL_DIR" ] && [ -f "$GHIDRA_INSTALL_DIR/ghidraRun" ]; then
    print_status "Ghidra found at: $GHIDRA_INSTALL_DIR"
    GHIDRA_EXISTS=true
else
    print_warning "Ghidra not found at: $GHIDRA_INSTALL_DIR"
    GHIDRA_EXISTS=false
fi

# Step 2: Install Ghidra if needed
if [ "$GHIDRA_EXISTS" = false ]; then
    echo ""
    echo -e "${BLUE}Step 2: Installing Ghidra ${GHIDRA_VERSION}...${NC}"

    # Check if user wants to install
    if [ -t 0 ]; then
        read -p "Do you want to download and install Ghidra? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_error "Ghidra installation required. Exiting."
            exit 1
        fi
    fi

    # Create installation directory
    mkdir -p "$(dirname "$GHIDRA_INSTALL_DIR")"

    # Download Ghidra
    print_info "Downloading Ghidra ${GHIDRA_VERSION}..."
    TEMP_ZIP="/tmp/ghidra_${GHIDRA_VERSION}.zip"

    if command -v wget &> /dev/null; then
        wget -O "$TEMP_ZIP" "$GHIDRA_URL"
    elif command -v curl &> /dev/null; then
        curl -L -o "$TEMP_ZIP" "$GHIDRA_URL"
    else
        print_error "Neither wget nor curl found. Please install one and try again."
        exit 1
    fi

    # Extract Ghidra
    print_info "Extracting Ghidra..."
    unzip -q "$TEMP_ZIP" -d "$(dirname "$GHIDRA_INSTALL_DIR")"

    # Rename to expected directory
    EXTRACTED_DIR="$(dirname "$GHIDRA_INSTALL_DIR")/ghidra_${GHIDRA_VERSION}_PUBLIC"
    if [ -d "$EXTRACTED_DIR" ] && [ "$EXTRACTED_DIR" != "$GHIDRA_INSTALL_DIR" ]; then
        mv "$EXTRACTED_DIR" "$GHIDRA_INSTALL_DIR"
    fi

    # Cleanup
    rm -f "$TEMP_ZIP"

    print_status "Ghidra ${GHIDRA_VERSION} installed successfully"
else
    echo ""
    echo -e "${BLUE}Step 2: Ghidra already installed (skipping)${NC}"
fi

# Step 3: Check Java installation
echo ""
echo -e "${BLUE}Step 3: Checking Java installation...${NC}"
if command -v java &> /dev/null; then
    JAVA_VERSION=$(java -version 2>&1 | head -n 1 | cut -d'"' -f2)
    print_status "Java found: $JAVA_VERSION"
else
    print_warning "Java not found. Ghidra requires Java 17 or later."

    if [ -t 0 ]; then
        read -p "Install OpenJDK 21? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            case $PKG_MANAGER in
                apt-get)
                    install_package "OpenJDK 21" "openjdk-21-jdk" || exit 1
                    ;;
                dnf|yum)
                    install_package "OpenJDK 21" "java-21-openjdk-devel" || exit 1
                    ;;
                pacman)
                    install_package "OpenJDK 21" "jdk21-openjdk" || exit 1
                    ;;
                *)
                    print_error "Unable to auto-install. Please install Java 17+ manually."
                    exit 1
                    ;;
            esac

            # Verify installation
            if command -v java &> /dev/null; then
                JAVA_VERSION=$(java -version 2>&1 | head -n 1 | cut -d'"' -f2)
                print_status "Java installed successfully: $JAVA_VERSION"
            else
                print_error "Java installation failed. Please install manually."
                exit 1
            fi
        else
            print_error "Java is required. Exiting."
            exit 1
        fi
    else
        print_error "Java required. Please install openjdk-21-jdk and try again."
        exit 1
    fi
fi

# Step 4: Check Gradle installation and version
echo ""
echo -e "${BLUE}Step 4: Checking Gradle installation...${NC}"

# Minimum required Gradle version for Ghidra 11.4.2
MIN_GRADLE_MAJOR=8
MIN_GRADLE_MINOR=0

# Function to check if Gradle version is sufficient
# Uses timeout to prevent hanging with slow/broken Gradle installations
check_gradle_version() {
    local gradle_cmd=$1

    # Try to get version with a 10 second timeout
    # Disable errexit temporarily to handle failures gracefully
    local version_output=""
    set +e
    if command -v timeout &> /dev/null; then
        version_output=$(timeout 10 $gradle_cmd --version 2>&1 | grep "^Gradle" | sed 's/Gradle //' || true)
    else
        # Fallback without timeout if timeout command not available
        version_output=$($gradle_cmd --version 2>&1 | grep "^Gradle" | sed 's/Gradle //' || true)
    fi
    set -e

    # Check if we got a version
    if [ -z "$version_output" ]; then
        echo "unknown"
        return 1
    fi

    local version="$version_output"
    local major=$(echo "$version" | cut -d. -f1 || echo "0")
    local minor=$(echo "$version" | cut -d. -f2 || echo "0")

    echo "$version"

    # Validate major/minor are numbers
    if ! [[ "$major" =~ ^[0-9]+$ ]] || ! [[ "$minor" =~ ^[0-9]+$ ]]; then
        return 1
    fi

    if [ "$major" -gt "$MIN_GRADLE_MAJOR" ]; then
        return 0
    elif [ "$major" -eq "$MIN_GRADLE_MAJOR" ] && [ "$minor" -ge "$MIN_GRADLE_MINOR" ]; then
        return 0
    else
        return 1
    fi
}

GRADLE_OK=false

# Check if gradle is available and meets minimum version
if command -v gradle &> /dev/null; then
    print_info "Checking Gradle version (this may take a moment)..."
    set +e
    GRADLE_VERSION=$(check_gradle_version "gradle")
    GRADLE_CHECK_RESULT=$?
    set -e
    if [ $GRADLE_CHECK_RESULT -eq 0 ]; then
        print_status "Gradle found: $GRADLE_VERSION (meets requirement >= $MIN_GRADLE_MAJOR.$MIN_GRADLE_MINOR)"
        GRADLE_OK=true
    else
        if [ "$GRADLE_VERSION" = "unknown" ]; then
            print_warning "Gradle found but unable to determine version (may be too slow or broken)"
        else
            print_warning "Gradle found but version $GRADLE_VERSION is too old (need >= $MIN_GRADLE_MAJOR.$MIN_GRADLE_MINOR)"
        fi
        print_info "The build script will attempt to use a local Gradle installation."
    fi
elif [ -f "/opt/gradle/bin/gradle" ]; then
    print_info "Checking Gradle at /opt/gradle/bin/gradle..."
    set +e
    GRADLE_VERSION=$(check_gradle_version "/opt/gradle/bin/gradle")
    GRADLE_CHECK_RESULT=$?
    set -e
    if [ $GRADLE_CHECK_RESULT -eq 0 ]; then
        print_status "Gradle found at: /opt/gradle/bin/gradle (version $GRADLE_VERSION)"
        GRADLE_OK=true
    fi
fi

# If no suitable Gradle found, offer to install from package manager or locally
if [ "$GRADLE_OK" = false ]; then
    print_warning "No suitable Gradle installation found."
    print_info "Ghidra 11.4.2 requires Gradle >= $MIN_GRADLE_MAJOR.$MIN_GRADLE_MINOR"
    echo ""
    print_info "The extension build script can automatically download Gradle 8.10.2"
    print_info "and install it locally (no root required) when you build the extension."
    echo ""

    if [ -t 0 ]; then
        echo "Options:"
        echo "  1. Continue - build script will download Gradle 8.10.2 locally when needed"
        echo "  2. Install system Gradle from package manager (may be old version)"
        echo "  3. Exit and install Gradle manually"
        echo ""
        read -p "Choose option (1/2/3): " -n 1 -r
        echo
        case $REPLY in
            1)
                print_info "Will use local Gradle installation during build."
                GRADLE_OK=true
                ;;
            2)
                case $PKG_MANAGER in
                    apt-get)
                        install_package "Gradle" "gradle"
                        ;;
                    dnf|yum)
                        install_package "Gradle" "gradle"
                        ;;
                    pacman)
                        install_package "Gradle" "gradle"
                        ;;
                    *)
                        print_error "Unable to auto-install. Please install Gradle manually."
                        print_info "Download from: https://gradle.org/releases/"
                        exit 1
                        ;;
                esac
                print_info "System Gradle installed (build script will verify version)."
                GRADLE_OK=true
                ;;
            3)
                print_info "Please install Gradle >= $MIN_GRADLE_MAJOR.$MIN_GRADLE_MINOR and run this script again."
                print_info "Download from: https://gradle.org/releases/"
                exit 1
                ;;
            *)
                print_error "Invalid option. Exiting."
                exit 1
                ;;
        esac
    else
        print_error "Gradle required. Please install Gradle >= $MIN_GRADLE_MAJOR.$MIN_GRADLE_MINOR and try again."
        exit 1
    fi
fi

# Step 5: Create user directories
echo ""
echo -e "${BLUE}Step 5: Setting up Ghidra user directories...${NC}"
GHIDRA_USER_DIR="$HOME/.ghidra/.ghidra_${GHIDRA_VERSION}_PUBLIC"
mkdir -p "$GHIDRA_USER_DIR/Extensions"
mkdir -p "$GHIDRA_USER_DIR/ghidra_scripts"
print_status "User directories created"

# Step 6: Build VectorSimplification extension
echo ""
echo -e "${BLUE}Step 6: Building VectorSimplification extension...${NC}"
EXTENSION_DIR="$SCRIPT_DIR/tools/ghidra_extensions/VectorSimplification"

if [ ! -d "$EXTENSION_DIR" ]; then
    print_error "VectorSimplification extension not found at: $EXTENSION_DIR"
    exit 1
fi

cd "$EXTENSION_DIR"
print_info "Building extension..."

# Set GHIDRA_INSTALL_DIR for build
export GHIDRA_INSTALL_DIR

if [ -f "build.sh" ]; then
    bash build.sh
else
    gradle -PGHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR" clean buildExtension
fi

print_status "Extension built successfully"

# Step 7: Install VectorSimplification extension
echo ""
echo -e "${BLUE}Step 7: Installing VectorSimplification extension...${NC}"

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
JAR_FILE="$EXTENSION_DIR/build/libs/VectorSimplification.jar"
if [ -f "$JAR_FILE" ]; then
    DECOMPILER_LIB="$GHIDRA_INSTALL_DIR/Ghidra/Features/Decompiler/lib"
    if [ -d "$DECOMPILER_LIB" ]; then
        print_info "Installing JAR for headless mode..."
        cp "$JAR_FILE" "$DECOMPILER_LIB/"
        print_status "JAR installed to Decompiler lib"
    fi
fi

print_status "VectorSimplification extension installed"

# Enable extension in user preferences
print_info "Enabling VectorSimplification extension..."
PREFS_DIR="$GHIDRA_USER_DIR/preferences"
mkdir -p "$PREFS_DIR"

# Create or update ExtensionProvider preferences to enable VectorSimplification
EXTENSION_PREFS="$PREFS_DIR/ExtensionProvider"
if [ ! -f "$EXTENSION_PREFS" ]; then
    cat > "$EXTENSION_PREFS" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<FILE_INFO>
    <BASIC_INFO>
        <STATE NAME="Extension States" TYPE="string" VALUE="VectorSimplification:true;" />
    </BASIC_INFO>
</FILE_INFO>
EOF
    print_status "Extension auto-enabled for GUI mode"
else
    # Update existing file to add VectorSimplification
    if grep -q "VectorSimplification" "$EXTENSION_PREFS"; then
        sed -i 's/VectorSimplification:[^;]*/VectorSimplification:true/g' "$EXTENSION_PREFS"
        print_status "Extension state updated to enabled"
    else
        # Add VectorSimplification to existing STATE value
        sed -i 's/VALUE="\([^"]*\)"/VALUE="\1VectorSimplification:true;"/g' "$EXTENSION_PREFS"
        print_status "Extension added to enabled list"
    fi
fi

print_info "Extension is enabled for both GUI and headless modes"

# Step 8: Install optional plugins
echo ""
echo -e "${BLUE}Step 8: Checking for optional plugins...${NC}"

PLUGIN_DIR="$SCRIPT_DIR/tools/plugin_installers"
if [ -d "$PLUGIN_DIR" ]; then
    PLUGIN_COUNT=0
    for plugin in "$PLUGIN_DIR"/*; do
        if [ -d "$plugin" ]; then
            PLUGIN_NAME=$(basename "$plugin")
            INSTALL_SCRIPT="$plugin/install_${PLUGIN_NAME}.sh"
            if [ -f "$INSTALL_SCRIPT" ]; then
                PLUGIN_COUNT=$((PLUGIN_COUNT + 1))
                print_info "Found plugin: $PLUGIN_NAME"
            fi
        fi
    done

    if [ $PLUGIN_COUNT -gt 0 ]; then
        print_info "Found $PLUGIN_COUNT optional plugin(s)"
        print_info "Run individual install scripts in: $PLUGIN_DIR"
    fi
else
    print_info "No optional plugins directory found"
fi

# Step 9: Verification
echo ""
echo -e "${BLUE}Step 9: Verifying installation...${NC}"

# Check if extension directory exists
if [ -d "$SYSTEM_EXT_DIR/VectorSimplification" ]; then
    print_status "VectorSimplification directory found"
else
    print_warning "VectorSimplification directory not found"
fi

# Check if JAR exists
if [ -f "$DECOMPILER_LIB/VectorSimplification.jar" ]; then
    print_status "VectorSimplification JAR installed"
else
    print_warning "VectorSimplification JAR not found in Decompiler lib"
fi

# Check Module.manifest
MANIFEST="$SYSTEM_EXT_DIR/VectorSimplification/Module.manifest"
if [ -f "$MANIFEST" ]; then
    print_status "Module.manifest found"
else
    print_warning "Module.manifest not found"
fi

# Step 10: Summary
echo ""
echo -e "${BLUE}========================================================================${NC}"
echo -e "${GREEN}                    Setup Complete!${NC}"
echo -e "${BLUE}========================================================================${NC}"
echo ""
echo "Ghidra installation: $GHIDRA_INSTALL_DIR"
echo "Extension installed: VectorSimplification"
echo "Extension status: ${GREEN}Automatically enabled${NC}"
echo ""
echo -e "${YELLOW}Using Ghidra GUI:${NC}"
echo "  Start Ghidra: $GHIDRA_INSTALL_DIR/ghidraRun"
echo "  The VectorSimplification extension is already enabled!"
echo ""
echo -e "${YELLOW}Using headless analysis:${NC}"
echo "  $GHIDRA_INSTALL_DIR/support/analyzeHeadless <project> <name> -import <binary>"
echo ""
echo -e "${YELLOW}Test the extension:${NC}"
echo "  cd $SCRIPT_DIR/test/vector_test"
echo "  python test_transformation.py"
echo ""
echo -e "${BLUE}========================================================================${NC}"
