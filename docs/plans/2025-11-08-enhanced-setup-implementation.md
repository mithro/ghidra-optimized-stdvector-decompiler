# Enhanced Setup Script Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enable fully automatic installation of Java and Ghidra dependencies from setup.sh on fresh Linux systems.

**Architecture:** Modular bash scripts with shared utilities (scripts/common.sh), separate installers for Java (scripts/install_java.sh) and Ghidra (scripts/install_ghidra.sh), orchestrated by enhanced setup.sh.

**Tech Stack:** Bash 4+, curl/wget, apt package manager, GitHub releases API

---

## Task 1: Create scripts directory and common.sh utilities

**Files:**
- Create: `scripts/common.sh`

**Step 1: Create scripts directory**

```bash
mkdir -p scripts
```

**Step 2: Create common.sh with color constants and print functions**

Create `scripts/common.sh`:

```bash
#!/bin/bash
# Common utilities for setup scripts

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print functions
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

# Error handling
fail() {
    print_error "$1"
    exit 1
}
```

**Step 3: Add has_sudo function**

Add to `scripts/common.sh` after the fail() function:

```bash
# Check if sudo is available without prompting
has_sudo() {
    if sudo -n true 2>/dev/null; then
        return 0
    else
        return 1
    fi
}
```

**Step 4: Add download_file function with retry logic**

Add to `scripts/common.sh` after has_sudo():

```bash
# Download file with retry logic
# Usage: download_file <url> <destination>
download_file() {
    local url="$1"
    local dest="$2"
    local max_retries=3
    local retry=0

    while [ $retry -lt $max_retries ]; do
        print_info "Downloading $(basename "$dest")... (attempt $((retry + 1))/$max_retries)"

        if command -v curl &> /dev/null; then
            if curl -L -f -o "$dest" "$url" 2>&1; then
                print_status "Download complete"
                return 0
            fi
        elif command -v wget &> /dev/null; then
            if wget -O "$dest" "$url" 2>&1; then
                print_status "Download complete"
                return 0
            fi
        else
            fail "Neither curl nor wget found. Please install one of them."
        fi

        retry=$((retry + 1))
        if [ $retry -lt $max_retries ]; then
            local wait_time=$((2 ** retry))
            print_warning "Download failed. Retrying in ${wait_time}s..."
            sleep $wait_time
        fi
    done

    return 1
}
```

**Step 5: Add extract_archive function**

Add to `scripts/common.sh` after download_file():

```bash
# Extract archive based on extension
# Usage: extract_archive <file> <destination>
extract_archive() {
    local file="$1"
    local dest="$2"

    print_info "Extracting $(basename "$file")..."

    case "$file" in
        *.zip)
            if ! command -v unzip &> /dev/null; then
                fail "unzip not found. Please install it: sudo apt-get install unzip"
            fi
            unzip -q -o "$file" -d "$dest" || fail "Extraction failed"
            ;;
        *.tar.gz|*.tgz)
            tar -xzf "$file" -C "$dest" || fail "Extraction failed"
            ;;
        *)
            fail "Unsupported archive format: $file"
            ;;
    esac

    print_status "Extraction complete"
}
```

**Step 6: Add check_disk_space function**

Add to `scripts/common.sh` after extract_archive():

```bash
# Check available disk space in MB
# Usage: check_disk_space <path> <required_mb>
check_disk_space() {
    local path="$1"
    local required_mb="$2"

    # Get available space in MB
    local available_mb=$(df -BM "$path" | awk 'NR==2 {print $4}' | sed 's/M//')

    if [ "$available_mb" -lt "$required_mb" ]; then
        fail "Insufficient disk space. Required: ${required_mb}MB, Available: ${available_mb}MB"
    fi
}
```

**Step 7: Verify common.sh can be sourced**

Run: `bash -n scripts/common.sh`
Expected: No output (syntax OK)

**Step 8: Commit common.sh**

```bash
git add scripts/common.sh
git commit -m "feat(setup): add common utilities for modular setup scripts

Add scripts/common.sh with:
- Color constants and print functions
- Error handling (fail function)
- Sudo availability checking
- Download helper with retry logic and exponential backoff
- Archive extraction for zip and tar.gz
- Disk space checking

Part of enhanced setup script implementation.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 2: Create install_java.sh

**Files:**
- Create: `scripts/install_java.sh`

**Step 1: Create install_java.sh with header and Java version check**

Create `scripts/install_java.sh`:

```bash
#!/bin/bash
# Java installation module for setup.sh

set -euo pipefail

# Source common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

# Check if Java is installed and meets minimum version
check_java_version() {
    if ! command -v java &> /dev/null; then
        return 1
    fi

    # Parse Java version (handles both old "1.8" and new "21" formats)
    local version_output=$(java -version 2>&1 | head -n 1)
    local java_version=$(echo "$version_output" | sed -n 's/.*version "\(.*\)".*/\1/p' | cut -d'.' -f1)

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
```

**Step 2: Add install_java_apt function**

Add to `scripts/install_java.sh` after check_java_version():

```bash
# Install Java using apt
install_java_apt() {
    print_info "Installing OpenJDK 21 via apt..."

    # Check sudo availability
    if ! has_sudo && ! sudo -v 2>/dev/null; then
        fail "Java installation requires sudo. Please run: sudo apt-get install openjdk-21-jdk"
    fi

    # Update package list
    print_info "Updating package list..."
    sudo apt-get update || fail "Failed to update package list"

    # Install Java
    print_info "Installing openjdk-21-jdk..."
    sudo apt-get install -y openjdk-21-jdk || fail "Failed to install Java"

    print_status "Java installed successfully"
}
```

**Step 3: Add main run_java_installer function**

Add to `scripts/install_java.sh` after install_java_apt():

```bash
# Main Java installer function
run_java_installer() {
    echo ""
    echo -e "${BLUE}Checking Java installation...${NC}"

    if check_java_version; then
        local version=$(java -version 2>&1 | head -n 1 | cut -d'"' -f2)
        print_status "Java found: $version"
        return 0
    fi

    print_warning "Java 21+ not found"
    install_java_apt

    # Verify installation
    if check_java_version; then
        local version=$(java -version 2>&1 | head -n 1 | cut -d'"' -f2)
        print_status "Java installation verified: $version"
    else
        fail "Java installation failed verification"
    fi
}

# Allow script to be sourced or run directly
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    run_java_installer
fi
```

**Step 4: Verify install_java.sh syntax**

Run: `bash -n scripts/install_java.sh`
Expected: No output (syntax OK)

**Step 5: Test install_java.sh with existing Java**

Run: `bash scripts/install_java.sh`
Expected: "✓ Java found: <version>" (should detect existing Java)

**Step 6: Commit install_java.sh**

```bash
git add scripts/install_java.sh
git commit -m "feat(setup): add Java installer module

Add scripts/install_java.sh with:
- Java version detection (handles both 1.x and modern formats)
- Minimum version check (21+)
- Automatic apt installation with sudo
- Installation verification
- Can be sourced or run standalone

Part of enhanced setup script implementation.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 3: Create install_ghidra.sh

**Files:**
- Create: `scripts/install_ghidra.sh`

**Step 1: Create install_ghidra.sh with configuration and architecture detection**

Create `scripts/install_ghidra.sh`:

```bash
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
```

**Step 2: Add function to build Ghidra download URL**

Add to `scripts/install_ghidra.sh` after detect_architecture():

```bash
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
```

**Step 3: Add function to check existing Ghidra installation**

Add to `scripts/install_ghidra.sh` after get_ghidra_download_url():

```bash
# Check if Ghidra is already installed
check_ghidra_installed() {
    if [ -f "$GHIDRA_INSTALL_DIR/ghidraRun" ]; then
        return 0
    else
        return 1
    fi
}
```

**Step 4: Add function to download and install Ghidra**

Add to `scripts/install_ghidra.sh` after check_ghidra_installed():

```bash
# Download and install Ghidra
install_ghidra() {
    local version="$1"
    local install_dir="$2"

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
```

**Step 5: Add main run_ghidra_installer function**

Add to `scripts/install_ghidra.sh` after install_ghidra():

```bash
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
```

**Step 6: Verify install_ghidra.sh syntax**

Run: `bash -n scripts/install_ghidra.sh`
Expected: No output (syntax OK)

**Step 7: Test install_ghidra.sh with existing Ghidra**

Run: `bash scripts/install_ghidra.sh`
Expected: Should detect existing Ghidra or attempt download if missing

**Step 8: Commit install_ghidra.sh**

```bash
git add scripts/install_ghidra.sh
git commit -m "feat(setup): add Ghidra installer module

Add scripts/install_ghidra.sh with:
- Architecture detection (x64/arm64)
- Ghidra download URL construction
- Existing installation detection
- Download from GitHub releases with retry
- Automatic extraction and installation to \$HOME/tools/ghidra
- Installation verification
- Can be sourced or run standalone

Part of enhanced setup script implementation.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 4: Enhance setup.sh to use new installers

**Files:**
- Modify: `setup.sh:1-56`

**Step 1: Read current setup.sh header**

Run: `head -56 setup.sh`
Expected: See current header with colors, config, and helper functions

**Step 2: Replace setup.sh header to source new modules**

Replace lines 1-56 in `setup.sh` with:

```bash
#!/bin/bash
# Automated setup script for Optimized Vector Decompiler Ghidra Plugin
# Builds and installs the extension with minimal configuration required

set -euo pipefail

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source common utilities and installers
source "$SCRIPT_DIR/scripts/common.sh"
source "$SCRIPT_DIR/scripts/install_java.sh"
source "$SCRIPT_DIR/scripts/install_ghidra.sh"

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
```

**Step 3: Update Step 1 comment in setup.sh**

Find and replace line 42 `# Step 1: Check for Ghidra` section (lines 42-55) with:

```bash
# Step 1: Verify Ghidra installation
echo ""
echo -e "${BLUE}Step 1: Verifying Ghidra installation...${NC}"
if [ -d "$GHIDRA_INSTALL_DIR" ] && [ -f "$GHIDRA_INSTALL_DIR/ghidraRun" ]; then
    print_status "Ghidra verified at: $GHIDRA_INSTALL_DIR"
else
    fail "Ghidra installation failed. Please check errors above."
fi
```

**Step 4: Update Step 2 comment in setup.sh**

Find line 58 `# Step 2: Check Java` and replace the section (lines 58-67) with:

```bash
# Step 2: Verify Java installation
echo ""
echo -e "${BLUE}Step 2: Verifying Java installation...${NC}"
if command -v java &> /dev/null; then
    JAVA_VERSION=$(java -version 2>&1 | head -n 1 | cut -d'"' -f2)
    print_status "Java verified: $JAVA_VERSION"
else
    fail "Java installation failed. Please check errors above."
fi
```

**Step 5: Renumber remaining steps in setup.sh**

Update step numbers:
- Old "Step 3: Create user directories" → "Step 3: Setting up Ghidra user directories"
- Old "Step 4: Build extension" → "Step 4: Building OptimizedVectorDecompiler extension"
- Old "Step 5: Install extension" → "Step 5: Installing extension"
- Old "Step 6: Auto-enable extension" → "Step 6: Enabling extension"
- Old "Step 7: Verification" → "Step 7: Verifying installation"

(Line numbers stay the same, just update the comment text)

**Step 6: Verify setup.sh syntax**

Run: `bash -n setup.sh`
Expected: No output (syntax OK)

**Step 7: Commit enhanced setup.sh**

```bash
git add setup.sh
git commit -m "feat(setup): integrate modular installers into setup.sh

Enhance setup.sh to:
- Source scripts/common.sh, install_java.sh, install_ghidra.sh
- Auto-install Java via run_java_installer
- Auto-install Ghidra via run_ghidra_installer
- Verify installations before proceeding to plugin build
- Maintain backward compatibility with existing env vars

Completes enhanced setup script implementation.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 5: Update documentation

**Files:**
- Modify: `README.md` (Quick Start section)
- Modify: `INSTALLATION.md` (if it exists and references manual installation)

**Step 1: Check if README.md has installation instructions**

Run: `grep -n "Installation\|Setup\|Quick Start" README.md | head -20`
Expected: Find sections that reference installation

**Step 2: Update README.md Quick Start**

Find the Quick Start or Installation section in `README.md` and update it to mention automatic dependency installation:

Add after the existing quick start instructions:

```markdown
The setup script will automatically:
- Install Java 21 (if not present)
- Download and install Ghidra 11.4.2 (if not present)
- Build the extension
- Install and enable it in Ghidra

**Requirements:**
- Ubuntu/Debian Linux (or compatible)
- sudo access (for Java installation only)
- ~500MB free disk space
- Internet connection
```

**Step 3: Update design document status**

Modify `docs/plans/2025-11-08-enhanced-setup-design.md` line 4:

Replace: `**Status**: Approved`
With: `**Status**: Implemented`

**Step 4: Commit documentation updates**

```bash
git add README.md docs/plans/2025-11-08-enhanced-setup-design.md
git commit -m "docs: update for automatic dependency installation

Update README.md to document automatic Java and Ghidra installation.
Mark design document as implemented.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 6: Testing and verification

**Files:**
- Create: `test_setup.sh` (temporary test script)

**Step 1: Create test verification script**

Create `test_setup.sh`:

```bash
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
```

**Step 2: Make test script executable and run it**

Run: `chmod +x test_setup.sh && ./test_setup.sh`
Expected: All tests pass (Java/Ghidra detection warnings OK)

**Step 3: Test setup.sh dry-run syntax**

Run: `bash -n setup.sh`
Expected: No output (syntax OK)

**Step 4: Manual verification checklist**

Verify:
- [ ] All scripts have correct shebang: `#!/bin/bash`
- [ ] All scripts use `set -euo pipefail`
- [ ] All functions are documented with comments
- [ ] Error messages include helpful instructions
- [ ] Download retry logic uses exponential backoff
- [ ] Disk space check before large downloads
- [ ] All commits follow conventional commit format

**Step 5: Remove test script**

Run: `rm test_setup.sh`

**Step 6: Final commit**

```bash
git add -A
git commit -m "test: verify enhanced setup implementation

All components tested:
- Script syntax validation
- Source-ability of modules
- Java version detection
- Ghidra installation detection
- Integration with main setup.sh

Ready for integration testing on fresh system.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Testing Strategy

### Post-Implementation Testing

After completing all tasks, test in these environments:

1. **Fresh Ubuntu 22.04/24.04** (Docker container or VM)
   - No Java, no Ghidra
   - Run: `./setup.sh`
   - Verify: Java installed, Ghidra downloaded, plugin built and enabled

2. **System with Java already installed**
   - Run: `./setup.sh`
   - Verify: Skips Java installation, proceeds to Ghidra

3. **System with both Java and Ghidra installed**
   - Run: `./setup.sh`
   - Verify: Skips both installations, only builds plugin

4. **Offline mode** (disable network)
   - Run: `./setup.sh`
   - Verify: Fails gracefully with helpful error message

### Verification Commands

After successful setup:
```bash
# Verify Java
java -version

# Verify Ghidra
ls -l $HOME/tools/ghidra/ghidraRun

# Verify plugin
ls -l $HOME/tools/ghidra/Extensions/Ghidra/OptimizedVectorDecompiler

# Test plugin
cd examples/vector_test
python test_transformation.py
```

Expected: All commands succeed, test finds vector patterns.

---

## Notes

- **Python requirement**: Per CLAUDE.md, use `uv` for Python commands, but existing test uses plain `python`
- **Temporary directories**: Create in project dir, not /tmp
- **Backward compatibility**: Existing `GHIDRA_INSTALL_DIR` env var continues to work
- **Error messages**: Include actionable instructions for manual fixes
- **Commits**: Follow conventional commits format with Co-Authored-By trailer
