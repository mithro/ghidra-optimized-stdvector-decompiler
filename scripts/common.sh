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

# Check if sudo is available without prompting
has_sudo() {
    if sudo -n true 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

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

# Check available disk space in MB
# Usage: check_disk_space <path> <required_mb>
check_disk_space() {
    local path="$1"
    local required_mb="$2"

    # Get available space in MB
    local available_mb
    available_mb=$(df -BM "$path" | awk 'NR==2 {print $4}' | sed 's/M//')

    if [ "$available_mb" -lt "$required_mb" ]; then
        fail "Insufficient disk space. Required: ${required_mb}MB, Available: ${available_mb}MB"
    fi
}
