#!/bin/bash
# Build script for OptimizedVectorDecompiler Ghidra extension

set -e

# Find Ghidra installation
GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-$HOME/tools/ghidra}"

if [ ! -d "$GHIDRA_INSTALL_DIR" ]; then
    echo "Error: Ghidra installation not found at $GHIDRA_INSTALL_DIR"
    echo "Set GHIDRA_INSTALL_DIR environment variable or install Ghidra at ~/tools/ghidra/"
    exit 1
fi

echo "Using Ghidra installation: $GHIDRA_INSTALL_DIR"

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "Building OptimizedVectorDecompiler extension..."
echo ""

# Minimum required Gradle version for Ghidra 11.4.2
MIN_GRADLE_MAJOR=8
MIN_GRADLE_MINOR=0

# Function to extract Gradle version
get_gradle_version() {
    local gradle_cmd=$1
    $gradle_cmd --version 2>&1 | grep "^Gradle" | sed 's/Gradle //'
}

# Function to compare versions (returns 0 if version is >= min_version)
version_ge() {
    local version=$1
    local min_major=$2
    local min_minor=$3

    local major=$(echo "$version" | cut -d. -f1)
    local minor=$(echo "$version" | cut -d. -f2)

    if [ "$major" -gt "$min_major" ]; then
        return 0
    elif [ "$major" -eq "$min_major" ] && [ "$minor" -ge "$min_minor" ]; then
        return 0
    else
        return 1
    fi
}

# Find Gradle - try multiple sources in order of preference
GRADLE_CMD=""

# 1. Check for local Gradle installation (installed by install_gradle.sh)
if [ -f "$SCRIPT_DIR/gradle/bin/gradle" ]; then
    GRADLE_VERSION=$(get_gradle_version "$SCRIPT_DIR/gradle/bin/gradle")
    if version_ge "$GRADLE_VERSION" $MIN_GRADLE_MAJOR $MIN_GRADLE_MINOR; then
        GRADLE_CMD="$SCRIPT_DIR/gradle/bin/gradle"
        echo "Using local Gradle: $GRADLE_VERSION"
    fi
fi

# 2. Check for Gradle wrapper in current directory
if [ -z "$GRADLE_CMD" ] && [ -f "./gradlew" ]; then
    GRADLE_CMD="./gradlew"
    echo "Using Gradle wrapper: ./gradlew"
fi

# 3. Check if gradle is in PATH
if [ -z "$GRADLE_CMD" ] && command -v gradle &> /dev/null; then
    GRADLE_VERSION=$(get_gradle_version "gradle")
    if version_ge "$GRADLE_VERSION" $MIN_GRADLE_MAJOR $MIN_GRADLE_MINOR; then
        GRADLE_CMD="gradle"
        echo "Using system Gradle: $(which gradle) (version $GRADLE_VERSION)"
    else
        echo "WARNING: System Gradle version $GRADLE_VERSION is too old (need >= $MIN_GRADLE_MAJOR.$MIN_GRADLE_MINOR)"
        echo "System Gradle will not be used."
    fi
fi

# 4. Check common installation locations
if [ -z "$GRADLE_CMD" ] && [ -f "/opt/gradle/bin/gradle" ]; then
    GRADLE_VERSION=$(get_gradle_version "/opt/gradle/bin/gradle")
    if version_ge "$GRADLE_VERSION" $MIN_GRADLE_MAJOR $MIN_GRADLE_MINOR; then
        GRADLE_CMD="/opt/gradle/bin/gradle"
        echo "Using Gradle from: /opt/gradle/bin/gradle (version $GRADLE_VERSION)"
    fi
fi

# If no suitable Gradle found, offer to install locally
if [ -z "$GRADLE_CMD" ]; then
    echo ""
    echo "ERROR: No suitable Gradle found!"
    echo ""
    echo "Ghidra 11.4.2 requires Gradle >= $MIN_GRADLE_MAJOR.$MIN_GRADLE_MINOR"
    echo ""

    # Check if we have install_gradle.sh script
    if [ -f "$SCRIPT_DIR/install_gradle.sh" ]; then
        if [ -t 0 ]; then
            read -p "Install Gradle 8.10.2 locally (no root required)? (y/n) " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                bash "$SCRIPT_DIR/install_gradle.sh"
                if [ -f "$SCRIPT_DIR/gradle/bin/gradle" ]; then
                    GRADLE_CMD="$SCRIPT_DIR/gradle/bin/gradle"
                    echo "Gradle installed successfully. Continuing with build..."
                else
                    echo "ERROR: Gradle installation failed."
                    exit 1
                fi
            else
                echo "Cannot continue without Gradle. Exiting."
                exit 1
            fi
        else
            echo "Non-interactive mode. Installing Gradle 8.10.2 locally..."
            bash "$SCRIPT_DIR/install_gradle.sh"
            if [ -f "$SCRIPT_DIR/gradle/bin/gradle" ]; then
                GRADLE_CMD="$SCRIPT_DIR/gradle/bin/gradle"
            else
                echo "ERROR: Gradle installation failed."
                exit 1
            fi
        fi
    else
        echo "You can download and install Gradle from: https://gradle.org/releases/"
        echo ""
        exit 1
    fi
fi

# Build using Gradle
$GRADLE_CMD -PGHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR" distributeExtension

echo ""
echo "========================================================================"
echo "Build complete!"
echo ""

# Find the output
DIST_FILE=$(ls -t dist/*.zip 2>/dev/null | head -1)
if [ -n "$DIST_FILE" ]; then
    echo "Extension package: $DIST_FILE"
    echo ""
    echo "To install:"
    echo "1. Unzip to $GHIDRA_INSTALL_DIR/Extensions/Ghidra/"
    echo "2. Restart Ghidra"
    echo "3. File → Configure → Check 'OptimizedVectorDecompiler'"
    echo ""
    echo "Or copy directly:"
    echo "    cp $DIST_FILE $GHIDRA_INSTALL_DIR/Extensions/Ghidra/"
else
    echo "Warning: Could not find output package in dist/"
fi
echo "========================================================================"
