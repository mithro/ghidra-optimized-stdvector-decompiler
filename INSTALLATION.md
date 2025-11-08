# Installation Guide

This guide covers both automatic and manual installation methods for the Optimized std::vector Decompiler plugin.

## Automatic Installation (Recommended)

The `setup.sh` script provides a fully automated installation process that handles all dependencies.

### Prerequisites

**Platform Requirements:**
- Ubuntu/Debian Linux (or compatible)
- sudo access (for Java installation only)
- ~500MB free disk space
- Internet connection

**Software (automatically installed if needed):**
- Java 21 or later
- Ghidra 11.4.2
- Gradle 8.0+ (installed locally by build script if needed)

### Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/ghidra-optimized-stdvector-decompiler.git
   cd ghidra-optimized-stdvector-decompiler
   ```

2. **Run the setup script:**
   ```bash
   ./setup.sh
   ```

3. **Follow the prompts:**
   - The script will detect missing dependencies
   - For Java: It will offer to install OpenJDK 21 via apt (requires sudo)
   - For Ghidra: It will offer to download and install Ghidra 11.4.2 to `~/ghidra`
   - The script will then build and install the extension automatically

4. **Start Ghidra:**
   ```bash
   $GHIDRA_INSTALL_DIR/ghidraRun
   ```

The extension is now active and ready to use!

### What the Setup Script Does

The `setup.sh` script automates the entire installation process:

1. **Environment Detection:**
   - Checks for existing Ghidra installation
   - Verifies Java version (requires Java 21+)
   - Detects available Gradle version

2. **Dependency Installation:**
   - **Java**: If not present or version < 21, offers to install OpenJDK 21 via apt
   - **Ghidra**: If not found, offers to download and install Ghidra 11.4.2 to `~/ghidra`
   - **Gradle**: Handled by `build.sh`, which installs Gradle 8.10.2 locally if needed

3. **Build Process:**
   - Compiles the Java extension using Gradle
   - Runs Ghidra's `buildExtension.gradle` build system
   - Generates the extension ZIP in `extension/dist/`

4. **Installation:**
   - Extracts extension to `$GHIDRA_INSTALL_DIR/Extensions/Ghidra/`
   - Copies JAR to `$GHIDRA_INSTALL_DIR/Ghidra/Features/Decompiler/lib/` for headless mode
   - Auto-enables the extension in Ghidra preferences

5. **Verification:**
   - Confirms all files are in place
   - Displays installation success message

## Manual Installation

If you prefer to install components manually or the automatic installation fails, follow these steps.

### Step 1: Install Java

**Check existing Java version:**
```bash
java -version
```

**If Java 21+ is not installed:**

On Ubuntu/Debian:
```bash
sudo apt update
sudo apt install -y openjdk-21-jdk
```

On other platforms, download from [Adoptium](https://adoptium.net/) or use your package manager.

### Step 2: Install Ghidra

**Option A: Download Manually**

1. Download Ghidra 11.4.2 from [ghidra-sre.org](https://ghidra-sre.org/)
2. Extract to your preferred location:
   ```bash
   unzip ghidra_11.4.2_PUBLIC_20241023.zip -d ~/
   export GHIDRA_INSTALL_DIR=~/ghidra_11.4.2_PUBLIC
   ```

**Option B: Use setup script for Ghidra only**

```bash
# Set environment to skip Java check
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
./setup.sh  # Answer 'n' to Java installation, 'y' to Ghidra
```

### Step 3: Build the Extension

```bash
cd extension
export GHIDRA_INSTALL_DIR=/path/to/ghidra  # Adjust path
./build.sh
```

The build script will:
- Check for Gradle 8.0+
- Offer to install Gradle 8.10.2 locally if needed
- Build the extension using Ghidra's build system
- Create ZIP file in `dist/` directory

### Step 4: Install the Extension

**Option A: Using Ghidra GUI**

1. Open Ghidra
2. Go to File → Install Extensions
3. Click the green "+" icon
4. Navigate to `extension/dist/` and select the ZIP file
5. Restart Ghidra
6. Verify in File → Configure → Extensions that "OptimizedVectorDecompiler" is checked

**Option B: Manual Installation**

```bash
# Extract to Ghidra Extensions directory
cd extension/dist
unzip OptimizedVectorDecompiler-*.zip -d $GHIDRA_INSTALL_DIR/Extensions/Ghidra/

# For headless mode support, also copy JAR:
cp $GHIDRA_INSTALL_DIR/Extensions/Ghidra/OptimizedVectorDecompiler/lib/OptimizedVectorDecompiler.jar \
   $GHIDRA_INSTALL_DIR/Ghidra/Features/Decompiler/lib/
```

### Step 5: Enable the Extension

**Option A: Via GUI**
1. Open Ghidra
2. File → Configure → Extensions
3. Check "OptimizedVectorDecompiler"
4. Restart Ghidra if prompted

**Option B: Manually edit preferences**

```bash
# Find your Ghidra user directory
GHIDRA_USER_DIR=~/.ghidra/.ghidra_11.4.2_PUBLIC

# Enable extension in preferences
echo "OptimizedVectorDecompiler=true" >> $GHIDRA_USER_DIR/preferences/ExtensionProvider
```

## Verification

### Test the Installation

1. **GUI Mode:**
   ```bash
   $GHIDRA_INSTALL_DIR/ghidraRun
   ```
   - Open a Windows executable
   - Analyze the binary
   - Open Decompiler window
   - Look for simplified vector operations

2. **Headless Mode:**
   ```bash
   cd examples/vector_test
   python test_transformation.py
   ```

   Expected output:
   ```
   ✓ Found 2 EMPTY patterns: vec->empty()
   ✓ Found 1 SIZE pattern: vec->size()
   ✓ Found 1 CAPACITY pattern: vec->capacity()
   ✓ Found 1 DATA pattern: vec->data()
   ```

### Check Installation Files

```bash
# Extension directory
ls $GHIDRA_INSTALL_DIR/Extensions/Ghidra/OptimizedVectorDecompiler

# Headless mode JAR
ls $GHIDRA_INSTALL_DIR/Ghidra/Features/Decompiler/lib/OptimizedVectorDecompiler.jar

# Check if enabled
grep OptimizedVectorDecompiler ~/.ghidra/.ghidra_11.4.2_PUBLIC/preferences/ExtensionProvider
```

## Troubleshooting

### Extension Not Loading

**Symptom:** Extension doesn't appear in File → Configure → Extensions

**Solutions:**

1. Check installation path:
   ```bash
   ls $GHIDRA_INSTALL_DIR/Extensions/Ghidra/OptimizedVectorDecompiler
   ```

2. Verify file permissions:
   ```bash
   chmod -R 755 $GHIDRA_INSTALL_DIR/Extensions/Ghidra/OptimizedVectorDecompiler
   ```

3. Check Ghidra logs:
   ```bash
   tail -f ~/.config/ghidra/ghidra_11.4.2_PUBLIC/application.log
   ```
   Look for errors related to "OptimizedVectorDecompiler"

4. Reinstall using GUI method (File → Install Extensions)

### Gradle Version Errors

**Symptom:** Build fails with `unexpected token: :` or similar syntax errors

**Cause:** Gradle version < 8.0

**Solution:** The `build.sh` script will automatically detect this and offer to install Gradle 8.10.2 locally:
```bash
cd extension
./build.sh
# Answer 'y' when prompted to install Gradle
```

### Java Version Issues

**Symptom:** Build fails with "UnsupportedClassVersionError" or "class file version" errors

**Cause:** Java version < 21

**Solution:**
```bash
# Check Java version
java -version

# Install Java 21 if needed
sudo apt install -y openjdk-21-jdk

# Set JAVA_HOME if you have multiple Java versions
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
```

### Patterns Not Detecting

**Symptom:** Vector patterns still show as raw pointer arithmetic

**Possible causes and solutions:**

1. **Binary not compiled with MSVC:**
   ```bash
   file binary.exe
   # Should show "PE32+ executable (console) x86-64"
   ```
   This plugin only supports MSVC-compiled binaries.

2. **Extension not enabled:**
   - File → Configure → Extensions
   - Ensure "OptimizedVectorDecompiler" is checked
   - Restart Ghidra

3. **No type information:**
   - The plugin works best with PDB debug symbols
   - Try analyzing with PDB file in same directory as executable
   - Pattern detection may be limited without type info

4. **Test with known-good binary:**
   ```bash
   cd examples/vector_test
   python test_transformation.py
   ```
   If test binaries work, the issue is with your target binary.

### Headless Mode Not Working

**Symptom:** Patterns not simplified in headless analysis scripts

**Cause:** JAR not copied to Decompiler lib directory

**Solution:**
```bash
cp $GHIDRA_INSTALL_DIR/Extensions/Ghidra/OptimizedVectorDecompiler/lib/OptimizedVectorDecompiler.jar \
   $GHIDRA_INSTALL_DIR/Ghidra/Features/Decompiler/lib/
```

### Permission Denied Errors

**Symptom:** Cannot write to Ghidra installation directory

**Solutions:**

1. **Run setup script normally** (only requires sudo for Java installation)
2. **If Ghidra is in system directory:**
   ```bash
   sudo chown -R $USER:$USER $GHIDRA_INSTALL_DIR
   ```
3. **Or install Ghidra to user directory:**
   ```bash
   export GHIDRA_INSTALL_DIR=~/ghidra_11.4.2_PUBLIC
   ```

## Uninstallation

To remove the extension:

1. **Via Ghidra GUI:**
   - File → Configure → Extensions
   - Uncheck "OptimizedVectorDecompiler"
   - Click the red "-" button to remove

2. **Manual removal:**
   ```bash
   rm -rf $GHIDRA_INSTALL_DIR/Extensions/Ghidra/OptimizedVectorDecompiler
   rm -f $GHIDRA_INSTALL_DIR/Ghidra/Features/Decompiler/lib/OptimizedVectorDecompiler.jar
   ```

3. **Remove from preferences:**
   ```bash
   # Edit this file and remove the OptimizedVectorDecompiler line:
   nano ~/.ghidra/.ghidra_11.4.2_PUBLIC/preferences/ExtensionProvider
   ```

## Advanced Configuration

### Using Different Ghidra Versions

The plugin is developed for Ghidra 11.4.2 but may work with other 11.x versions:

1. Set `GHIDRA_INSTALL_DIR` to your Ghidra version
2. Update `extension.properties` if API changes are needed
3. Rebuild and test thoroughly

### Building for Distribution

To create a redistributable extension:

```bash
cd extension
export GHIDRA_INSTALL_DIR=/path/to/ghidra
./build.sh
```

The ZIP file in `extension/dist/` can be shared and installed via Ghidra's GUI.

### Development Setup

For plugin development:

1. Install Ghidra and extension as above
2. Import `extension/` as Gradle project in your IDE
3. Set GHIDRA_INSTALL_DIR environment variable
4. Use `./build.sh` for incremental builds
5. Test changes: copy JAR and restart Ghidra

See [CLAUDE.md](CLAUDE.md) for development guidance.

## Getting Help

If you encounter issues not covered here:

1. Check the [GitHub Issues](https://github.com/YOUR_USERNAME/ghidra-optimized-stdvector-decompiler/issues)
2. Review [CLAUDE.md](CLAUDE.md) for troubleshooting tips
3. Run test suite to isolate the problem:
   ```bash
   cd examples/vector_test
   python test_transformation.py
   ```
4. Check Ghidra logs for detailed error messages
5. Open a new issue with:
   - Your platform and versions (Java, Ghidra, OS)
   - Full error message and logs
   - Steps to reproduce
