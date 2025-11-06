# Ghidra Setup Guide

This guide explains how to set up Ghidra with all modules and the custom VectorSimplification extension.

## Quick Start

Run the automated setup script:

```bash
./setup_ghidra.sh
```

This will:
1. Check if Ghidra is installed (optionally download and install if missing)
2. Verify Java installation
3. Create necessary user directories
4. Build the VectorSimplification extension
5. Install the extension to Ghidra
6. Verify the installation

## Requirements

- **Java 17 or later**: `sudo apt-get install openjdk-21-jdk`
- **Gradle** (included with the project)
- **wget** or **curl** (for downloading Ghidra if needed)
- **unzip** (for extracting archives)

## Manual Installation

If you prefer manual installation:

### 1. Install Ghidra

Download Ghidra 11.4.2 from:
https://github.com/NationalSecurityAgency/ghidra/releases

Extract to `/root/tools/ghidra/` (or set `GHIDRA_INSTALL_DIR`)

### 2. Build VectorSimplification Extension

```bash
cd tools/ghidra_extensions/VectorSimplification
export GHIDRA_INSTALL_DIR=/root/tools/ghidra
bash build.sh
```

### 3. Install Extension

**Option A: System-wide installation**
```bash
unzip dist/ghidra_11.4.2_PUBLIC_*_VectorSimplification.zip -d $GHIDRA_INSTALL_DIR/Extensions/Ghidra/
```

**Option B: User installation**
```bash
unzip dist/ghidra_11.4.2_PUBLIC_*_VectorSimplification.zip -d ~/.ghidra/.ghidra_11.4.2_PUBLIC/Extensions/
```

### 4. Install JAR for Headless Mode

For headless analysis support:
```bash
cp build/libs/VectorSimplification.jar $GHIDRA_INSTALL_DIR/Ghidra/Features/Decompiler/lib/
```

### 5. Enable Extension in Ghidra

1. Launch Ghidra: `$GHIDRA_INSTALL_DIR/ghidraRun`
2. Go to: **File → Configure**
3. Check: **VectorSimplification**
4. Restart Ghidra

## Configuration

### Environment Variables

- `GHIDRA_INSTALL_DIR`: Ghidra installation directory (default: `/root/tools/ghidra`)
- `GHIDRA_VERSION`: Ghidra version to install (default: `11.4.2`)
- `GHIDRA_RELEASE`: Release build date (default: `20250826`)

Example:
```bash
export GHIDRA_INSTALL_DIR=/opt/ghidra
./setup_ghidra.sh
```

### Extension Configuration

The VectorSimplification extension is configured via:
- Module.manifest: Extension metadata
- extension.properties: Extension properties
- build.gradle: Build configuration

## Usage

### GUI Mode

1. Open Ghidra
2. Create/open a project
3. Import a binary (e.g., `vector_test_msvc.exe`)
4. Analyze with default analyzers
5. Open the decompiler - vector patterns will be automatically simplified

### Headless Mode

```bash
$GHIDRA_INSTALL_DIR/support/analyzeHeadless \
    /tmp/ghidra_project \
    TestProject \
    -import vector_test_msvc.exe \
    -postScript test_transformation.py
```

### Testing

Test the extension with the provided test binary:

```bash
cd test/vector_test
python test_transformation.py
```

Expected output:
- 2 EMPTY patterns: `vec->empty()`
- 1 SIZE pattern: `vec->size()`
- 1 CAPACITY pattern: `vec->capacity()`
- 1 DATA pattern: `vec->data()`

## Extension Features

The **VectorSimplification** extension detects and simplifies MSVC `std::vector` patterns:

### Supported Patterns

| Pattern | Decompiled Code | Simplified |
|---------|----------------|------------|
| **SIZE** | `(_Mylast - _Myfirst) >> N` | `vec->size()` |
| **EMPTY** | `_Myfirst == _Mylast` | `vec->empty()` |
| **CAPACITY** | `(_Myend - _Myfirst) >> N` | `vec->capacity()` |
| **DATA** | `*_Myfirst` (when dereferenced) | `vec->data()` |

### Implementation Details

- **Pattern Matching**: Analyzes Pcode operations to identify vector member access
- **Context-Aware**: DATA pattern only matches when pointer is actually dereferenced
- **AST Rewriting**: Uses ClangTokenGroup to transform decompiled output
- **Varnode Tracing**: Traces through CAST/COPY/MULTIEQUAL operations to find source variables

## Troubleshooting

### Extension Not Appearing

1. Check installation:
   ```bash
   ls $GHIDRA_INSTALL_DIR/Extensions/Ghidra/VectorSimplification
   ```

2. Check Module.manifest:
   ```bash
   cat $GHIDRA_INSTALL_DIR/Extensions/Ghidra/VectorSimplification/Module.manifest
   ```

3. Check Ghidra logs:
   ```bash
   tail -f ~/.config/ghidra/ghidra_11.4.2_PUBLIC/application.log
   ```

### Headless Mode Not Working

1. Verify JAR installation:
   ```bash
   ls $GHIDRA_INSTALL_DIR/Ghidra/Features/Decompiler/lib/VectorSimplification.jar
   ```

2. Rebuild and reinstall:
   ```bash
   cd tools/ghidra_extensions/VectorSimplification
   bash build.sh
   cp build/libs/VectorSimplification.jar $GHIDRA_INSTALL_DIR/Ghidra/Features/Decompiler/lib/
   ```

### Build Errors

1. Check Java version:
   ```bash
   java -version  # Should be 17 or later
   ```

2. Check Gradle:
   ```bash
   cd tools/ghidra_extensions/VectorSimplification
   ./gradlew --version
   ```

3. Clean and rebuild:
   ```bash
   ./gradlew clean buildExtension
   ```

### Pattern Not Detecting

1. Enable debug output:
   - The extension prints debug info to stderr
   - Check terminal output when running headless

2. Verify binary uses MSVC std::vector:
   - Pattern detection only works with MSVC implementation
   - Uses offsets: _Myfirst (0x0), _Mylast (0x8), _Myend (0x10)

## Optional Plugins

Additional Ghidra plugins are available in `tools/plugin_installers/`:

- **GhidraGPT**: AI-powered analysis assistant
- **DAILA**: Deep learning for binary analysis
- **ret-sync**: Synchronization with debuggers

Install individual plugins:
```bash
cd tools/plugin_installers/ghidragpt
./install_ghidragpt.sh
```

## Development

### Building from Source

```bash
cd tools/ghidra_extensions/VectorSimplification
gradle -PGHIDRA_INSTALL_DIR=/path/to/ghidra buildExtension
```

### Running Tests

```bash
cd test/vector_test
# Run analysis
$GHIDRA_INSTALL_DIR/support/analyzeHeadless /tmp/test TestProject \
    -import vector_test_msvc.exe \
    -postScript test_transformation.py
```

### Debugging

Add debug output to VectorPatternMatcher.java:
```java
System.err.println("Debug: " + varnode);
```

Rebuild and check stderr output.

## References

- [Ghidra Documentation](https://ghidra-sre.org/)
- [Extension Development Guide](https://ghidra.re/ghidra_docs/api/)
- [VectorSimplification Source](tools/ghidra_extensions/VectorSimplification/)
- [Test Binaries](test/vector_test/)

## License

See [LICENSE](LICENSE) for details.
