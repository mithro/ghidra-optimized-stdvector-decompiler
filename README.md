# Optimized std::vector Decompiler - Ghidra Plugin

A Ghidra plugin which improves the decompilation output of std::vectors in binaries that are compiled with optimization on (Currently MSVC++ focused).

## Overview

When decompiling optimized Windows C++ binaries compiled with MSVC, aggressive compiler optimizations transform high-level `std::vector` operations into complex pointer arithmetic. Ghidra's decompiler output shows these low-level patterns instead of the original clean vector operations, making reverse engineering significantly harder.

**Before (Raw Decompiled Output):**
```c
if ((_Mylast - _Myfirst) >> 3 == 0) {  // What does this mean?
    doSomething();
}
value = *_Myfirst;  // Direct pointer access
capacity = (_Myend - _Myfirst) >> 3;
```

**After (With Optimized Vector Decompiler):**
```c
if (vec->empty()) {  // Much clearer!
    doSomething();
}
value = vec->data();
capacity = vec->capacity();
```

This plugin automatically detects and transforms these optimized patterns back into readable C++ method calls, dramatically improving the decompilation quality for reverse engineering optimized binaries.

## Features

### Supported Patterns

| Pattern | Raw MSVC Code | Simplified Output |
|---------|---------------|-------------------|
| **SIZE** | `(_Mylast - _Myfirst) >> N` | `vec->size()` |
| **EMPTY** | `_Myfirst == _Mylast` | `vec->empty()` |
| **CAPACITY** | `(_Myend - _Myfirst) >> N` | `vec->capacity()` |
| **DATA** | `*_Myfirst` (when dereferenced) | `vec->data()` |

### Key Capabilities

- **Automatic Pattern Detection**: Analyzes P-code operations to identify vector member access
- **Context-Aware**: Only matches when patterns are actually used (e.g., DATA only when pointer is dereferenced)
- **AST Rewriting**: Uses ClangTokenGroup to transform decompiled output cleanly
- **Varnode Tracing**: Traces through CAST/COPY/MULTIEQUAL operations to find source variables
- **Both GUI and Headless**: Works in Ghidra GUI and headless analysis mode

## Quick Start

### Prerequisites

- **Ghidra 11.4.2** (or compatible version)
- **Java 21** or later
- **Gradle 8.0+** (automatically installed if needed)

### Installation

1. **Clone this repository:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/ghidra-optimized-stdvector-decompiler.git
   cd ghidra-optimized-stdvector-decompiler
   ```

2. **Run the setup script:**
   ```bash
   ./setup.sh
   ```

   The script will:
   - Check dependencies (Java, Gradle)
   - Build the extension
   - Install to Ghidra
   - **Automatically enable the extension** (no manual configuration needed!)

3. **Start using Ghidra:**
   ```bash
   $GHIDRA_INSTALL_DIR/ghidraRun
   ```

The extension is now active and will automatically simplify vector patterns!

## Manual Installation

If you prefer to build and install manually, see [INSTALLATION.md](INSTALLATION.md) for detailed instructions.

## Usage

### GUI Mode

1. Open Ghidra and load a Windows executable
2. Analyze the binary (use default analyzers)
3. Open the Decompiler window
4. Vector patterns are automatically simplified!

### Headless Mode

```bash
$GHIDRA_INSTALL_DIR/support/analyzeHeadless \
    /path/to/project ProjectName \
    -import binary.exe \
    -postScript your_analysis_script.py
```

The extension works automatically in headless mode too.

## Examples

See the [examples/vector_test](examples/vector_test) directory for:
- **Test C++ programs** that demonstrate all supported patterns
- **Pre-compiled binaries** (MSVC) for immediate testing
- **Python test scripts** to verify the extension works
- **Analysis scripts** showing detected patterns

### Quick Test

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

## How It Works

The extension works by:

1. **P-code Analysis**: Intercepts the decompilation process to analyze P-code operations
2. **Pattern Recognition**: Identifies MSVC std::vector member access patterns:
   - Recognizes `_Myfirst`, `_Mylast`, `_Myend` structure members
   - Detects pointer arithmetic operations (subtraction, shifts)
   - Validates context (e.g., dereferencing for DATA pattern)

3. **AST Transformation**: Rewrites the ClangTokenGroup tree to replace matched patterns with clean method calls

4. **Output Generation**: Returns simplified C code to the decompiler

For implementation details, see:
- [extension/src/main/java/vectorsimplify/VectorPatternMatcher.java](extension/src/main/java/vectorsimplify/VectorPatternMatcher.java)
- [extension/src/main/java/vectorsimplify/ClangTokenRewriter.java](extension/src/main/java/vectorsimplify/ClangTokenRewriter.java)

## Building from Source

```bash
cd extension
export GHIDRA_INSTALL_DIR=/path/to/ghidra
./build.sh
```

The built extension will be in `extension/dist/`.

For more details, see [INSTALLATION.md](INSTALLATION.md).

## Troubleshooting

### Extension not appearing in Ghidra

1. Check installation:
   ```bash
   ls $GHIDRA_INSTALL_DIR/Extensions/Ghidra/OptimizedVectorDecompiler
   ```

2. Verify it's enabled:
   - File → Configure → Extensions
   - Check that "OptimizedVectorDecompiler" is checked

3. Check logs:
   ```bash
   tail -f ~/.config/ghidra/ghidra_11.4.2_PUBLIC/application.log
   ```

### Gradle version errors

If you see `unexpected token: :` errors, your Gradle is too old (<  8.0). The build script will offer to install Gradle 8.10.2 locally.

### Patterns not detecting

- Verify the binary was compiled with **MSVC** (not GCC/Clang)
- Check that you're analyzing a Windows executable
- Try running test binaries in `examples/vector_test/` first

For more help, see [INSTALLATION.md](INSTALLATION.md#troubleshooting).

## Contributing

Contributions are welcome! Areas for improvement:

- Support for other STL containers (list, map, etc.)
- Support for GCC/Clang implementations of std::vector
- Additional vector operations (push_back, pop_back, etc.)
- Performance optimizations

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

This is the same license as Ghidra itself.

## Acknowledgments

- Built for the [Ghidra](https://ghidra-sre.org/) reverse engineering framework
- Developed as part of the binary analysis project
- Inspired by the need for better C++ decompilation in Ghidra

## Resources

- [Ghidra Documentation](https://ghidra-sre.org/)
- [Ghidra Extension Development](https://ghidra.re/ghidra_docs/api/)
- [Installation Guide](INSTALLATION.md)
