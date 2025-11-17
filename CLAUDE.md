# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Ghidra plugin that improves decompilation output for **optimized** Windows C++ binaries compiled with MSVC. It automatically detects and transforms std::vector pointer arithmetic patterns into readable C++ method calls (e.g., `(_Mylast - _Myfirst) >> 3` becomes `vec->size()`).

**Key Transformation Examples:**
- SIZE: `(_Mylast - _Myfirst) >> N` → `vec->size()`
- EMPTY: `_Myfirst == _Mylast` → `vec->empty()`
- CAPACITY: `(_Myend - _Myfirst) >> N` → `vec->capacity()`
- DATA: `*_Myfirst` (when dereferenced) → `vec->data()`

**CRITICAL TESTING REQUIREMENT:**
- **MUST** test against O2 (optimized) binaries (`*_O2.exe`), NOT Od (debug) binaries
- The extension is specifically designed to work on OPTIMIZED code where patterns are present
- Do NOT switch tests to use Od binaries as a workaround - fix the extension to work with O2
- Debug binaries have different code generation and are not representative of real-world use cases

## Project Structure

```
extension/                   # Main Ghidra extension
  src/main/java/vectorsimplify/
    VectorPatternMatcher.java      # P-code analysis and pattern detection
    ClangTokenRewriter.java        # AST rewriting to transform output
    VectorSimplifyingDecompiler.java  # Main decompiler interface
    VectorSimplificationPlugin.java   # Ghidra GUI plugin
    VectorPattern.java             # Pattern representation
    VectorPatternType.java         # Pattern type enum
  build.gradle                # Gradle build configuration
  build.sh                   # Build script with Gradle version detection
  extension.properties        # Extension metadata

demo/                         # Demo binaries and analysis scripts
  *.cpp                       # C++ demo programs demonstrating patterns
  scripts/*.py                # Python Ghidra headless analysis scripts
  *.exe                       # Pre-compiled MSVC demo binaries
  build_setup/                # Build environment setup scripts

docs/
  INSTALLATION.md            # Detailed installation guide

setup.sh                     # Automated one-step setup script
```

## Build Commands

### Build the Extension
```bash
cd extension
export GHIDRA_INSTALL_DIR=/path/to/ghidra  # or set in environment
./build.sh
```

The build script automatically:
- Detects suitable Gradle version (requires 8.0+)
- Offers to install Gradle 8.10.2 locally if needed
- Builds the extension using Ghidra's buildExtension.gradle

### Build Demo Binaries

**Clone with submodule:**
```bash
git clone --recurse-submodules git@github.com:mithro/ghidra-optimized-stdvector-decompiler.git
# OR if already cloned:
git submodule update --init
```

**Build with default compiler (clang-19):**
```bash
cd demo
make
```

**Build with specific compiler:**
```bash
make COMPILER=clang-20 all
make COMPILER=msvc-14.44 optimized
```

**List available compilers:**
```bash
make list-compilers
```

Binaries are output to `demo/out/{compiler}/` directory.

### One-Step Setup (Recommended)
```bash
./setup.sh
```

This script:
1. Checks for Ghidra installation
2. Verifies Java version
3. Builds the extension
4. Installs to Ghidra Extensions directory
5. Copies JAR to Decompiler lib for headless mode
6. Auto-enables the extension in preferences

## Testing

### Run Test Suite
```bash
python3 test.py
```

Expected output shows detected patterns:
- 5+ SIZE patterns: `vec->size()`
- 7+ EMPTY patterns: `vec->empty()`
- 7+ CAPACITY patterns: `vec->capacity()`
- 2+ DATA patterns: `vec->data()`

### Headless Analysis
```bash
$GHIDRA_INSTALL_DIR/support/analyzeHeadless \
    /tmp/demo_project DemoProject \
    -import demo/vector_extra_O2.exe \
    -postScript demo/scripts/analyze_patterns.py
```

## Architecture

### Pattern Detection Flow

1. **P-code Analysis** (VectorPatternMatcher.java)
   - Intercepts decompilation at P-code level
   - Iterates through all PcodeOpAST operations
   - Identifies MSVC std::vector member offsets:
     - `_Myfirst` at offset 0x0
     - `_Mylast` at offset 0x8
     - `_Myend` at offset 0x10

2. **Pattern Matching**
   - SIZE: Looks for `INT_RIGHT` with `INT_SUB(_Mylast, _Myfirst)` input
   - EMPTY: Looks for `INT_EQUAL(_Myfirst, _Mylast)`
   - CAPACITY: Looks for `INT_RIGHT` with `INT_SUB(_Myend, _Myfirst)` input
   - DATA: Looks for `LOAD(_Myfirst)` when result is dereferenced

3. **Varnode Tracing**
   - Traces through CAST/COPY/MULTIEQUAL operations
   - Finds source variables with type information
   - Validates that base varnodes have std::vector type
   - Uses `traceToSourceVariable()` to reach original variable
   - Checks `isVectorType()` using Ghidra's type information to prevent false positives

4. **AST Rewriting** (ClangTokenRewriter.java)
   - Receives ClangTokenGroup tree from decompiler
   - Walks AST to find nodes corresponding to matched patterns
   - Replaces matched subtrees with method call syntax
   - Preserves surrounding code structure

5. **Integration**
   - VectorSimplifyingDecompiler extends DecompInterface
   - Overrides `decompileFunction()` to inject pattern analysis
   - Caches simplified code per function
   - Plugin (VectorSimplificationPlugin) registers decompiler with Ghidra

### Type Safety

The matcher uses strict type checking to avoid false positives:
- Only matches patterns where base varnode has confirmed std::vector type
- Checks type name for "vector<", "Vector_val", or namespace path
- Rejects patterns if type information is missing
- Many structs use similar offsets (0x8, 0x10, 0x18), so type validation is critical

### Context-Aware Matching

DATA pattern only matches when pointer is actually used:
- `isUsedAsPointer()` recursively checks descendants
- Matches if used in LOAD/STORE address operand
- Matches if used in PTRADD/PTRSUB pointer arithmetic
- Matches if used as function call argument
- Traces through CAST/COPY/MULTIEQUAL to find actual usage
- Prevents false positives for iterator assignment

## Requirements

**Note:** The `setup.sh` script automatically installs Java and Ghidra if not present.

- **Ghidra**: 11.4.2 (auto-installed by setup.sh if needed)
- **Java**: 21 or later (auto-installed by setup.sh if needed)
- **Gradle**: 8.0+ (auto-installed locally by build.sh if needed)
- **Target Binaries**: MSVC-compiled Windows executables (64-bit)
- **Type Information**: PDB debug symbols recommended for best results

## Common Development Tasks

### Adding New Pattern Types

1. Add enum to `VectorPatternType.java`
2. Implement `match*Pattern()` method in `VectorPatternMatcher.java`
3. Call new matcher from `findVectorPatterns()`
4. Update `ClangTokenRewriter.java` to handle new pattern in AST transformation

### Debugging Pattern Detection

The matcher writes verbose debug output to stderr:
- Look for `matchSizePattern checking shift:`
- Look for `>>> MATCHED * PATTERN!` success messages
- Check `/tmp/vector_matcher_called.txt` for call counts
- Run headless scripts to capture full stderr output

### Testing Changes

1. Modify Java source
2. Run `cd extension && ./build.sh`
3. Copy JAR: `cp build/libs/OptimizedVectorDecompiler.jar $GHIDRA_INSTALL_DIR/Ghidra/Features/Decompiler/lib/`
4. Test: `python3 test.py`

## Known Limitations

- **MSVC-only**: Currently only supports MSVC std::vector implementation
  - Uses specific offsets: _Myfirst(0x0), _Mylast(0x8), _Myend(0x10)
  - GCC/Clang use different internal structure
- **64-bit binaries**: Offsets assume 8-byte pointers
- **Type information**: Works best with PDB debug symbols
  - Can still detect patterns without PDB, but validation is weaker
- **Windows binaries**: Focused on Windows PE executables

## Troubleshooting

### Extension Not Loading
```bash
# Check installation
ls $GHIDRA_INSTALL_DIR/Extensions/Ghidra/OptimizedVectorDecompiler

# Check Ghidra logs
tail -f ~/.config/ghidra/ghidra_11.4.2_PUBLIC/application.log

# Verify enabled
grep OptimizedVectorDecompiler ~/.ghidra/.ghidra_11.4.2_PUBLIC/preferences/ExtensionProvider
```

### Gradle Version Errors
If you see `unexpected token: :` errors, your Gradle is too old (< 8.0).
Run `cd extension && ./build.sh` and accept the prompt to install Gradle 8.10.2 locally.

### Patterns Not Detecting
- Verify binary compiled with MSVC: `file binary.exe`
- Check that analysis includes PDB symbols if available
- Run test binaries first: `python3 test.py`
- Check stderr for matcher debug output
- Enable verbose logging to see which patterns are being checked
