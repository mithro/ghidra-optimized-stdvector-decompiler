# Vector Simplification Demo

This directory contains demo programs and test binaries that demonstrate the Ghidra VectorSimplification extension's ability to transform optimized MSVC std::vector pointer arithmetic into readable C++ method calls.

## Quick Start

```bash
# 1. One-time setup (downloads ~2.7GB, requires ~9GB disk space)
cd demo
./setup_build_env.sh

# 2. Verify environment
make check-env

# 3. Build demo binaries
make

# 4. Create Ghidra projects
export GHIDRA_INSTALL_DIR=/path/to/ghidra
make ghidra-projects

# 5. Run verification test
cd ..
python3 test.py
```

## Demo Binaries

Two C++ programs demonstrate different pattern coverage levels:

### vector_basic.cpp
Simple demonstration with 6 test functions covering core patterns:
- `size()` - Size calculation: `(_Mylast - _Myfirst) >> 2`
- `empty()` - Empty check: `_Mylast == _Myfirst`
- `data()` - Data pointer: `_Myfirst`
- `capacity()` - Capacity calculation: `(_Myend - _Myfirst) >> 2`

Perfect for quick validation and understanding the basic transformations.

### vector_extra.cpp
Comprehensive demonstration with 18 test functions covering all patterns:
- All basic patterns from vector_basic
- `reserve()`, `resize()`, `push_back()`, `pop_back()`, `clear()`
- `front()`, `back()`, indexing, iterators
- `shrink_to_fit()`, `swap()`, assignment
- Complex multi-pattern operations
- Nested struct with vector member

Represents real-world optimized code patterns found in production binaries.

### Build Configurations

Each source file is built in **two configurations** for comparison:

| Suffix | Optimization | Purpose |
|--------|-------------|---------|
| `_O2` | `/O2` (Release) | **Primary demo**: Shows pointer arithmetic patterns that the extension simplifies |
| `_Od` | `/Od` (Debug) | **Comparison**: Shows high-level C++ calls without inlining |

**Example binaries:**
- `vector_basic_O2.exe` - Optimized, shows `(field_0x10 - field_0x8) >> 2` patterns
- `vector_basic_Od.exe` - Debug, shows `std::vector::size()` calls directly
- `vector_extra_O2.exe` - Main test binary used by test.py
- `vector_extra_Od.exe` - Debug comparison version

Each binary includes:
- Windows PE32+ executable (`.exe`)
- Full debug symbols (`.pdb`)
- Ghidra project (`.gpr` + `.rep/` directory)

## Why Optimizations Matter

**The extension is designed for optimized production binaries.** Here's why:

### Without Optimizations (`/Od` - Debug build)
```cpp
// Ghidra decompilation shows:
size_t size = vec.size();  // High-level method call
```
- Compiler doesn't inline vector methods
- Ghidra decompiles to readable C++ method calls
- **Extension has nothing to simplify**
- Not representative of production code

### With Optimizations (`/O2` - Release build)
```cpp
// Ghidra decompilation shows:
size_t size = (vec._Mylast - vec._Myfirst) >> 2;  // Pointer arithmetic
// OR in binaries without debug symbols:
size_t size = (field_0x10 - field_0x8) >> 2;
```
- Compiler inlines vector methods into pointer arithmetic
- Ghidra shows raw field offsets and bit shifts
- **Extension transforms this back to `vec->size()`**
- Matches real production binaries

This is exactly what appears in optimized shipping binaries, making the extension valuable for reverse engineering.

## Build System

### Makefile Targets

```bash
# Build targets
make all              # Build all binaries (default)
make optimized        # Build only _O2 versions (faster)
make debug            # Build only _Od versions
make basic            # Build vector_basic binaries
make extra            # Build vector_extra binaries

# Ghidra integration
make ghidra-projects  # Generate Ghidra projects for all binaries
make test             # Run pattern analysis

# Maintenance
make check-env        # Verify build environment
make clean            # Remove build artifacts
make clean-ghidra     # Remove Ghidra projects
make distclean        # Remove everything
make help             # Show all targets
```

### Environment Variables

The Makefile respects these environment variables:

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra  # Required for ghidra-projects, test
export MSVC_DIR=$HOME/.msvc                # MSVC headers location (default: ~/.msvc)
export CLANG_CL=clang-cl-19                # Compiler (default: clang-cl-19)
```

## Analysis Scripts

Located in `scripts/`:

| Script | Purpose |
|--------|---------|
| `analyze_patterns.py` | Main analysis: counts SIZE/EMPTY/CAPACITY/DATA transformations |
| `show_details.py` | Shows detailed decompilation for specific functions |
| `list_functions.py` | Lists all functions in binary |

Run in Ghidra headless mode:
```bash
$GHIDRA_INSTALL_DIR/support/analyzeHeadless \
    . TempProject \
    -import vector_extra_O2.exe \
    -postScript scripts/analyze_patterns.py
```

## Expected Results

When analyzing `vector_extra_O2.exe` with the VectorSimplification extension, you should see approximately:

- **SIZE patterns**: 5+ transformations to `vec->size()`
- **EMPTY patterns**: 7+ transformations to `vec->empty()`
- **CAPACITY patterns**: 7+ transformations to `vec->capacity()`
- **DATA patterns**: 2+ transformations to `vec->data()`

See `../test.py` for automated verification.

## Pattern Coverage Details

### Size Calculation
```cpp
// Before: (vec._Mylast - vec._Myfirst) >> 2
// After:  vec->size()
```
Appears in: `TestVectorSize`, `SumIfNotEmpty`, `TestComplexOperations`, etc.

### Empty Check
```cpp
// Before: vec._Mylast == vec._Myfirst
// After:  vec->empty()
```
Appears in: `TestVectorEmpty`, `SumIfNotEmpty`, `TestVectorFront`, etc.

### Capacity Calculation
```cpp
// Before: (vec._Myend - vec._Myfirst) >> 2
// After:  vec->capacity()
```
Appears in: `TestVectorCapacity`, `TestVectorReserve`, `TestComplexOperations`, etc.

### Data Pointer
```cpp
// Before: vec._Myfirst (when dereferenced)
// After:  vec->data()
```
Appears in: `TestVectorData`, `TestComplexOperations`

## MSVC std::vector Layout

The extension specifically recognizes MSVC's internal std::vector structure:

```cpp
template<typename T>
class std::vector {
    T* _Myfirst;  // offset 0x0  - pointer to first element
    T* _Mylast;   // offset 0x8  - pointer past last element
    T* _Myend;    // offset 0x10 - pointer to end of capacity
};
```

This layout differs from GCC/Clang implementations, which is why MSVC-compatible binaries are required.

## Build Methods

Multiple approaches for setting up the build environment are available in `build_environments/`:

| Method | Setup Script | CI-Friendly | Speed | Pros | Cons |
|--------|-------------|-------------|-------|------|------|
| **clang-cl + xwin** | `setup_clangcl.sh` | ✅ Yes | Fast | Reproducible, no Wine | 3GB download |
| **msvc-wine** | `setup_msvc_wine.sh` | ✅ Yes | Slow | Real MSVC | Wine overhead |
| **winetricks** | `setup_msvc_winetricks.sh` | ❌ No | Medium | Official | GUI required |

See `build_environments/README.md` for detailed comparison and instructions.

The default `./setup_build_env.sh` uses the clang-cl + xwin method (fast and CI-friendly).

## Binary Details

All binaries are built with:
- **Compiler**: clang-cl-19 in MSVC-compatible mode
- **MSVC Version**: 14.44.35207
- **Windows SDK**: 10.0.26100.0
- **Architecture**: PE32+ executable (64-bit Windows)
- **Debug Info**: Full PDB symbols
- **std::vector Layout**: MSVC layout with correct offsets

Optimized builds use `/O2 /OPT:REF /OPT:ICF` to match production binary optimization levels.

## Troubleshooting

### Build fails with "MSVC headers not found"
```bash
./setup_build_env.sh  # Downloads MSVC toolchain
make check-env        # Verify installation
```

### "clang-cl-19: command not found"
```bash
./setup_build_env.sh  # Installs clang-19
```

### Ghidra projects fail to generate
```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
make check-env
```

### Extension doesn't detect patterns
- Verify you're analyzing `*_O2.exe` (optimized), not `*_Od.exe` (debug)
- Ensure VectorSimplification extension is installed and enabled
- Check that extension JAR is in `$GHIDRA_INSTALL_DIR/Ghidra/Features/Decompiler/lib/`

## Related Files

- `../test.py` - Top-level test that validates extension functionality
- `../CLAUDE.md` - Project overview and development guide
- `../docs/INSTALLATION.md` - Extension installation instructions
- `build_environments/README.md` - Detailed build method comparison
