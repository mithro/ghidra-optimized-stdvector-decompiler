# MSVC Vector Test Binary

This directory contains a test program for verifying the Ghidra VectorSimplification extension works correctly with MSVC-compiled binaries.

## Files

- `vector_test.cpp` - C++ test program with std::vector operations
- `vector_test_msvc.exe` - Compiled Windows PE32+ executable
- `vector_test_msvc.pdb` - Debug symbols (PDB format)
- `BUILD_OPTIONS.md` - Documentation of various MSVC build approaches

## Building

### Quick Start

From the repository root, run:

```bash
./build_msvc_binary.sh
```

This script will:
1. Download MSVC 14.44 headers and Windows SDK 10.0.26100 (~2.7 GB)
2. Install clang-19 with lld-link
3. Compile `vector_test.cpp` to a Windows PE executable with PDB symbols

**Requirements:**
- Ubuntu 24.04 or similar (for clang-19 in apt repos)
- ~9 GB disk space
- Internet connection for downloads

**Time:** First run takes 15-30 minutes (subsequent runs are faster if toolchain is cached)

### What Gets Built

The resulting binary:
- **Format:** PE32+ executable (64-bit Windows)
- **Compiler:** clang-cl-19 in MSVC-compatible mode
- **MSVC Version:** 14.44.35207
- **Windows SDK:** 10.0.26100.0
- **Optimization:** `/O2 /OPT:REF /OPT:ICF` (Release build with optimizations)
- **Debug Info:** Full PDB symbols (`/Zi /DEBUG:FULL`)
- **std::vector Layout:** MSVC layout with `_Myfirst`, `_Mylast`, `_Myend` at offsets 0x8, 0x10, 0x18
- **Binary Size:** 16KB exe, 540KB PDB

### Why Optimizations Matter

**Critical: The binary MUST be compiled with optimizations enabled (`/O2`)** to match real-world binaries like production binaries.

**Without optimizations (Debug build):**
- Ghidra shows high-level C++ method calls: `std::vector::size()`, `std::vector::empty()`
- VectorSimplification extension has nothing to simplify
- Not representative of production binaries

**With optimizations (Release build):**
- Compiler inlines vector methods, showing raw pointer arithmetic
- Ghidra shows patterns like: `(vec._Mylast - vec._Myfirst) >> 2`
- This matches production binaries's decompilation: `(field_0x10 - field_0x8) >> 2`
- VectorSimplification extension can detect and simplify these patterns

**Why MSVC-compatible compilation matters:**
The Ghidra VectorSimplification extension specifically recognizes MSVC's std::vector internal structure. GCC and Clang use different layouts, so we need an actual MSVC-compatible binary for testing.

## Test Program

The test program (`vector_test.cpp`) is a comprehensive test suite covering **all 10 pointer arithmetic patterns** found in production binaries. See `PATTERN_COVERAGE.md` for detailed analysis.

### Test Functions (18 functions total):

**Basic Operations:**
- `TestVectorSize()` - Size calculation: `(field_0x10 - field_0x8) >> 2`
- `TestVectorEmpty()` - Empty check: `field_0x10 == field_0x8`
- `TestVectorData()` - Data pointer: `field_0x8`
- `TestVectorCapacity()` - Capacity: `(field_0x18 - field_0x8) >> 2`

**Modifying Operations:**
- `TestVectorReserve()` - Capacity checks and reallocation
- `TestVectorResize()` - Size and capacity checks
- `TestVectorPushBack()` - Field increment: `field_0x10 += 4`
- `TestVectorPopBack()` - Field decrement: `field_0x10 -= 4`
- `TestVectorClear()` - Field assignment: `field_0x10 = field_0x8`

**Advanced Operations:**
- `TestVectorIndexing()` - Pointer arithmetic: `*(field_0x8 + index * 4)`
- `TestVectorIterators()` - begin()/end() with pointer arithmetic
- `TestVectorFront()` - `*field_0x8`
- `TestVectorBack()` - `*(field_0x10 - 4)`
- `TestVectorShrinkToFit()` - Field_0x18 adjustment
- `TestVectorSwap()` - Field-to-field copy
- `TestVectorAssignment()` - Multiple field operations
- `TestComplexOperations()` - Combines multiple patterns
- `TestNestedVectorAccess()` - Struct with vector field

Each function triggers specific decompilation patterns that match optimized binary's real-world code.

## Testing with Ghidra

After building, the binary can be analyzed in Ghidra with the VectorSimplification extension to verify it correctly identifies and simplifies vector operations.

## Verification Results

The comprehensive test binary has been verified to contain **all 10 pointer arithmetic patterns** found in production binaries. See `PATTERN_COVERAGE.md` for detailed pattern-by-pattern analysis.

**Pattern Coverage Summary:**
- ✓ Size calculation: `(field_0x10 - field_0x8) >> 2` (5 functions)
- ✓ Capacity calculation: `(field_0x18 - field_0x8)` (7 functions)
- ✓ Empty check: `field_0x10 == field_0x8` (7 functions)
- ✓ Capacity check: `field_0x18 == field_0x10` (7 functions)
- ✓ Field assignments: `field_0x8/0x10/0x18 = ptr` (_Emplace_reallocate)
- ✓ Field increment: `field_0x10 += element_size` (TestComplexOperations)
- ✓ Pointer arithmetic: `ptr + offset` (_Emplace_reallocate)
- ✓ Index calculation: `(ptr - field_0x8) / element_size` (_Emplace_reallocate)
- ✓ Direct data access: `*field_0x8` (TestComplexOperations)
- ✓ Field-to-field copy: `field_0x10 = field_0x8` (clear operations)

**Total: 26 pattern instances across 7 core functions**

**Analysis scripts included:**
- `analyze_all_patterns.py` - Detects all pattern types in binary
- `show_detailed_patterns.py` - Shows detailed decompilation
- `check_main.py` - Analyzes main() decompilation patterns
- `check_patterns.py` - Searches for field patterns in all functions
- `list_functions.py` - Lists all functions in the binary

See `OPTIMIZED_BUILD_RESULTS.md` for initial optimization verification.

## Alternative Build Methods

See `BUILD_OPTIONS.md` for other approaches:
- Option 1: msvc-wine (Python-based, used by build script)
- Option 2: winetricks + Wine (GUI installer)
- Option 3: Docker (clean container environment)
- Option 4: Native Windows build
- Option 5: xwin (Rust-based, has SSL issues in containers)
- Option 6: Manual MSVC download
- Option 7: Visual Studio Installer

The automated script uses Option 1 (msvc-wine) as it's the most reliable in CI/container environments.
