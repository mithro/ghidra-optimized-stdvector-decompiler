# Compiler Matrix Submodule Design

**Date**: 2025-11-09
**Status**: Approved for Implementation

## Overview

Move demo binary outputs (.exe, .pdb files) to a dedicated git submodule to keep the main repository small while supporting a comprehensive compiler test matrix. This enables verification that the Ghidra plugin works correctly across multiple Windows C++ compilers (clang-cl-19, clang-cl-20, MSVC 14.44, etc.).

## Goals

1. **Keep main repo small**: Remove large binary files from main repository history
2. **Support multiple compilers**: Store outputs from clang-19, clang-20, MSVC 14.44, MSVC 14.40, and future compilers
3. **Maintain manual workflow**: Developers manually build and commit binaries (no CI automation)
4. **Comprehensive testing**: Test suite validates plugin against all compiler variants

## Architecture

### Directory Structure

**Submodule location**: `demo/out` (points to git@github.com:mithro/ghidra-optimized-stdvector-decompiler-demo-out.git)

**Structure**:
```
demo/out/
├── README.md
├── clang-19/
│   ├── vector_basic_O2.exe
│   ├── vector_basic_O2.pdb
│   ├── vector_basic_Od.exe
│   ├── vector_basic_Od.pdb
│   ├── vector_extra_O2.exe
│   ├── vector_extra_O2.pdb
│   ├── vector_extra_Od.exe
│   └── vector_extra_Od.pdb
├── clang-20/
│   └── (same pattern)
├── msvc-14.44/
│   └── (same pattern)
└── msvc-14.40/
    └── (same pattern)
```

**Compiler naming convention**:
- Clang: `clang-{major}` (e.g., `clang-19`, `clang-20`)
- MSVC: `msvc-{major}.{minor}` (e.g., `msvc-14.44`, `msvc-14.40`)
- Future compilers follow same pattern for easy discovery

### Makefile Integration

**New variables**:
```makefile
COMPILER ?= clang-19        # Default compiler identifier
OUT_DIR = out/$(COMPILER)   # Output directory path
```

**Build commands**:
```bash
make                         # Builds with default compiler (clang-19)
make COMPILER=clang-20 all   # Builds with clang-20
make COMPILER=msvc-14.44 all # Builds with MSVC 14.44
```

**Automatic submodule initialization**:
```makefile
.PHONY: init-submodule
init-submodule:
    @if [ ! -f out/.git ]; then \
        git submodule update --init demo/out; \
    fi

all: init-submodule $(ALL_BINARIES)
```

**Pattern rules updated**:
- Output paths change from `/Fe:$@` to `/Fe:$(OUT_DIR)/$@`
- Add `mkdir -p $(OUT_DIR)` before compilation

**New targets**:
- `make list-compilers`: Shows available compiler directories in `out/`

### Test Script Changes

**Multi-compiler validation**:
- test.py auto-discovers all compiler directories in `demo/out/*/`
- Runs pattern analysis on each compiler's `vector_extra_O2.exe`
- Reports per-compiler results with clear pass/fail status
- Exits with error if ANY compiler fails pattern detection

**Example output**:
```
Testing clang-19/vector_extra_O2.exe...
  ✓ SIZE patterns: 5 found
  ✓ EMPTY patterns: 7 found
  ✓ CAPACITY patterns: 7 found
  ✓ DATA patterns: 2 found

Testing clang-20/vector_extra_O2.exe...
  ✓ SIZE patterns: 5 found
  ✓ EMPTY patterns: 7 found
  ✓ CAPACITY patterns: 7 found
  ✓ DATA patterns: 2 found

Testing msvc-14.44/vector_extra_O2.exe...
  ✓ SIZE patterns: 5 found
  ✓ EMPTY patterns: 7 found
  ✓ CAPACITY patterns: 7 found
  ✓ DATA patterns: 2 found

Summary: 3/3 compilers passed
```

**Error handling**:
- Warns if `demo/out/` doesn't exist: "Run: git submodule update --init"
- Skips compilers with no binaries (warns but doesn't fail entire suite)
- Validates binary format (PE executable) before running Ghidra analysis

## Migration Plan

### Steps

1. **Initialize submodule**:
   ```bash
   git submodule add git@github.com:mithro/ghidra-optimized-stdvector-decompiler-demo-out.git demo/out
   ```

2. **Move existing binaries**:
   ```bash
   mkdir -p demo/out/clang-19
   mv demo/*.exe demo/*.pdb demo/out/clang-19/
   cd demo/out
   git add .
   git commit -m "Initial binaries from clang-19"
   git push
   cd ../..
   git add demo/out
   git commit -m "Add demo binary outputs submodule"
   ```

3. **Remove from main repo**:
   ```bash
   git rm demo/*.exe demo/*.pdb
   git commit -m "Move binaries to submodule"
   ```

4. **Update Makefile** (implement changes described above)

5. **Update test.py** (implement multi-compiler discovery)

6. **Update documentation** (see Documentation section)

### No .gitignore needed

The submodule handles its own files. Main repo `.gitignore` already excludes temporary build artifacts (*.obj, *.ilk, etc.) which is sufficient.

## Documentation Updates

### Submodule README.md (demo/out/README.md)

```markdown
# Demo Binary Outputs

Pre-compiled demonstration binaries for the [Ghidra Optimized Vector Decompiler](https://github.com/mithro/ghidra-optimized-stdvector-decompiler).

This submodule stores test binaries compiled with different Windows C++ compilers to verify the plugin works correctly across compiler variations.

**Main Repository**: https://github.com/mithro/ghidra-optimized-stdvector-decompiler

## Compiler Matrix

| Compiler | Version | Build Date | Notes |
|----------|---------|------------|-------|
| clang-19 | 19.x.x  | 2025-11-09 | LLVM 19 with clang-cl MSVC compatibility |
| clang-20 | 20.x.x  | TBD        | LLVM 20 with clang-cl MSVC compatibility |
| msvc-14.44 | 14.44.35207 | TBD   | Native MSVC via Wine |

## Directory Structure

Each compiler has its own directory with O2 (optimized) and Od (debug) variants:
- `{compiler}/vector_basic_O2.exe` - Basic vector operations, optimized
- `{compiler}/vector_basic_Od.exe` - Basic vector operations, debug
- `{compiler}/vector_extra_O2.exe` - Extended patterns, optimized
- `{compiler}/vector_extra_Od.exe` - Extended patterns, debug

All binaries include PDB debug symbols.
```

### Main Repository Updates

**CLAUDE.md**:
- Update build commands to show `COMPILER` variable
- Add examples: `make COMPILER=clang-20 optimized`
- Document submodule workflow for building new compiler variants

**README.md**:
- Add submodule clone instructions: `git clone --recurse-submodules`
- Update setup instructions to include `git submodule update --init`

**demo/README.md**:
- Add multi-compiler build examples
- Document how to add new compiler variants
- Explain test.py multi-compiler validation

## Workflow

### Cloning the repository

```bash
git clone --recurse-submodules git@github.com:mithro/ghidra-optimized-stdvector-decompiler.git
# OR if already cloned:
git submodule update --init
```

### Building with different compilers

```bash
cd demo

# Build with default compiler (clang-19)
make

# Build with specific compiler
make COMPILER=clang-20 all
make COMPILER=msvc-14.44 all

# Build optimized versions only
make COMPILER=clang-20 optimized
```

### Adding a new compiler variant

```bash
cd demo

# Build binaries for new compiler
make COMPILER=clang-21 all

# Commit to submodule
cd out
git add clang-21/
git commit -m "Add clang-21 binaries"
git push

# Update main repo reference
cd ../..
git add demo/out
git commit -m "Update demo binaries: add clang-21"
git push
```

### Running tests

```bash
# Test all compilers
python3 test.py

# Test fails if ANY compiler's binaries fail pattern detection
```

## Benefits

1. **Main repo stays lightweight**: Binary files don't bloat git history
2. **Comprehensive testing**: Validates plugin against multiple compilers automatically
3. **Clear organization**: Compiler-first directory structure makes it easy to find variants
4. **Easy expansion**: Adding new compilers just requires building with `COMPILER=new-name`
5. **Independent versioning**: Binaries can be updated without changing code
6. **Manual control**: Developers explicitly control when binaries are updated (no CI surprises)

## Trade-offs

**Chosen approach**: Makefile-integrated with COMPILER variable

**Pros**:
- Integrated workflow (single `make COMPILER=X` command)
- Automatic path management
- Easy to add new compilers
- Submodule auto-initialized by Makefile

**Cons**:
- Moderate Makefile complexity (manageable)
- Requires understanding of submodule workflow

**Rejected alternatives**:
- Minimal manual setup: Too brittle, hard to maintain as compilers added
- Scripted wrapper: Extra script to maintain, Makefile stays dumb

## Future Enhancements

- Add CI artifact uploads (manual commit to submodule from artifacts)
- Add more MSVC versions (14.40, 14.39, etc.)
- Add GCC/MinGW variants (requires separate pattern detection since different std::vector layout)
- Automated submodule update workflow (if manual becomes burden)
