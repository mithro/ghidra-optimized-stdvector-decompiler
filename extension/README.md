# Optimized Vector Decompiler - Ghidra Plugin

A Ghidra plugin that improves decompilation of optimized binaries by transforming std::vector pointer arithmetic from MSVC-compiled code into idiomatic C++ method calls.

## Features

Transforms MSVC std::vector operations at the AST level (NO regex/string manipulation):

### SIZE Pattern
**Before:** `(vec->field_0x10 - vec->field_0x8) >> 2`  
**After:** `(vec).size()`

### EMPTY Pattern  
**Before:** `vec->field_0x10 == vec->field_0x8`  
**After:** `(vec).empty()`

## Requirements

- MSVC-compiled binaries (64-bit)
- PDB debug information
- Ghidra 11.x

## Installation

Copy JAR to Ghidra's classpath:
```bash
cp OptimizedVectorDecompiler.jar $GHIDRA_HOME/Ghidra/Features/Decompiler/lib/
```

## Usage

See `tools/ghidra_scripts/ExportDecompilationWithSimplification.py` for example usage.

## Technical Details

- **Pattern Detection**: Analyzes pcode operations (INT_RIGHT, INT_EQUAL)
- **Type Checking**: Validates varnodes have std::vector types to prevent false positives  
- **AST Transformation**: Rewrites ClangToken trees, preserving structure

## Limitations

- MSVC-only (uses offsets 0x8/0x10/0x18 for _Myfirst/_Mylast/_Myend)
- DATA pattern disabled (expression boundary issues)
- Requires type information from PDB

## Testing

Test project in `test/vector_test/` demonstrates functionality.

