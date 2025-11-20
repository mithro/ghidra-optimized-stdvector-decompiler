# Aggressive Optimization Vector Pattern Demo

This demo reproduces the complex P-code pattern found in heavily optimized MSVC 2019+ binaries.

## The Problem

Aggressively optimized binaries exhibit a pattern where:

1. **LOAD operations** access vector members (`_Myfirst`, `_Mylast`, `_Myend`)
2. **Address pre-computation**: The LOAD address is NOT directly a PTRSUB/PTRADD operation
3. **Intermediate storage**: Address is computed earlier and stored in register/unique varnode
4. **Tracing required**: Must trace through COPY/CAST to find the original PTRSUB

### P-code Pattern

```
INT_SUB operand pattern:
  operand0: (unique, 0x1000020b, 8)  // MYLAST
    - Defined by: CAST
    - CAST input: (register, 0x10, 8)  // Input parameter
    - defOp: null (stored from earlier computation)

  operand1: (unique, 0xdc00, 8)  // MYFIRST
    - Defined by: LOAD
    - LOAD address: (unique, 0x10000203, 8)
    - Address defOp: NOT PTRSUB/PTRADD directly!
    - Must trace through COPY/CAST to find PTRSUB
```

## The Fix

Modified `VectorPatternMatcher.java` to trace through COPY/CAST operations when analyzing LOAD addresses:

```java
// If address is not directly PTRSUB/PTRADD, try tracing through COPY/CAST
if (addrDef != null && (addrDef.getOpcode() == PcodeOp.COPY || addrDef.getOpcode() == PcodeOp.CAST)) {
    if (addrDef.getNumInputs() > 0) {
        addrVarnode = addrDef.getInput(0);
        addrDef = addrVarnode.getDef();
    }
}
```

## Compilation

To reproduce the aggressive optimization pattern, compile with MSVC 2019+ with optimizations:

```bash
# Windows (MSVC)
cl /O2 /std:c++17 vector_optimized_pattern.cpp /Fe:vector_optimized_pattern.exe

# Alternative: Use specific optimization flags
cl /O2 /Ob2 /Oi /std:c++17 vector_optimized_pattern.cpp
```

### Why MSVC 2019+?

- Uses `_Compressed_pair` wrapper → 8-byte offset (0x8, 0x10, 0x18)
- Aggressive optimization creates intermediate varnode storage
- Results in LOAD addresses being pre-computed

### Older MSVC versions (2015-2017)

- Direct offsets (0x0, 0x8, 0x10)
- May not exhibit the same LOAD pattern
- Less aggressive optimization

## Expected Patterns

When analyzed with OptimizedVectorDecompiler, should detect:

### SIZE Pattern
```
(mylast - myfirst) >> 2  →  vec->size()
```

### CAPACITY Pattern
```
(myend - myfirst) >> 2  →  vec->capacity()
```

### EMPTY Pattern
```
myfirst == mylast  →  vec->empty()
```

### DATA Pattern
```
*myfirst  →  vec->data()
```

## Verification

```bash
# Import and analyze
$GHIDRA_INSTALL_DIR/support/analyzeHeadless \\
    /tmp/test_project TestProject \\
    -import vector_optimized_pattern.exe \\
    -postScript ../scripts/analyze_patterns.py \\
    -scriptPath ../scripts

# Expected output:
# >>> MATCHED SIZE PATTERN! shift=2
# >>> MATCHED CAPACITY PATTERN! shift=2
# >>> MATCHED DATA PATTERN! <<<
```

## Key Functions

- `process_int_vector()` - Demonstrates optimized vector operations pattern
- `process_vector_with_reallocation()` - Generic template version
- `test_vector_operations()` - Driver function

## Debugging

If patterns aren't detected:

1. Check offset values in decompiled code:
   ```
   field_0x8  = _Myfirst (Pattern 2)
   field_0x10 = _Mylast  (Pattern 2)
   field_0x18 = _Myend   (Pattern 2)
   ```

2. Verify LOAD address computation:
   ```python
   # Check if addresses are pre-computed
   # Look for COPY/CAST operations before LOAD
   ```

3. Check stderr for pattern matcher debug output:
   ```
   >>> FOUND VECTOR MEMBER VIA LOAD! <<<
   ```

## Historical Context

This demo was created to demonstrate the complex optimization pattern that requires tracing through COPY/CAST operations to find the underlying PTRSUB/PTRADD address computation, ensuring the extension works on both simple and aggressively optimized binaries.
