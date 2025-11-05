# Vector Simplification Ghidra Extension

A native Ghidra extension that recognizes and simplifies std::vector pointer arithmetic patterns during decompilation.

## Overview

This extension analyzes pcode operations at the decompiler level to identify std::vector usage patterns and recognizes them as higher-level C++ method calls.

### Patterns Recognized

| Pattern | C++ Equivalent |
|---------|----------------|
| `(mylast - myfirst) >> N` | `vector.size()` |
| `*myfirst` | `vector.data()` |
| `mylast == myfirst` | `vector.empty()` |
| `(myend - myfirst) >> N` | `vector.capacity()` |

### Architecture

```
DecompInterface (Ghidra)
    ↓
VectorSimplifyingDecompiler (our wrapper)
    ↓
HighFunction analysis
    ↓
VectorPatternMatcher
    ↓
Pattern recognition on PcodeOpAST
    ↓
VectorPattern objects
```

## Building

### Prerequisites

1. **Ghidra Installation**
   - Ghidra 11.2+ installed at `~/tools/ghidra/`
   - Or set `GHIDRA_INSTALL_DIR` environment variable

2. **Java Development Kit**
   - JDK 17+ (matches Ghidra's requirement)
   ```bash
   java -version  # Should show 17 or higher
   ```

3. **Gradle** (included with Ghidra)
   - Ghidra includes its own Gradle distribution

### Build Steps

```bash
cd tools/ghidra_extensions/VectorSimplification

# Set Ghidra home
export GHIDRA_INSTALL_DIR=~/tools/ghidra

# Build the extension
$GHIDRA_INSTALL_DIR/support/buildExtension.sh . $GHIDRA_INSTALL_DIR

# This creates: dist/ghidra_11.x_PUBLIC_<date>_VectorSimplification.zip
```

### Installation

```bash
# Extract the built extension
cd $GHIDRA_INSTALL_DIR/Extensions/Ghidra

# Unzip the extension
unzip /path/to/dist/ghidra_*_VectorSimplification.zip

# Restart Ghidra
# Go to File → Configure → select VectorSimplification
```

## Usage

### In Ghidra GUI

1. Open your program in Ghidra
2. Ensure VectorSimplification is enabled:
   - File → Configure → Check "VectorSimplification"
3. Decompile functions as normal
4. Vector patterns will be analyzed automatically

### In Headless Mode

```java
// In your analysis script
import vectorsimplify.VectorSimplifyingDecompiler;

VectorSimplifyingDecompiler decompiler = new VectorSimplifyingDecompiler();
decompiler.openProgram(currentProgram);

// Decompile with vector analysis
DecompileResults results = decompiler.decompileFunction(func, 30, monitor);
```

### From Python (Jython)

```python
from vectorsimplify import VectorSimplifyingDecompiler

decompiler = VectorSimplifyingDecompiler()
decompiler.openProgram(getCurrentProgram())

func = getGlobalFunctions("main")[0]
results = decompiler.decompileFunction(func, 30, monitor)

print results.getDecompiledFunction().getC()
```

## Current Limitations

### Pattern Recognition Only

Currently, the extension **recognizes** patterns but does **not transform** the decompiled output. This is because:

1. **Pcode is Read-Only**: Ghidra's pcode API during decompilation is read-only
2. **ClangToken Modification is Complex**: Would require deep integration with decompiler output generation
3. **C++ Core Limitations**: True transformation requires changes to the C++ decompiler engine

### What Works

- ✅ Pattern identification in pcode
- ✅ Statistics on vector usage
- ✅ Foundation for future transformation

### What Doesn't Work Yet

- ❌ Actual transformation of decompiled C output
- ❌ Replacing patterns with method calls
- ❌ Modifying the syntax tree

## Future Enhancements

To achieve full transformation capability, we need to:

### Option 1: ClangToken Manipulation

```java
// Would need to implement
ClangTokenGroup tokens = results.getCCodeMarkup();
// Traverse and replace tokens
// Complex but possible
```

### Option 2: Custom Print C Action

```java
// Override the C printing process
class VectorPrintC extends PrintC {
    @Override
    public void opIntRight(PcodeOp op) {
        if (isVectorSizePattern(op)) {
            emit("vector.size()");
        } else {
            super.opIntRight(op);
        }
    }
}
```

### Option 3: Decompiler Core Modification

Modify Ghidra's C++ decompiler core to add simplification rules:
- Edit `Ghidra/Features/Decompiler/src/decompile/cpp/`
- Add rules to `ActionDatabase`
- Rebuild entire Ghidra

**Complexity**: Very High
**Maintenance**: Difficult

## Development

### Project Structure

```
VectorSimplification/
├── extension.properties        # Extension metadata
├── Module.manifest             # Module info
├── build.gradle                # Build configuration
├── README.md                   # This file
└── src/main/java/vectorsimplify/
    ├── VectorSimplificationPlugin.java     # Main plugin
    ├── VectorSimplifyingDecompiler.java    # Custom decompiler
    ├── VectorPatternMatcher.java           # Pattern recognition
    ├── VectorPattern.java                  # Pattern data class
    └── VectorPatternType.java              # Pattern types enum
```

### Adding New Patterns

1. Add pattern type to `VectorPatternType.java`:
   ```java
   public enum VectorPatternType {
       SIZE, DATA, EMPTY, CAPACITY,
       YOUR_NEW_PATTERN  // Add here
   }
   ```

2. Implement matcher in `VectorPatternMatcher.java`:
   ```java
   private VectorPattern matchYourPattern(PcodeOpAST op) {
       // Pattern matching logic
   }
   ```

3. Register in `findVectorPatterns()`:
   ```java
   VectorPattern newPattern = matchYourPattern(op);
   if (newPattern != null) {
       patterns.add(newPattern);
   }
   ```

### Testing

```bash
# Build
./build.sh

# Test in Ghidra
$GHIDRA_INSTALL_DIR/ghidraRun

# Check console output for pattern detection messages
```

## Comparison with Post-Processing Approach

| Aspect | Java Extension | Post-Processing |
|--------|----------------|-----------------|
| **Pattern Recognition** | ✅ Native pcode analysis | ⚠️ String matching |
| **Transformation** | ❌ Not yet implemented | ✅ Full control |
| **Performance** | ✅ During decompilation | ⚠️ After export |
| **Maintenance** | ⚠️ Requires Java builds | ✅ Simple Python |
| **Success Rate** | 🔄 TBD | ✅ 99.8% proven |

## Contributing

To contribute enhancements:

1. Fork the repository
2. Make changes to Java source
3. Test with sample programs
4. Submit pull request

## License

Apache License 2.0 (matches Ghidra)

## See Also

- [GHIDRA_NATIVE_VS_POSTPROCESSING.md](../../../docs/GHIDRA_NATIVE_VS_POSTPROCESSING.md) - Comparison analysis
- [Ghidra Extension Development](https://htmlpreview.github.io/?https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GhidraClass/Intermediate/Extending_The_Decompiler.html)
- [Pcode Reference](https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/PcodeOp.html)
