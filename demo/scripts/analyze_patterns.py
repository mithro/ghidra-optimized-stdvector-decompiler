# Analyze vector pattern transformations with VectorSimplifyingDecompiler
#@category Demo

from vectorsimplify import VectorSimplifyingDecompiler

print("=" * 80)
print("Vector Simplification Pattern Analysis")
print("=" * 80)

# Use the custom decompiler with pattern detection
decompiler = VectorSimplifyingDecompiler()
decompiler.openProgram(currentProgram)

# Track pattern transformations
transformations = {
    "SIZE": 0,
    "EMPTY": 0,
    "CAPACITY": 0,
    "DATA": 0
}

functions_with_transforms = []

print("\nAnalyzing functions...")
print("-" * 80)

for func in currentProgram.getFunctionManager().getFunctions(True):
    name = func.getName()

    # Skip internal/thunk functions
    if name.startswith("_") or name.startswith("FUN_"):
        continue

    # Decompile with our custom decompiler
    results = decompiler.decompileFunction(func, 30, monitor)
    if not results.decompileCompleted():
        continue

    # Get simplified and original code
    simplifiedCode = decompiler.getSimplifiedC(results)
    originalCode = results.getDecompiledFunction().getC()

    # Check if transformation occurred
    if simplifiedCode != originalCode:
        # Count pattern types in simplified code
        func_patterns = []
        if "->size()" in simplifiedCode:
            count = simplifiedCode.count("->size()")
            transformations["SIZE"] += count
            func_patterns.append("SIZE(%d)" % count)

        if "->empty()" in simplifiedCode:
            count = simplifiedCode.count("->empty()")
            transformations["EMPTY"] += count
            func_patterns.append("EMPTY(%d)" % count)

        if "->capacity()" in simplifiedCode:
            count = simplifiedCode.count("->capacity()")
            transformations["CAPACITY"] += count
            func_patterns.append("CAPACITY(%d)" % count)

        if "->data()" in simplifiedCode:
            count = simplifiedCode.count("->data()")
            transformations["DATA"] += count
            func_patterns.append("DATA(%d)" % count)

        if func_patterns:
            functions_with_transforms.append((name, func_patterns))
            print("  %s: %s" % (name, ", ".join(func_patterns)))

decompiler.dispose()

print("\n" + "=" * 80)
print("Pattern Transformation Summary:")
print("=" * 80)

for pattern_name, count in transformations.items():
    print("  %s: %d transformations" % (pattern_name, count))

print("\nTotal functions with transformations: %d" % len(functions_with_transforms))
print("\nComplete!")
