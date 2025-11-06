# Compare decompilation WITH vector simplification extension
#@category Testing

from ghidra.app.decompiler import DecompInterface

# Try to import the VectorSimplification extension
try:
    from vectorsimplify import VectorSimplifyingDecompiler
    EXTENSION_AVAILABLE = True
except ImportError:
    EXTENSION_AVAILABLE = False

if not EXTENSION_AVAILABLE:
    print("ERROR: VectorSimplification extension not available!")
    print("Make sure to run with: -p /path/to/VectorSimplification.jar")
    exit(1)

decompiler = VectorSimplifyingDecompiler()
decompiler.setSimplificationEnabled(True)
decompiler.openProgram(currentProgram)

print("=" * 80)
print("WITH EXTENSION: Vector Simplification Enabled")
print("=" * 80)
print("")

target_functions = ["TestComplexOperations", "TestVectorSize", "TestVectorEmpty",
                    "_Emplace_reallocate", "main"]

simplification_applied = 0
no_simplification = 0

for func in currentProgram.getFunctionManager().getFunctions(True):
    name = func.getName()

    # Check if this is one of our target functions
    if not any(target in name for target in target_functions):
        continue

    print("\n" + "=" * 80)
    print("Function: " + name)
    print("=" * 80)

    results = decompiler.decompileFunction(func, 30, monitor)
    if results.decompileCompleted():
        # Get simplified code
        simplified_code = decompiler.getSimplifiedC(results)

        # Get original code for comparison
        original_code = results.getDecompiledFunction().getC() if results.getDecompiledFunction() else ""

        # Check if simplification was applied
        was_simplified = simplified_code != original_code and simplified_code != ""

        if was_simplified:
            simplification_applied += 1
            print("[SIMPLIFIED]")
        else:
            no_simplification += 1
            print("[NO CHANGES]")

        # Print first 60 lines
        lines = simplified_code.split('\n')
        for i, line in enumerate(lines[:60]):
            print(line)
        if len(lines) > 60:
            print("... (" + str(len(lines) - 60) + " more lines)")

        # Analyze patterns
        print("\n--- Pattern Analysis ---")
        has_myfirst = "_Myfirst" in simplified_code or "field_0x8" in simplified_code
        has_mylast = "_Mylast" in simplified_code or "field_0x10" in simplified_code
        has_myend = "_Myend" in simplified_code or "field_0x18" in simplified_code
        has_shift = ">> 2" in simplified_code or ">> 3" in simplified_code
        has_size_call = ".size()" in simplified_code
        has_empty_call = ".empty()" in simplified_code
        has_data_call = ".data()" in simplified_code

        print("  Raw pointer fields: " + str(has_myfirst and has_mylast))
        print("  Pointer arithmetic (>>): " + str(has_shift))
        print("  High-level .size(): " + str(has_size_call))
        print("  High-level .empty(): " + str(has_empty_call))
        print("  High-level .data(): " + str(has_data_call))

        if was_simplified:
            print("\n  STATUS: Vector operations SIMPLIFIED!")
        else:
            print("\n  STATUS: No simplification applied")

decompiler.dispose()

print("\n" + "=" * 80)
print("Extension Test Complete")
print("=" * 80)
print("Functions with simplification: " + str(simplification_applied))
print("Functions without changes: " + str(no_simplification))
print("")
print("Expected: .size(), .empty() calls instead of pointer arithmetic")
print("=" * 80)
