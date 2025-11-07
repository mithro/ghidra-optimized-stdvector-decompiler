# Compare decompilation WITHOUT vector simplification (baseline)
#@category Testing

from ghidra.app.decompiler import DecompInterface

decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

print("=" * 80)
print("BASELINE: Decompilation WITHOUT Vector Simplification")
print("=" * 80)
print("")

target_functions = ["TestComplexOperations", "TestVectorSize", "TestVectorEmpty",
                    "_Emplace_reallocate", "main"]

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
        code = results.getDecompiledFunction().getC()

        # Print first 60 lines
        lines = code.split('\n')
        for i, line in enumerate(lines[:60]):
            print(line)
        if len(lines) > 60:
            print("... (" + str(len(lines) - 60) + " more lines)")

        # Analyze patterns
        print("\n--- Pattern Analysis ---")
        has_myfirst = "_Myfirst" in code or "field_0x8" in code
        has_mylast = "_Mylast" in code or "field_0x10" in code
        has_myend = "_Myend" in code or "field_0x18" in code
        has_shift = ">> 2" in code or ">> 3" in code
        has_size_call = ".size()" in code
        has_empty_call = ".empty()" in code

        print("  Raw pointer fields: " + str(has_myfirst and has_mylast))
        print("  Pointer arithmetic (>>): " + str(has_shift))
        print("  High-level .size(): " + str(has_size_call))
        print("  High-level .empty(): " + str(has_empty_call))

decompiler.dispose()

print("\n" + "=" * 80)
print("Baseline Analysis Complete")
print("Expected: Raw pointer arithmetic (_Myfirst, _Mylast, >> 2)")
print("=" * 80)
