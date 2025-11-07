# Check if optimized decompilation shows field_0x8/0x10/0x18 patterns
#@category Testing

from ghidra.app.decompiler import DecompInterface

decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

print("=" * 80)
print("Checking Decompilation Patterns in Optimized Binary")
print("=" * 80)

target_functions = ["GetVectorSize", "IsVectorEmpty", "SumIfNotEmpty", "GetVectorData"]

for func in currentProgram.getFunctionManager().getFunctions(True):
    name = func.getName()

    # Check if this is one of our target functions
    matches = [target for target in target_functions if target in name]
    if not matches:
        continue

    print("\n" + "=" * 80)
    print("Function: " + name)
    print("=" * 80)

    results = decompiler.decompileFunction(func, 30, monitor)
    if results.decompileCompleted():
        decomp_code = results.getDecompiledFunction().getC()
        print(decomp_code)

        # Check for patterns
        has_field_0x8 = "field_0x8" in decomp_code
        has_field_0x10 = "field_0x10" in decomp_code
        has_field_0x18 = "field_0x18" in decomp_code
        has_high_level = any(x in decomp_code for x in ["::size()", "::empty()", "::data()"])

        print("\nPattern Analysis:")
        print("  - Has field_0x8:  " + str(has_field_0x8))
        print("  - Has field_0x10: " + str(has_field_0x10))
        print("  - Has field_0x18: " + str(has_field_0x18))
        print("  - Has high-level calls: " + str(has_high_level))

        if has_field_0x8 or has_field_0x10 or has_field_0x18:
            print("\nGOOD: Shows low-level field access (matches optimized binary pattern)")
        elif has_high_level:
            print("\nBAD: Still shows high-level calls (doesn't match optimized binary)")
    else:
        print("ERROR: Decompilation failed")

decompiler.dispose()

print("\n" + "=" * 80)
print("Analysis Complete")
print("=" * 80)
