# Check main function decompilation
#@category Testing

from ghidra.app.decompiler import DecompInterface

decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

print("=" * 80)
print("Decompilation of main() in Optimized Binary")
print("=" * 80)

for func in currentProgram.getFunctionManager().getFunctions(True):
    if func.getName() == "main":
        results = decompiler.decompileFunction(func, 30, monitor)
        if results.decompileCompleted():
            decomp_code = results.getDecompiledFunction().getC()
            print(decomp_code)

            print("\n" + "=" * 80)
            print("Pattern Analysis:")
            print("=" * 80)

            has_field_0x8 = "field_0x8" in decomp_code
            has_field_0x10 = "field_0x10" in decomp_code
            has_field_0x18 = "field_0x18" in decomp_code
            has_high_level = any(x in decomp_code for x in ["::size()", "::empty()", "::data()"])
            has_vec_size = "vec.size()" in decomp_code or "vecObj->size()" in decomp_code

            print("  - Has field_0x8:  " + str(has_field_0x8))
            print("  - Has field_0x10: " + str(has_field_0x10))
            print("  - Has field_0x18: " + str(has_field_0x18))
            print("  - Has high-level calls: " + str(has_high_level))
            print("  - Has vec.size(): " + str(has_vec_size))

            if has_field_0x8 or has_field_0x10 or has_field_0x18:
                print("\nRESULT: Shows low-level field access (matches optimized binary pattern)")
            elif has_high_level:
                print("\nRESULT: Shows high-level calls (doesn't match optimized binary)")
            else:
                print("\nRESULT: No vector operations found")
        break

decompiler.dispose()
