# Analyze all vector-related pointer arithmetic patterns in the binary
#@category Testing

from ghidra.app.decompiler import DecompInterface

decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

print("=" * 80)
print("Vector Pointer Arithmetic Pattern Analysis")
print("=" * 80)

patterns_found = {
    "size_calc": [],        # (field_0x10 - field_0x8) or (_Mylast - _Myfirst)
    "capacity_calc": [],    # (field_0x18 - field_0x8) or (_Myend - _Myfirst)
    "empty_check": [],      # field_0x10 == field_0x8 or _Mylast == _Myfirst
    "capacity_check": [],   # field_0x18 == field_0x10 or _Myend == _Mylast
    "field_access": [],     # Direct access to field_0x8/_Myfirst
    "field_assign": [],     # Assignment to fields
    "pointer_arith": []     # Arithmetic on field values
}

for func in currentProgram.getFunctionManager().getFunctions(True):
    name = func.getName()

    results = decompiler.decompileFunction(func, 30, monitor)
    if results.decompileCompleted():
        code = results.getDecompiledFunction().getC()

        # Check for size calculation patterns
        if ("_Mylast" in code and "_Myfirst" in code) or \
           ("field_0x10" in code and "field_0x8" in code):
            if ">> 2" in code or "/ 4" in code or "/ 0x" in code:
                patterns_found["size_calc"].append(name)

        # Check for capacity calculation
        if ("_Myend" in code and "_Myfirst" in code) or \
           ("field_0x18" in code and "field_0x8" in code):
            patterns_found["capacity_calc"].append(name)

        # Check for empty/capacity checks
        if ("_Mylast" in code and ("==" in code or "!=" in code)) or \
           ("field_0x10" in code and ("==" in code or "!=" in code)):
            if "_Myfirst" in code or "field_0x8" in code:
                patterns_found["empty_check"].append(name)

        if ("_Myend" in code and ("==" in code or "!=" in code)) or \
           ("field_0x18" in code and ("==" in code or "!=" in code)):
            if "_Mylast" in code or "field_0x10" in code:
                patterns_found["capacity_check"].append(name)

decompiler.dispose()

print("\nPattern Detection Results:")
print("=" * 80)
for pattern_name, functions in patterns_found.items():
    print("\n" + pattern_name.upper() + ":")
    if functions:
        for f in functions[:10]:  # Limit to first 10
            print("  - " + f)
        if len(functions) > 10:
            print("  ... and " + str(len(functions) - 10) + " more")
    else:
        print("  (none found)")

print("\n" + "=" * 80)
print("Summary:")
print("  Total patterns detected: " + str(sum(len(v) for v in patterns_found.values())))
