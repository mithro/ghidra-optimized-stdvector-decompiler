# Show detailed decompilation to verify all patterns
#@category Testing

from ghidra.app.decompiler import DecompInterface

decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

target_functions = ["TestComplexOperations", "_Emplace_reallocate", "_Reallocate"]

for func in currentProgram.getFunctionManager().getFunctions(True):
    name = func.getName()

    if any(target in name for target in target_functions):
        print("\n" + "=" * 80)
        print("Function: " + name)
        print("=" * 80)

        results = decompiler.decompileFunction(func, 30, monitor)
        if results.decompileCompleted():
            code = results.getDecompiledFunction().getC()
            # Print first 100 lines
            lines = code.split('\n')
            for i, line in enumerate(lines[:100]):
                print(line)
            if len(lines) > 100:
                print("... (" + str(len(lines) - 100) + " more lines)")

decompiler.dispose()
