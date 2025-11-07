# Show decompiled code for all test functions
#@category Testing

from ghidra.app.decompiler import DecompInterface

# Initialize standard decompiler
decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

test_functions = ["GetVectorSize", "IsVectorEmpty", "SumIfNotEmpty", "GetVectorData"]

for target_name in test_functions:
    for func in currentProgram.getFunctionManager().getFunctions(True):
        if target_name in func.getName():
            print("\n" + "=" * 70)
            print("Function: {}".format(func.getName()))
            print("=" * 70)

            results = decompiler.decompileFunction(func, 30, monitor)
            if results.decompileCompleted():
                code = results.getDecompiledFunction().getC()
                print(code)
            break

decompiler.dispose()
