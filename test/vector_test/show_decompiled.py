# Show decompiled code for test functions
#@category Testing

from ghidra.app.decompiler import DecompInterface

# Initialize standard decompiler
decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

# Find and decompile GetVectorSize
for func in currentProgram.getFunctionManager().getFunctions(True):
    if "GetVectorSize" in func.getName():
        print("Function: {}".format(func.getName()))
        print("Address: {}".format(func.getEntryPoint()))

        results = decompiler.decompileFunction(func, 30, monitor)
        if results.decompileCompleted():
            code = results.getDecompiledFunction().getC()
            print("\nDecompiled code:")
            print("=" * 70)
            print(code)
            print("=" * 70)

        # Also show the function signature and parameters
        print("\nFunction signature: {}".format(func.getSignature()))

        # Show data types if available
        print("\nParameters:")
        for param in func.getParameters():
            print("  {}: {}".format(param.getName(), param.getDataType()))

        break

decompiler.dispose()
