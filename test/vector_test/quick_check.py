# Quick check optimized decompilation
#@category Testing

from ghidra.app.decompiler import DecompInterface

decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

for func in currentProgram.getFunctionManager().getFunctions(True):
    name = func.getName()
    if "GetVectorSize" in name:
        print("=== GetVectorSize ===")
        results = decompiler.decompileFunction(func, 30, monitor)
        if results.decompileCompleted():
            print(results.getDecompiledFunction().getC())
        break

decompiler.dispose()
