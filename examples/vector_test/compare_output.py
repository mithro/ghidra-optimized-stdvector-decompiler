# Compare original vs simplified output
#@category Testing

from ghidra.app.decompiler import DecompInterface
from vectorsimplify import VectorSimplifyingDecompiler

print("=" * 80)
print("ORIGINAL VS SIMPLIFIED COMPARISON")
print("=" * 80)

# Get original decompilation
originalDecomp = DecompInterface()
originalDecomp.openProgram(currentProgram)

# Get simplified decompilation
simplifiedDecomp = VectorSimplifyingDecompiler()
simplifiedDecomp.openProgram(currentProgram)

for func in currentProgram.getFunctionManager().getFunctions(True):
    if "TestComplexOperations" not in func.getName():
        continue

    print("\nFunction: " + func.getName())
    print("=" * 80)

    # Original
    origResults = originalDecomp.decompileFunction(func, 30, monitor)
    origCode = origResults.getDecompiledFunction().getC()

    # Simplified
    simpResults = simplifiedDecomp.decompileFunction(func, 30, monitor)
    simpCode = simplifiedDecomp.getSimplifiedC(simpResults)

    # Extract first 20 lines of each
    origLines = origCode.split('\n')[:25]
    simpLines = simpCode.split('\n')[:25]

    print("\n--- ORIGINAL (first 25 lines) ---")
    for line in origLines:
        print(line)

    print("\n--- SIMPLIFIED (first 25 lines) ---")
    for line in simpLines:
        print(line)

    break

originalDecomp.dispose()
simplifiedDecomp.dispose()
print("\nComplete")
