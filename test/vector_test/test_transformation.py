# Test VectorSimplifyingDecompiler end-to-end
#@category Testing

from vectorsimplify import VectorSimplifyingDecompiler

print("=" * 80)
print("VECTOR SIMPLIFICATION END-TO-END TEST")
print("=" * 80)

# Use the custom decompiler
decompiler = VectorSimplifyingDecompiler()
decompiler.openProgram(currentProgram)

for func in currentProgram.getFunctionManager().getFunctions(True):
    if "TestComplexOperations" not in func.getName():
        continue

    print("\nFunction: " + func.getName())
    print("-" * 80)

    # Decompile with our custom decompiler
    results = decompiler.decompileFunction(func, 30, monitor)
    if not results.decompileCompleted():
        print("Decompilation failed!")
        break

    # Get the simplified code
    simplifiedCode = decompiler.getSimplifiedC(results)

    print("\n=== SIMPLIFIED CODE ===")
    print(simplifiedCode)
    print("\n=== END ===")

    # Also get original for comparison
    originalCode = results.getDecompiledFunction().getC()
    if simplifiedCode != originalCode:
        print("\n!!! CODE WAS TRANSFORMED !!!")
        print("\nOriginal had:")
        for line in originalCode.split('\n'):
            if '._Mylast' in line or '._Myfirst' in line or '>>' in line:
                print("  " + line.strip())
    else:
        print("\n??? NO TRANSFORMATION OCCURRED ???")

    break

decompiler.dispose()
print("\nComplete")
