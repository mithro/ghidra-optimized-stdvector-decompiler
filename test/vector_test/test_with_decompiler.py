# Test using VectorSimplifyingDecompiler
#@category Testing

from vectorsimplify import VectorSimplifyingDecompiler

print("=" * 80)
print("TEST WITH VECTORSIMPLIFYINGDECOMPILER")
print("=" * 80)

dec = VectorSimplifyingDecompiler()
dec.setSimplificationEnabled(True)
dec.openProgram(currentProgram)

# Find TestComplexOperations
for func in currentProgram.getFunctionManager().getFunctions(True):
    if "TestComplexOperations" not in func.getName():
        continue

    print("\nTesting: " + func.getName())
    print("-" * 80)

    # Use the VectorSimplifyingDecompiler
    results = dec.decompileFunction(func, 30, monitor)

    if not results.decompileCompleted():
        print("Decompilation failed!")
        break

    print("Decompilation OK")

    # Get simplified code
    simplified = dec.getSimplifiedC(results)

    print("\nSimplified code length: " + str(len(simplified)))

    # Show first 500 chars
    print("\nFirst 500 chars:")
    print(simplified[:500])

    break

dec.dispose()
print("\nComplete")
