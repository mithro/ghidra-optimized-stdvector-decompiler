# Simple direct test of pattern matcher
#@category Testing

from ghidra.app.decompiler import DecompInterface
from vectorsimplify import VectorPatternMatcher

print("=" * 80)
print("SIMPLE PATTERN MATCHER TEST")
print("=" * 80)

decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

# Find TestComplexOperations
for func in currentProgram.getFunctionManager().getFunctions(True):
    if "TestComplexOperations" not in func.getName():
        continue

    print("\n Testing: " + func.getName())
    print("-" * 80)

    results = decompiler.decompileFunction(func, 30, monitor)
    if not results.decompileCompleted():
        print("Decompilation failed!")
        break

    highFunc = results.getHighFunction()
    if highFunc == None:
        print("No high function!")
        break

    print("Decompilation OK")

    # Call pattern matcher directly
    print("\nCalling VectorPatternMatcher...")
    matcher = VectorPatternMatcher()
    patterns = matcher.findVectorPatterns(highFunc)

    print("\n>>> PATTERNS FOUND: " + str(len(patterns)) + " <<<")

    for i, pattern in enumerate(patterns):
        print("Pattern " + str(i+1) + ": " + str(pattern.getType()))

    break

decompiler.dispose()

print("\n" + "=" * 80)
print("Test Complete")
print("=" * 80)
