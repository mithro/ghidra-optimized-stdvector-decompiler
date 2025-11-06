# Test VectorPatternMatcher directly
#@category Testing

print("=" * 80)
print("DIRECT PATTERN MATCHER TEST")
print("=" * 80)

from ghidra.app.decompiler import DecompInterface
from vectorsimplify import VectorPatternMatcher

# Setup decompiler
decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

# Find TestComplexOperations
for func in currentProgram.getFunctionManager().getFunctions(True):
    if "TestComplexOperations" not in func.getName():
        continue

    print("\nFunction: " + func.getName())
    print("-" * 80)

    # Decompile
    results = decompiler.decompileFunction(func, 30, monitor)
    if not results.decompileCompleted():
        print("Decompilation failed!")
        break

    # Get high function
    highFunc = results.getHighFunction()
    if highFunc == None:
        print("No high function!")
        break

    print("High function obtained: " + str(highFunc))

    # Create matcher
    matcher = VectorPatternMatcher()
    print("Matcher created: " + str(matcher))

    # Call findVectorPatterns
    print("\nCalling findVectorPatterns directly...")
    try:
        patterns = matcher.findVectorPatterns(highFunc)
        print("Returned successfully")
        print("Pattern count: " + str(len(patterns)))

        if patterns:
            for i, pattern in enumerate(patterns):
                print("\n[Pattern " + str(i) + "]")
                print("  Type: " + str(pattern.getPatternType()))
                print("  String: " + str(pattern))
        else:
            print("\nNo patterns found")
            print("Checking if log file was created...")
            import os
            if os.path.exists("/tmp/vector_matcher_called.txt"):
                print("Log file EXISTS!")
                with open("/tmp/vector_matcher_called.txt", 'r') as f:
                    print("Contents:")
                    print(f.read())
            else:
                print("Log file NOT FOUND - method body not executing!")

    except Exception as e:
        print("EXCEPTION: " + str(e))
        import traceback
        traceback.print_exc()

    break

decompiler.dispose()
print("\nComplete")
