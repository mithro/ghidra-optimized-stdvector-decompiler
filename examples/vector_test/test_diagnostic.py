# Enhanced diagnostic test
#@category Testing

print("=" * 80)
print("ENHANCED DIAGNOSTIC TEST")
print("=" * 80)

# Test 1: Can we import?
print("\n[TEST 1] Importing classes...")
try:
    from ghidra.app.decompiler import DecompInterface
    print("  DecompInterface: OK")
except Exception as e:
    print("  DecompInterface: FAILED - " + str(e))

try:
    from vectorsimplify import VectorPatternMatcher
    print("  VectorPatternMatcher: OK")
except Exception as e:
    print("  VectorPatternMatcher: FAILED - " + str(e))
    exit(1)

# Test 2: Can we instantiate?
print("\n[TEST 2] Creating VectorPatternMatcher...")
try:
    matcher = VectorPatternMatcher()
    print("  Instance created: " + str(matcher))
    print("  Instance class: " + str(matcher.__class__))
except Exception as e:
    print("  FAILED: " + str(e))
    import traceback
    traceback.print_exc()
    exit(1)

# Test 3: Does the method exist?
print("\n[TEST 3] Checking method...")
if hasattr(matcher, 'findVectorPatterns'):
    print("  findVectorPatterns method exists")
    print("  Method: " + str(matcher.findVectorPatterns))
else:
    print("  findVectorPatterns method DOES NOT EXIST!")
    print("  Available methods: " + str(dir(matcher)))
    exit(1)

# Test 4: Get a HighFunction
print("\n[TEST 4] Getting HighFunction...")
decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

found_func = False
for func in currentProgram.getFunctionManager().getFunctions(True):
    if "TestComplexOperations" not in func.getName():
        continue
    found_func = True
    print("  Testing function: " + func.getName())

    results = decompiler.decompileFunction(func, 30, monitor)
    if not results.decompileCompleted():
        print("  Decompilation failed!")
        break

    highFunc = results.getHighFunction()
    if highFunc == None:
        print("  No high function!")
        break

    print("  HighFunction: " + str(highFunc))
    print("  HighFunction class: " + str(highFunc.__class__))

    # Test 5: Call the method
    print("\n[TEST 5] Calling findVectorPatterns...")
    try:
        print("  Before call...")
        patterns = matcher.findVectorPatterns(highFunc)
        print("  After call!")
        print("  Return value: " + str(patterns))
        print("  Return type: " + str(type(patterns)))

        if patterns is None:
            print("  ERROR: Returned None!")
        else:
            print("  Pattern count: " + str(len(patterns)))

    except Exception as e:
        print("  EXCEPTION: " + str(e))
        import traceback
        traceback.print_exc()

    break

if not found_func:
    print("  ERROR: Could not find TestComplexOperations!")

decompiler.dispose()

print("\n" + "=" * 80)
print("Diagnostic Complete")
print("=" * 80)
