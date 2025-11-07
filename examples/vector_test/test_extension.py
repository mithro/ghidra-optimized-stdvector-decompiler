# Test the VectorSimplification extension on the test binary
#@category Testing

from ghidra.app.decompiler import DecompInterface

# Try to import the extension
try:
    from vectorsimplify import VectorSimplifyingDecompiler
    EXTENSION_AVAILABLE = True
    print("VectorSimplification extension loaded successfully")
except ImportError as e:
    print("ERROR: VectorSimplification extension not available: {}".format(e))
    EXTENSION_AVAILABLE = False

if EXTENSION_AVAILABLE:
    # Initialize the decompiler
    decompiler = VectorSimplifyingDecompiler()
    decompiler.setSimplificationEnabled(True)
    decompiler.openProgram(currentProgram)

    # Test specific functions
    test_functions = [
        "GetVectorSize",
        "IsVectorEmpty",
        "SumIfNotEmpty",
        "GetVectorData",
        "ProcessVector",
        "ResizeVector"
    ]

    print("=" * 70)
    print("Testing Vector Simplification on Test Functions")
    print("=" * 70)

    for func_name in test_functions:
        # Find the function
        func = None
        for f in currentProgram.getFunctionManager().getFunctions(True):
            if func_name in f.getName():
                func = f
                break

        if func is None:
            print("\nFunction '{}' not found (may be mangled)".format(func_name))
            continue

        print("\n--- {} ---".format(func.getName()))

        # Decompile
        results = decompiler.decompileFunction(func, 30, monitor)
        if not results.decompileCompleted():
            print("  Decompilation failed")
            continue

        # Get simplified code
        simplified_code = decompiler.getSimplifiedC(results)
        original_code = results.getDecompiledFunction().getC()

        if simplified_code == original_code:
            print("  No simplifications applied")
        else:
            print("  SIMPLIFIED!")
            print("  Original length: {} chars".format(len(original_code)))
            print("  Simplified length: {} chars".format(len(simplified_code)))

    decompiler.dispose()

    print("\n" + "=" * 70)
    print("Test complete")
    print("=" * 70)
else:
    print("Extension not available - cannot test")
