#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test OptimizedVectorDecompiler extension within Ghidra.

This script is designed to run ONLY inside Ghidra's Jython environment.

Usage:
    $GHIDRA_INSTALL_DIR/support/analyzeHeadless \
        /tmp TestProject \
        -import demo/out/msvc-14.44/vector_extra_O2.exe \
        -postScript test_ghidra.py
"""

from vectorsimplify import VectorSimplifyingDecompiler

# Expected minimum pattern counts in vector_extra_O2.exe
EXPECTED_PATTERNS = {
    'SIZE': 5,      # vec->size() transformations
    'EMPTY': 7,     # vec->empty() transformations
    'CAPACITY': 7,  # vec->capacity() transformations
    'DATA': 2,      # vec->data() transformations
}

def main():
    """Run analysis in current Ghidra session."""
    print("=" * 80)
    print("Vector Simplification Extension Test")
    print("=" * 80)
    print("")

    # Use the custom decompiler with pattern detection
    decompiler = VectorSimplifyingDecompiler()
    decompiler.openProgram(currentProgram)

    # Track pattern transformations
    transformations = {
        "SIZE": 0,
        "EMPTY": 0,
        "CAPACITY": 0,
        "DATA": 0
    }

    functions_with_transforms = []

    print("Analyzing functions...")
    print("-" * 80)

    for func in currentProgram.getFunctionManager().getFunctions(True):
        name = func.getName()

        # Skip internal/thunk functions
        if name.startswith("_") or name.startswith("FUN_"):
            continue

        # Decompile with our custom decompiler
        results = decompiler.decompileFunction(func, 30, monitor)
        if not results.decompileCompleted():
            continue

        # Get simplified and original code
        simplifiedCode = decompiler.getSimplifiedC(results)
        originalCode = results.getDecompiledFunction().getC()

        # Check if transformation occurred
        if simplifiedCode != originalCode:
            # Count pattern types in simplified code
            func_patterns = []
            if "->size()" in simplifiedCode:
                count = simplifiedCode.count("->size()")
                transformations["SIZE"] += count
                func_patterns.append("SIZE(%d)" % count)

            if "->empty()" in simplifiedCode:
                count = simplifiedCode.count("->empty()")
                transformations["EMPTY"] += count
                func_patterns.append("EMPTY(%d)" % count)

            if "->capacity()" in simplifiedCode:
                count = simplifiedCode.count("->capacity()")
                transformations["CAPACITY"] += count
                func_patterns.append("CAPACITY(%d)" % count)

            if "->data()" in simplifiedCode:
                count = simplifiedCode.count("->data()")
                transformations["DATA"] += count
                func_patterns.append("DATA(%d)" % count)

            if func_patterns:
                functions_with_transforms.append((name, func_patterns))
                print("  %s: %s" % (name, ", ".join(func_patterns)))

    decompiler.dispose()

    print("")
    print("=" * 80)
    print("Pattern Transformation Summary:")
    print("=" * 80)

    all_passed = True
    for pattern_name, expected_count in EXPECTED_PATTERNS.items():
        actual = transformations.get(pattern_name, 0)
        status = "PASS" if actual >= expected_count else "FAIL"
        print("  %s %s: expected >=%d, found %d" % (status, pattern_name, expected_count, actual))
        if actual < expected_count:
            all_passed = False

    print("")
    print("Total functions with transformations: %d" % len(functions_with_transforms))
    print("")

    if all_passed:
        print("=" * 80)
        print("ALL TESTS PASSED")
        print("=" * 80)
        return 0
    else:
        print("=" * 80)
        print("SOME TESTS FAILED")
        print("=" * 80)
        return 1

if __name__ == '__main__' or __name__ == '__builtin__':
    exit_code = main()
    if exit_code != 0:
        raise Exception("Tests failed")
