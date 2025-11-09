#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Test script to verify aggressive optimization pattern detection
Checks that the fix for pre-computed LOAD addresses works
"""

from vectorsimplify import VectorSimplifyingDecompiler

print("=" * 80)
print("Testing aggressive optimization Pattern Detection")
print("=" * 80)

# Use the custom decompiler
decompiler = VectorSimplifyingDecompiler()
decompiler.openProgram(currentProgram)

# Find our test functions
test_functions = [
    'process_int_vector',
    'process_vector_with_reallocation',
    'test_vector_operations'
]

results = {
    'total_functions': 0,
    'patterns_found': 0,
    'size_patterns': 0,
    'capacity_patterns': 0,
    'empty_patterns': 0,
    'data_patterns': 0
}

print("\nSearching for test functions...")

for func in currentProgram.getFunctionManager().getFunctions(True):
    name = func.getName()

    # Check if this is one of our test functions
    is_test_func = False
    for test_name in test_functions:
        if test_name in name:
            is_test_func = True
            break

    if not is_test_func:
        continue

    results['total_functions'] += 1
    print("\n" + "-" * 80)
    print("Function: {}".format(name))
    print("-" * 80)

    # Decompile
    res = decompiler.decompileFunction(func, 60, monitor)
    if not res.decompileCompleted():
        print("  [!] Decompilation failed")
        continue

    # Get simplified code
    simplified = decompiler.getSimplifiedC(res)
    original = res.getDecompiledFunction().getC()

    # Check for patterns
    found_any = False

    if "->size()" in simplified or ".size()" in simplified:
        results['size_patterns'] += 1
        results['patterns_found'] += 1
        found_any = True
        print("  [+] SIZE pattern detected")

    if "->capacity()" in simplified or ".capacity()" in simplified:
        results['capacity_patterns'] += 1
        results['patterns_found'] += 1
        found_any = True
        print("  [+] CAPACITY pattern detected")

    if "->empty()" in simplified or ".empty()" in simplified:
        results['empty_patterns'] += 1
        results['patterns_found'] += 1
        found_any = True
        print("  [+] EMPTY pattern detected")

    if "->data()" in simplified or ".data()" in simplified:
        results['data_patterns'] += 1
        results['patterns_found'] += 1
        found_any = True
        print("  [+] DATA pattern detected")

    if not found_any:
        print("  [-] No patterns detected")
        # Show field accesses as evidence of vector operations
        if 'field_0x' in original or '_Myfirst' in original:
            print("  [~] Raw vector fields present in original code")

decompiler.dispose()

print("\n" + "=" * 80)
print("RESULTS")
print("=" * 80)
print("Test functions analyzed: {}".format(results['total_functions']))
print("Total pattern detections: {}".format(results['patterns_found']))
print("")
print("Pattern breakdown:")
print("  SIZE:     {}".format(results['size_patterns']))
print("  CAPACITY: {}".format(results['capacity_patterns']))
print("  EMPTY:    {}".format(results['empty_patterns']))
print("  DATA:     {}".format(results['data_patterns']))
print("")

if results['patterns_found'] > 0:
    print("[SUCCESS] aggressive optimization pattern fix is working!")
    print("The extension correctly handles pre-computed LOAD addresses.")
else:
    print("[FAILURE] No patterns detected")
    print("Possible issues:")
    print("  - Binary not compiled with correct optimization flags")
    print("  - MSVC version doesn't produce aggressive optimization-style pattern")
    print("  - Extension fix not properly applied")
