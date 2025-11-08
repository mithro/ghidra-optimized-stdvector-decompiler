#!/usr/bin/env python3
"""
Verify OptimizedVectorDecompiler extension works correctly.

This script tests the extension against demo/vector_extra_O2.exe and verifies
that all expected vector pattern transformations are detected.

Usage:
    # From repository root:
    python3 test.py

    # Or via Ghidra headless:
    $GHIDRA_INSTALL_DIR/support/analyzeHeadless \
        /tmp TestProject \
        -import demo/vector_extra_O2.exe \
        -postScript test.py
"""

# Check if running in Ghidra (has currentProgram defined) or standalone
try:
    # Running in Ghidra - use Ghidra API
    from vectorsimplify import VectorSimplifyingDecompiler
    RUNNING_IN_GHIDRA = True
except ImportError:
    # Running standalone - need to invoke Ghidra headless
    RUNNING_IN_GHIDRA = False

import sys
import os
import subprocess
import tempfile

# Expected minimum pattern counts in vector_extra_O2.exe
EXPECTED_PATTERNS = {
    'SIZE': 5,      # vec->size() transformations
    'EMPTY': 7,     # vec->empty() transformations
    'CAPACITY': 7,  # vec->capacity() transformations
    'DATA': 2,      # vec->data() transformations
}

def run_analysis_in_ghidra():
    """Run analysis when executed as Ghidra script."""
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
        status = "✓" if actual >= expected_count else "✗"
        print("  %s %s: expected >=%d, found %d" % (status, pattern_name, expected_count, actual))
        if actual < expected_count:
            all_passed = False

    print("")
    print("Total functions with transformations: %d" % len(functions_with_transforms))
    print("")

    if all_passed:
        print("=" * 80)
        print("✓ ALL TESTS PASSED")
        print("=" * 80)
        return 0
    else:
        print("=" * 80)
        print("✗ SOME TESTS FAILED")
        print("=" * 80)
        print("")
        print("Possible causes:")
        print("  - OptimizedVectorDecompiler extension not installed or not enabled")
        print("  - Extension JAR not in $GHIDRA_INSTALL_DIR/Ghidra/Features/Decompiler/lib/")
        print("  - Analyzing wrong binary (use vector_extra_O2.exe, not _Od)")
        return 1

def run_via_ghidra_headless():
    """Run test by invoking Ghidra in headless mode."""
    print("=" * 80)
    print("Vector Simplification Extension Test")
    print("=" * 80)
    print("")

    # Find Ghidra installation
    ghidra_dir = os.environ.get('GHIDRA_INSTALL_DIR')
    if not ghidra_dir:
        print("✗ ERROR: GHIDRA_INSTALL_DIR not set")
        print("  Set it with: export GHIDRA_INSTALL_DIR=/path/to/ghidra")
        return 1

    if not os.path.isdir(ghidra_dir):
        print("✗ ERROR: GHIDRA_INSTALL_DIR does not exist: %s" % ghidra_dir)
        return 1

    analyze_headless = os.path.join(ghidra_dir, 'support', 'analyzeHeadless')
    if not os.path.exists(analyze_headless):
        print("✗ ERROR: analyzeHeadless not found at: %s" % analyze_headless)
        return 1

    # Find demo binary
    script_dir = os.path.dirname(os.path.abspath(__file__))
    demo_binary = os.path.join(script_dir, 'demo', 'vector_extra_O2.exe')

    if not os.path.exists(demo_binary):
        print("✗ ERROR: Demo binary not found: %s" % demo_binary)
        print("  Build it with: cd demo && make extra")
        return 1

    print("✓ Found Ghidra: %s" % ghidra_dir)
    print("✓ Found demo binary: %s" % demo_binary)
    print("")
    print("Running Ghidra headless analysis...")
    print("-" * 80)

    # Create temporary project directory
    with tempfile.TemporaryDirectory() as temp_dir:
        project_name = "VectorTestProject"

        # Run Ghidra headless with this script as postScript
        cmd = [
            analyze_headless,
            temp_dir,
            project_name,
            '-import', demo_binary,
            '-postScript', __file__,
            '-deleteProject'  # Clean up after
        ]

        try:
            result = subprocess.run(cmd, check=False, capture_output=False)
            return result.returncode
        except Exception as e:
            print("✗ ERROR running Ghidra: %s" % str(e))
            return 1

def main():
    """Main entry point."""
    if RUNNING_IN_GHIDRA:
        # Execute analysis in current Ghidra session
        exit_code = run_analysis_in_ghidra()
        # In Ghidra, we can't actually exit, but we can signal failure
        if exit_code != 0:
            raise Exception("Tests failed")
    else:
        # Invoke Ghidra headless
        exit_code = run_via_ghidra_headless()
        sys.exit(exit_code)

if __name__ == '__main__':
    main()
