#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Verify OptimizedVectorDecompiler extension works correctly.

This script tests the extension against demo/out/*/vector_realistic_O2.exe and
verifies that all expected vector pattern transformations are detected.

Usage:
    # From repository root:
    python3 test.py

    # Or via Ghidra headless:
    $GHIDRA_INSTALL_DIR/support/analyzeHeadless \
        /tmp TestProject \
        -import demo/out/clang-19/vector_realistic_O2.exe \
        -postScript test.py
"""

# Check if running in Ghidra (has currentProgram defined) or standalone
try:
    # Running in Ghidra - use Ghidra API
    from vectorsimplify import VectorSimplifyingDecompiler
    RUNNING_IN_GHIDRA = True
    print("DEBUG: Successfully imported VectorSimplifyingDecompiler")
except ImportError as e:
    # Running standalone - need to invoke Ghidra headless
    RUNNING_IN_GHIDRA = False
    print("DEBUG: Not running in Ghidra (ImportError: %s)" % str(e))

import sys
import os
import subprocess
import tempfile

# Conditional import for pathlib (not available in Jython)
try:
    from pathlib import Path
    HAS_PATHLIB = True
except ImportError:
    HAS_PATHLIB = False

# Expected minimum pattern counts in test binaries
# Note: These are MINIMUM counts - more is better
EXPECTED_PATTERNS = {
    'SIZE': 1,      # vec->size() transformations
    'EMPTY': 1,     # vec->empty() transformations
    'CAPACITY': 1,  # vec->capacity() transformations
    'DATA': 1,      # vec->data() transformations
}

def discover_compilers(demo_dir="demo"):
    """Discover all compiler directories in demo/out/"""
    out_dir = os.path.join(demo_dir, "out")

    if not os.path.exists(out_dir):
        print("ERROR: %s does not exist" % out_dir)
        print("Run: git submodule update --init")
        return []

    compilers = []
    try:
        for item in os.listdir(out_dir):
            item_path = os.path.join(out_dir, item)
            if os.path.isdir(item_path) and not item.startswith('.'):
                compilers.append(item)
    except OSError:
        pass

    return sorted(compilers)

def run_analysis_in_ghidra():
    """Run analysis when executed as Ghidra script."""
    print("=" * 80)
    print("Vector Simplification Extension Test")
    print("=" * 80)
    print("DEBUG: run_analysis_in_ghidra() called")
    print("DEBUG: RUNNING_IN_GHIDRA = %s" % RUNNING_IN_GHIDRA)
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

        # Skip internal/thunk/runtime functions (those starting with _)
        # DO NOT skip FUN_* functions - these are user functions with stripped symbols
        if name.startswith("_"):
            continue

        # Skip known system functions
        system_functions = ["entry", "exception", "terminate", "free", "malloc", "memset", "memmove", "strlen"]
        if name in system_functions:
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
        print("")
        print("Possible causes:")
        print("  - OptimizedVectorDecompiler extension not installed or not enabled")
        print("  - Extension JAR not in $GHIDRA_INSTALL_DIR/Ghidra/Features/Decompiler/lib/")
        print("  - Analyzing wrong binary (use vector_realistic_O2.exe, not _Od)")
        return 1

def test_compiler(compiler, demo_dir="demo"):
    """Test binaries for a specific compiler"""
    # Use vector_extra as main test binary (per demo/README.md)
    # Fall back to vector_realistic, then vector_basic
    test_binaries = [
        "vector_extra_O2.exe",
        "vector_realistic_O2.exe",
        "vector_basic_O2.exe",
    ]

    binary_path = None
    for binary_name in test_binaries:
        candidate = os.path.join(demo_dir, "out", compiler, binary_name)
        if os.path.exists(candidate):
            binary_path = candidate
            break

    if not binary_path:
        print("  WARNING: Skipping %s: no test binaries found" % compiler)
        return None

    binary_name = os.path.basename(binary_path)
    print("\nTesting %s/%s..." % (compiler, binary_name))
    print("  Binary path: %s" % binary_path)

    # Find Ghidra installation
    ghidra_dir = os.environ.get('GHIDRA_INSTALL_DIR')
    if not ghidra_dir:
        print("  ERROR: GHIDRA_INSTALL_DIR not set")
        print("  Set it with: export GHIDRA_INSTALL_DIR=/path/to/ghidra")
        return False

    if not os.path.isdir(ghidra_dir):
        print("  ERROR: GHIDRA_INSTALL_DIR does not exist: %s" % ghidra_dir)
        return False

    analyze_headless = os.path.join(ghidra_dir, 'support', 'analyzeHeadless')
    if not os.path.exists(analyze_headless):
        print("  ERROR: analyzeHeadless not found at: %s" % analyze_headless)
        return False

    # Create temporary project directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    temp_dir = os.path.join(script_dir, '.tmp_test_%s' % compiler)

    try:
        os.makedirs(temp_dir, exist_ok=True)
        project_name = "VectorTestProject_%s" % compiler

        # Add extension JAR to classpath
        extension_jar = os.path.join(ghidra_dir, 'Ghidra', 'Features', 'Decompiler', 'lib', 'OptimizedVectorDecompiler.jar')

        # Run Ghidra headless with this script as postScript
        # Use CLASSPATH environment variable to load our extension
        env = os.environ.copy()
        if os.path.exists(extension_jar):
            if 'CLASSPATH' in env:
                env['CLASSPATH'] = extension_jar + os.pathsep + env['CLASSPATH']
            else:
                env['CLASSPATH'] = extension_jar

        cmd = [
            analyze_headless,
            temp_dir,
            project_name,
            '-import', binary_path,
            '-postScript', __file__,
            '-deleteProject'  # Clean up after
        ]

        print("  Running Ghidra analysis...")
        result = subprocess.run(cmd, check=False, capture_output=True, text=True, env=env)
        print("  Analysis complete (exit code: %d)" % result.returncode)

        # Clean up temp directory
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)

        # Parse output to determine pass/fail
        # Look for "ALL TESTS PASSED" in the output
        output = result.stdout + result.stderr

        # DEBUG: Always print output to diagnose CI issues
        if os.environ.get('CI') or os.environ.get('DEBUG_TEST'):
            print("  ===== FULL GHIDRA OUTPUT (last 100 lines) =====")
            for line in output.split('\n')[-100:]:
                if line.strip():
                    print("  %s" % line)
            print("  ===== END GHIDRA OUTPUT =====")

        if "ALL TESTS PASSED" in output:
            return True
        elif "SOME TESTS FAILED" in output:
            return False
        else:
            # If we can't determine, print some output for debugging
            print("  WARNING: Could not determine test result from output")
            print("  Last 50 lines of output:")
            for line in output.split('\n')[-50:]:
                if line.strip():
                    print("    %s" % line)
            return False

    except Exception as e:
        print("  ERROR running Ghidra: %s" % str(e))
        # Clean up temp directory on error
        import shutil
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
        return False

def run_via_ghidra_headless():
    """Run test by invoking Ghidra in headless mode."""
    print("=" * 80)
    print("Vector Simplification Extension Test")
    print("=" * 80)
    print("")

    # Find Ghidra installation
    ghidra_dir = os.environ.get('GHIDRA_INSTALL_DIR')
    if not ghidra_dir:
        print("ERROR: GHIDRA_INSTALL_DIR not set")
        print("  Set it with: export GHIDRA_INSTALL_DIR=/path/to/ghidra")
        return 1

    if not os.path.isdir(ghidra_dir):
        print("ERROR: GHIDRA_INSTALL_DIR does not exist: %s" % ghidra_dir)
        return 1

    analyze_headless = os.path.join(ghidra_dir, 'support', 'analyzeHeadless')
    if not os.path.exists(analyze_headless):
        print("ERROR: analyzeHeadless not found at: %s" % analyze_headless)
        return 1

    # Find demo binary
    script_dir = os.path.dirname(os.path.abspath(__file__))
    demo_binary = os.path.join(script_dir, 'demo', 'out', 'clang-19', 'vector_realistic_O2.exe')

    if not os.path.exists(demo_binary):
        print("ERROR: Demo binary not found: %s" % demo_binary)
        print("  Build it with: cd demo && make realistic")
        return 1

    print("Found Ghidra: %s" % ghidra_dir)
    print("Found demo binary: %s" % demo_binary)
    print("")
    print("Running Ghidra headless analysis...")
    print("-" * 80)

    # Create temporary project directory
    with tempfile.TemporaryDirectory() as temp_dir:
        project_name = "VectorTestProject"

        # Add extension JAR to classpath
        extension_jar = os.path.join(ghidra_dir, 'Ghidra', 'Features', 'Decompiler', 'lib', 'OptimizedVectorDecompiler.jar')

        # Run Ghidra headless with this script as postScript
        # Use CLASSPATH environment variable to load our extension
        env = os.environ.copy()
        if os.path.exists(extension_jar):
            if 'CLASSPATH' in env:
                env['CLASSPATH'] = extension_jar + os.pathsep + env['CLASSPATH']
            else:
                env['CLASSPATH'] = extension_jar

        cmd = [
            analyze_headless,
            temp_dir,
            project_name,
            '-import', demo_binary,
            '-postScript', __file__,
            '-deleteProject'  # Clean up after
        ]

        try:
            result = subprocess.run(cmd, check=False, capture_output=False, env=env)
            return result.returncode
        except Exception as e:
            print("ERROR running Ghidra: %s" % str(e))
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
        # Multi-compiler validation mode

        # Check GHIDRA_INSTALL_DIR early to avoid repeating error for each compiler
        ghidra_dir = os.environ.get('GHIDRA_INSTALL_DIR')
        if not ghidra_dir:
            print("✗ ERROR: GHIDRA_INSTALL_DIR not set")
            print("  Set it with: export GHIDRA_INSTALL_DIR=/path/to/ghidra")
            return 1

        if not os.path.isdir(ghidra_dir):
            print("✗ ERROR: GHIDRA_INSTALL_DIR does not exist: %s" % ghidra_dir)
            return 1

        compilers = discover_compilers()

        if not compilers:
            print("ERROR: No compilers found in demo/out/")
            print("Run: git submodule update --init")
            return 1

        print("=" * 80)
        print("Vector Simplification Extension Test - Multi-Compiler Mode")
        print("=" * 80)
        print("")
        print("Found %d compiler(s): %s" % (len(compilers), ', '.join(compilers)))

        results = {}
        for compiler in compilers:
            result = test_compiler(compiler)
            if result is not None:
                results[compiler] = result

        # Print summary
        print("")
        print("=" * 80)
        print("SUMMARY")
        print("=" * 80)

        passed = sum(1 for r in results.values() if r)
        total = len(results)

        for compiler, result in sorted(results.items()):
            status = "PASS" if result else "FAIL"
            print("  %s: %s" % (status, compiler))

        print("")
        print("Result: %d/%d compilers passed" % (passed, total))

        return 0 if passed == total else 1

if __name__ == '__main__':
    sys.exit(main())
