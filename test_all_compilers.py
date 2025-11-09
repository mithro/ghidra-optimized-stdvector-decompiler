#!/usr/bin/env python3
"""
Test OptimizedVectorDecompiler extension against all compiler binaries.

This script runs Ghidra in headless mode to test each compiler's binary.

Usage:
    export GHIDRA_INSTALL_DIR=/path/to/ghidra
    python3 test_all_compilers.py

Or:
    GHIDRA_INSTALL_DIR=/path/to/ghidra python3 test_all_compilers.py
"""

import os
import sys
import subprocess
import shutil

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


def test_compiler(compiler, ghidra_dir, demo_dir="demo"):
    """Test binaries for a specific compiler"""
    binary_path = os.path.join(demo_dir, "out", compiler, "vector_extra_O2.exe")

    if not os.path.exists(binary_path):
        print("  ERROR: Binary not found: %s" % binary_path)
        return False

    print("Testing %s/vector_extra_O2.exe..." % compiler)
    print("  Binary path: %s" % binary_path)

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

        # Run Ghidra headless with test_ghidra.py as postScript
        cmd = [
            analyze_headless,
            temp_dir,
            project_name,
            '-import', binary_path,
            '-postScript', os.path.join(script_dir, 'test_ghidra.py'),
            '-deleteProject'  # Clean up after
        ]

        print("  Running Ghidra analysis...")
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        print("  Analysis complete (exit code: %d)" % result.returncode)

        # Clean up temp directory
        shutil.rmtree(temp_dir, ignore_errors=True)

        # Parse output to determine pass/fail
        output = result.stdout + result.stderr

        # DEBUG: Print output in CI mode
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
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
        return False


def main():
    """Main entry point."""

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
    print("")

    results = {}
    for compiler in compilers:
        result = test_compiler(compiler, ghidra_dir)
        if result is not None:
            results[compiler] = result
        print("")

    # Print summary
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
    print("")

    if passed == total:
        print("=" * 80)
        print("ALL COMPILERS PASSED")
        print("=" * 80)
        return 0
    else:
        return 1


if __name__ == '__main__':
    sys.exit(main())
