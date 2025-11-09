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


def find_ghidra_installation():
    """Find Ghidra installation directory.

    Returns path if found, None otherwise.
    """
    # Check environment variable first
    if 'GHIDRA_INSTALL_DIR' in os.environ:
        ghidra_dir = os.environ['GHIDRA_INSTALL_DIR']
        if os.path.isdir(ghidra_dir) and os.path.isfile(os.path.join(ghidra_dir, 'ghidraRun')):
            return ghidra_dir
        print("WARNING: GHIDRA_INSTALL_DIR is set but doesn't contain a valid Ghidra installation")
        print("  Path: %s" % ghidra_dir)
        return None

    # Try default location
    default_path = os.path.join(os.path.expanduser('~'), 'tools', 'ghidra')
    if os.path.isdir(default_path) and os.path.isfile(os.path.join(default_path, 'ghidraRun')):
        return default_path

    return None


def verify_extension_installed(ghidra_dir):
    """Verify that the OptimizedVectorDecompiler extension is built and installed.

    Returns True if extension is ready, False otherwise.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Check if extension JAR is built
    jar_path = os.path.join(script_dir, "extension", "build", "libs", "OptimizedVectorDecompiler.jar")
    if not os.path.exists(jar_path):
        print("✗ ERROR: Extension JAR not built")
        print("  Expected: %s" % jar_path)
        print("")
        print("Please build the extension:")
        print("  cd extension && ./build.sh")
        print("  Or run: ./setup.sh")
        print("")
        return False

    # Check if extension is installed in Ghidra's Decompiler lib (required for headless mode)
    decompiler_jar = os.path.join(ghidra_dir, "Ghidra", "Features", "Decompiler", "lib", "OptimizedVectorDecompiler.jar")
    if not os.path.exists(decompiler_jar):
        print("✗ ERROR: Extension not installed in Ghidra")
        print("  Expected: %s" % decompiler_jar)
        print("")
        print("Please install the extension:")
        print("  ./setup.sh")
        print("")
        return False

    print("✓ Extension verified: %s" % os.path.basename(jar_path))
    return True


def main():
    """Main entry point."""

    # Find Ghidra installation
    ghidra_dir = find_ghidra_installation()
    if not ghidra_dir:
        print("✗ ERROR: Ghidra installation not found")
        print("")
        print("Please either:")
        print("  1. Set GHIDRA_INSTALL_DIR environment variable:")
        print("     export GHIDRA_INSTALL_DIR=/path/to/ghidra")
        print("  2. Install Ghidra to default location: ~/tools/ghidra")
        print("  3. Run ./setup.sh to install Ghidra automatically")
        print("")
        return 1

    print("✓ Ghidra found: %s" % ghidra_dir)

    # Verify extension is built and installed
    if not verify_extension_installed(ghidra_dir):
        return 1

    print("")

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
