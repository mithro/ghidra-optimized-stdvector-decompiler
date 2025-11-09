#!/usr/bin/env python3
"""
Test script to verify Makefile incremental build fix.

This script verifies that the Makefile correctly handles incremental builds
by checking that existing binaries are not rebuilt unnecessarily.
"""

import subprocess
import sys
import os
from pathlib import Path

def run_command(cmd, cwd=None):
    """Run command and return exit code and output."""
    result = subprocess.run(
        cmd,
        shell=True,
        cwd=cwd,
        capture_output=True,
        text=True
    )
    return result.returncode, result.stdout, result.stderr

def main():
    demo_dir = Path(__file__).parent
    print("Testing Makefile incremental build fix...")
    print(f"Working directory: {demo_dir}")
    print()

    # Test 1: Verify binary exists
    binary = demo_dir / "out/clang-19/vector_extra_O2.exe"
    if not binary.exists():
        print(f"❌ FAIL: Binary not found: {binary}")
        return 1
    print(f"✓ Binary exists: {binary}")

    # Test 2: Run make without -q and verify it doesn't rebuild
    print("\nTest: Running 'make out/clang-19/vector_extra_O2.exe'...")
    code, stdout, stderr = run_command(
        "make out/clang-19/vector_extra_O2.exe",
        cwd=demo_dir
    )

    if code != 0:
        print(f"❌ FAIL: make returned non-zero exit code: {code}")
        print(f"stdout: {stdout}")
        print(f"stderr: {stderr}")
        return 1

    if "Building" in stdout or "clang-cl" in stdout:
        print(f"❌ FAIL: make tried to rebuild when binary is up-to-date")
        print(f"stdout: {stdout}")
        return 1

    print("✓ make correctly recognized binary is up-to-date (no rebuild)")

    # Test 3: Touch source file and verify it would rebuild
    print("\nTest: Touch source and verify make would rebuild...")
    source = demo_dir / "vector_extra.cpp"
    source.touch()

    code, stdout, stderr = run_command(
        "make -n out/clang-19/vector_extra_O2.exe",
        cwd=demo_dir
    )

    if "Building optimized binary:" not in stdout:
        print(f"❌ FAIL: make didn't plan to rebuild after source was touched")
        print(f"stdout: {stdout}")
        return 1

    print("✓ make correctly detects source change and plans rebuild")

    # Test 4: Restore binary timestamp and verify no rebuild
    print("\nTest: Restore binary timestamp and verify no rebuild...")
    binary.touch()

    code, stdout, stderr = run_command(
        "make out/clang-19/vector_extra_O2.exe",
        cwd=demo_dir
    )

    if code != 0:
        print(f"❌ FAIL: make returned non-zero exit code: {code}")
        return 1

    if "Building" in stdout or "clang-cl" in stdout:
        print(f"❌ FAIL: make tried to rebuild after restoring timestamp")
        print(f"stdout: {stdout}")
        return 1

    print("✓ make correctly recognized binary is up-to-date after timestamp restore")

    # Test 5: Verify phony targets use correct paths
    print("\nTest: Verify 'basic' and 'extra' targets use full paths...")
    code, stdout, stderr = run_command(
        "make -n basic",
        cwd=demo_dir
    )

    if "out/clang-19/vector_basic_O2.exe" not in stdout:
        print(f"❌ FAIL: 'basic' target doesn't use full path")
        print(f"stdout: {stdout}")
        return 1

    print("✓ Phony targets use correct $(OUT_DIR) paths")

    # Test 6: Verify /Fe: flag uses full path
    print("\nTest: Verify /Fe: flag uses full path...")
    code, stdout, stderr = run_command(
        "make -n out/clang-19/vector_basic_O2.exe",
        cwd=demo_dir
    )

    if "/Fe:out/clang-19/vector_basic_O2.exe" not in stdout:
        print(f"❌ FAIL: /Fe: flag doesn't use full path")
        print(f"stdout: {stdout}")
        return 1

    # Make sure it's not duplicated
    if "/Fe:out/clang-19/out/clang-19/" in stdout:
        print(f"❌ FAIL: /Fe: flag duplicates directory path")
        print(f"stdout: {stdout}")
        return 1

    print("✓ /Fe: flag correctly uses full path without duplication")

    print("\n" + "="*60)
    print("✓ ALL TESTS PASSED!")
    print("="*60)
    print("\nThe Makefile bug has been successfully fixed:")
    print("  - BINARIES variables now include $(OUT_DIR) prefix")
    print("  - Pattern rules declare targets with $(OUT_DIR)")
    print("  - /Fe: flag uses $@ directly (full path)")
    print("  - Phony targets use full paths")
    print("  - Incremental builds work correctly")
    return 0

if __name__ == "__main__":
    sys.exit(main())
