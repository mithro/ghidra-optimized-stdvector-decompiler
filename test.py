#!/usr/bin/env python3
"""
Backwards compatibility wrapper for test_all_compilers.py

This script is deprecated. Use test_all_compilers.py instead.
"""

import sys
import subprocess

print("NOTE: test.py is deprecated. Please use test_all_compilers.py instead.")
print("")

# Just run test_all_compilers.py
result = subprocess.run([sys.executable, "test_all_compilers.py"])
sys.exit(result.returncode)
