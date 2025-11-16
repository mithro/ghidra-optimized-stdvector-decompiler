#!/usr/bin/env python3
"""
Wrapper script to call msvcpp-normalize-pe via uvx.
This ensures the tool works in make on Windows where PATH issues occur.
"""
import subprocess
import sys

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: normalize_pe.py <pe_file> [timestamp]", file=sys.stderr)
        sys.exit(1)

    # Call uvx to run msvcpp-normalize-pe
    # uvx will automatically fetch and run the package
    args = ["uvx", "msvcpp-normalize-pe"] + sys.argv[1:]
    result = subprocess.run(args)
    sys.exit(result.returncode)
