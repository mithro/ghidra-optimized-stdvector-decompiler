#!/usr/bin/env python3
"""
Wrapper script to call msvcpp-normalize-pe.
This ensures the tool works in make on Windows where PATH issues occur.
"""
import sys
from pathlib import Path

# Import the msvcpp_normalize_pe module
from msvcpp_normalize_pe import patch_pe_file

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: normalize_pe.py <pe_file> [timestamp]", file=sys.stderr)
        sys.exit(1)

    pe_file = Path(sys.argv[1])
    timestamp = int(sys.argv[2]) if len(sys.argv) > 2 else 1

    # Call the patch function directly
    result = patch_pe_file(pe_file, timestamp=timestamp, verbose=False)

    if result.success:
        print(f"  Normalized {pe_file.name}: {result.patches_applied} fields patched")
        sys.exit(0)
    else:
        print(f"ERROR: Failed to normalize {pe_file}", file=sys.stderr)
        sys.exit(1)
