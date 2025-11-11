#!/usr/bin/env python3
"""
Patch PE TimeDateStamp to a fixed value for reproducible builds.

This script modifies the TimeDateStamp field in the COFF header of PE files
(executables and DLLs) to a deterministic value, making builds reproducible.

Usage:
    python patch_pe_timestamp.py <pe_file> [timestamp_value]

    timestamp_value: Unix timestamp to use (default: 1)
"""

import struct
import sys
from pathlib import Path


def patch_pe_timestamp(pe_path, timestamp_value=1):
    """
    Patch the TimeDateStamp in a PE file's COFF header.

    Args:
        pe_path: Path to PE file (.exe or .dll)
        timestamp_value: Fixed timestamp value to write (default: 1)

    Returns:
        True if patched successfully, False otherwise
    """
    pe_path = Path(pe_path)

    if not pe_path.exists():
        print(f"ERROR: File not found: {pe_path}", file=sys.stderr)
        return False

    # Read the entire file
    with open(pe_path, 'rb') as f:
        data = bytearray(f.read())

    # Find PE signature offset (at offset 0x3c)
    if len(data) < 0x40:
        print(f"ERROR: File too small to be a valid PE: {pe_path}", file=sys.stderr)
        return False

    pe_offset = struct.unpack('<I', data[0x3c:0x40])[0]

    # Verify PE signature
    if len(data) < pe_offset + 4:
        print(f"ERROR: Invalid PE offset: {pe_offset}", file=sys.stderr)
        return False

    pe_sig = data[pe_offset:pe_offset+4]
    if pe_sig != b'PE\x00\x00':
        print(f"ERROR: Not a valid PE file (signature: {pe_sig.hex()})", file=sys.stderr)
        return False

    # COFF Header starts at pe_offset + 4
    # TimeDateStamp is at COFF_offset + 4 (after Machine=2 bytes, NumberOfSections=2 bytes)
    coff_offset = pe_offset + 4
    timestamp_offset = coff_offset + 4

    if len(data) < timestamp_offset + 4:
        print(f"ERROR: File too small for COFF header", file=sys.stderr)
        return False

    # Read original timestamp
    original_timestamp = struct.unpack('<I', data[timestamp_offset:timestamp_offset+4])[0]

    # Patch with new timestamp
    data[timestamp_offset:timestamp_offset+4] = struct.pack('<I', timestamp_value)

    # Write back
    with open(pe_path, 'wb') as f:
        f.write(data)

    print(f"✓ Patched {pe_path.name}: 0x{original_timestamp:08x} → 0x{timestamp_value:08x}")
    return True


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        print("\nExamples:", file=sys.stderr)
        print("  python patch_pe_timestamp.py program.exe", file=sys.stderr)
        print("  python patch_pe_timestamp.py program.exe 1234567890", file=sys.stderr)
        sys.exit(1)

    pe_file = sys.argv[1]
    timestamp_value = int(sys.argv[2]) if len(sys.argv) > 2 else 1

    success = patch_pe_timestamp(pe_file, timestamp_value)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
