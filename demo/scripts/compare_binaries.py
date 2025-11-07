#!/usr/bin/env python3
"""Compare two binary files and report differences."""

import sys
from pathlib import Path


def hexdump(data, offset=0, length=100):
    """Generate hexdump of data."""
    lines = []
    for i in range(0, min(len(data), length), 16):
        hex_part = ' '.join(f'{b:02x}' for b in data[i:i+16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
        lines.append(f'{offset+i:08x}  {hex_part:<48}  {ascii_part}')
    return '\n'.join(lines)


def compare_binaries(file1_path, file2_path):
    """
    Compare two binary files.

    Returns:
        0 if identical
        1 if different
        2 on error
    """
    file1 = Path(file1_path)
    file2 = Path(file2_path)

    # Check existence
    if not file1.exists():
        print(f"ERROR: File not found: {file1}", file=sys.stderr)
        return 2
    if not file2.exists():
        print(f"ERROR: File not found: {file2}", file=sys.stderr)
        return 2

    # Compare sizes
    size1 = file1.stat().st_size
    size2 = file2.stat().st_size

    if size1 != size2:
        print(f"DIFFERENT: Files have different sizes")
        print(f"  {file1.name}: {size1:,} bytes")
        print(f"  {file2.name}: {size2:,} bytes")
        return 1

    # Compare contents
    with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
        data1 = f1.read()
        data2 = f2.read()

    if data1 == data2:
        print(f"IDENTICAL: {file1.name} ({size1:,} bytes)")
        return 0

    # Find first difference
    for i, (b1, b2) in enumerate(zip(data1, data2)):
        if b1 != b2:
            print(f"DIFFERENT: Files differ starting at byte {i} (0x{i:x})")
            print(f"\n{file1.name}:")
            print(hexdump(data1[i:], offset=i))
            print(f"\n{file2.name}:")
            print(hexdump(data2[i:], offset=i))
            return 1

    # Should not reach here if sizes are equal
    print(f"IDENTICAL: {file1.name}")
    return 0


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <file1> <file2>", file=sys.stderr)
        print(f"Compare two binary files and exit with:", file=sys.stderr)
        print(f"  0 = identical", file=sys.stderr)
        print(f"  1 = different", file=sys.stderr)
        print(f"  2 = error", file=sys.stderr)
        sys.exit(2)

    result = compare_binaries(sys.argv[1], sys.argv[2])
    sys.exit(result)


if __name__ == '__main__':
    main()
