# Building MSVC Test Binary for Vector Simplification Extension

## Quick Start

**Simply run:**

```bash
cd /home/user/ghidra-optimized-stdvector-decompiler
./install_msvc_and_build.sh
```

This will automatically:
1. ✓ Install Wine (if needed)
2. ✓ Download Visual Studio Build Tools (~4GB)
3. ✓ Install MSVC compiler in Wine
4. ✓ Compile `test/vector_test/vector_test.cpp` with MSVC
5. ✓ Generate proper PDB debug symbols
6. ✓ Test the binary with Ghidra
7. ✓ Verify the VectorSimplification extension works
8. ✓ Commit the MSVC-compiled binary

**Estimated time:** 20-30 minutes (mostly downloading/installing MSVC)

## Why This Matters

The VectorSimplification extension is specifically designed for **MSVC-compiled binaries** because:

- **MSVC layout:** `_Myfirst` at 0x8, `_Mylast` at 0x10, `_Myend` at 0x18
- **GCC layout:** `_M_start`, `_M_finish`, `_M_end_of_storage` (different offsets)

Our test currently uses GCC, so patterns don't match. We need MSVC to properly test.

## What You'll Get

After running the script:
- `test/vector_test/vector_test_msvc.exe` - MSVC-compiled 64-bit PE executable
- `test/vector_test/vector_test_msvc.pdb` - Full debug symbols
- Ghidra test results showing detected vector patterns
- Git commit with the MSVC binary

## If The Script Fails

See `test/vector_test/README_MSVC.md` for:
- Manual installation steps
- Troubleshooting guide
- Alternative approaches

## Verify It Worked

After the script completes, you should see output like:

```
[VectorSimplification] Simplifying 1 vector patterns in GetVectorSize
  GetVectorSize - SIMPLIFIED

Functions tested: 6
Functions simplified: 3

SUCCESS: Extension is working with MSVC-compiled binary!
```

This confirms the extension properly detects and transforms MSVC std::vector patterns.

## Background

The extension was developed for production binaries (MSVC-compiled) and needs testing with a known MSVC binary to verify correctness. The GCC binary we have proves the extension correctly *rejects* non-MSVC code, which is good. Now we need to prove it correctly *accepts and transforms* MSVC code.
