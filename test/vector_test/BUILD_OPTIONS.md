# Building vector_test with MSVC-Compatible Compiler

This document explains the different options for building `vector_test.cpp` with MSVC-compatible layout and PDB debug symbols.

## Why MSVC?

The Ghidra VectorSimplification extension is designed to recognize MSVC's std::vector layout:
- `_Myfirst` at offset 0x8 (pointer to first element)
- `_Mylast` at offset 0x10 (pointer to last element)
- `_Myend` at offset 0x18 (pointer to end of allocated storage)

GCC and other compilers use different layouts (e.g., `_M_start`, `_M_finish`, `_M_end_of_storage`), so we need MSVC or an MSVC-compatible compiler.

## Option 1: Wine + MSVC Build Tools (Recommended but Complex)

**Status**: Currently not working reliably in Wine.

The installer completes but doesn't actually install cl.exe. This is a known Wine limitation with Visual Studio installers.

**Script**: `install_msvc_and_build.sh`

**Issue**: VS Build Tools installer returns success but doesn't install compiler:
```
Installer exit code: 0
ERROR: cl.exe not found after installation
```

**Diagnostic**: Run `./check_wine_msvc.sh` to see what was actually installed.

**Why it fails**:
- VS installers use complex .NET components that don't work well in Wine
- Even with .NET Framework installed, the workload installers may fail silently
- Wine's COM/DCOM implementation is incomplete

## Option 2: clang-cl + xwin (Alternative, Easier)

**Status**: Should work, but requires Rust/Cargo.

Uses LLVM's clang-cl (MSVC-compatible frontend) with xwin (MSVC SDK downloader).

**Script**: `install_clangcl_and_build.sh`

**Pros**:
- Produces genuine Windows PE executables
- Creates real PDB debug symbols
- Uses MSVC std::vector layout
- Much easier to install than full MSVC

**Cons**:
- Requires installing Rust/Cargo (large dependency)
- First run downloads ~500MB of MSVC SDK files
- Not "real" MSVC (uses LLVM codegen)

**To use**:
```bash
chmod +x install_clangcl_and_build.sh
./install_clangcl_and_build.sh
```

## Option 3: Compile on Windows (Simplest)

**Status**: Always works if you have Windows.

Just compile on a real Windows machine with Visual Studio or Build Tools.

**Steps on Windows**:
```cmd
# Install Visual Studio Build Tools
# https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022

# Open "x64 Native Tools Command Prompt"
cd test\vector_test
cl.exe /Zi /EHsc /std:c++17 /MD /Fe:vector_test_msvc.exe vector_test.cpp /link /DEBUG:FULL

# Copy the .exe and .pdb back to this repository
```

Then copy `vector_test_msvc.exe` and `vector_test_msvc.pdb` back to the Linux machine.

## Option 4: GitHub Actions (Automated)

**Status**: Not yet implemented, but straightforward.

Create a GitHub Actions workflow that:
1. Runs on Windows runner
2. Compiles with MSVC
3. Uploads artifacts

**Example workflow** (`.github/workflows/build-test-binary.yml`):
```yaml
name: Build MSVC Test Binary
on: [push, workflow_dispatch]
jobs:
  build:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      - uses: microsoft/setup-msbuild@v1
      - name: Compile test binary
        run: |
          cd test\vector_test
          cl.exe /Zi /EHsc /std:c++17 /MD /Fe:vector_test_msvc.exe vector_test.cpp /link /DEBUG:FULL
      - uses: actions/upload-artifact@v3
        with:
          name: msvc-binary
          path: |
            test/vector_test/vector_test_msvc.exe
            test/vector_test/vector_test_msvc.pdb
```

## Option 5: MinGW-w64 Cross-Compiler (Not MSVC-Compatible)

**Status**: Easy to install but won't work for our purposes.

MinGW-w64 can cross-compile to Windows PE format, but it uses GCC's std::vector layout, not MSVC's.

**Why it doesn't work**:
```cpp
// GCC/MinGW layout:
struct _Vector_impl {
    T* _M_start;        // offset 0x0
    T* _M_finish;       // offset 0x8
    T* _M_end_of_storage; // offset 0x10
};

// MSVC layout (what we need):
struct _Vector_val {
    T* _Myfirst;  // offset 0x8 (after _Myproxy)
    T* _Mylast;   // offset 0x10
    T* _Myend;    // offset 0x18
};
```

Our Ghidra extension specifically looks for offsets 0x8, 0x10, 0x18, so GCC binaries won't work.

## Current Recommendation

**For Tim (or anyone with the failed Wine installation)**:

1. **First**, run the diagnostic script to see what happened:
   ```bash
   ./check_wine_msvc.sh
   ```

2. **Then**, try one of these approaches in order of preference:

   a. **Easiest**: Compile on a Windows machine (Option 3) and copy the files back

   b. **Automated**: Set up GitHub Actions (Option 4) to build automatically

   c. **Linux-only**: Try the clang-cl approach (Option 2):
      ```bash
      ./install_clangcl_and_build.sh
      ```

3. **Last resort**: Debug the Wine installation further (may not be worth the effort)

## Testing After Build

Once you have `vector_test_msvc.exe` and `vector_test_msvc.pdb`:

```bash
# Test with Ghidra
cd test/vector_test
python3 test_extension.py

# Or run full analysis
/root/tools/ghidra/support/analyzeHeadless \
    . VectorTestMSVC \
    -import vector_test_msvc.exe \
    -overwrite \
    -scriptPath . \
    -postScript test_extension.py
```

The output should show:
```
[VectorSimplification] Simplifying X vector patterns in GetVectorSize
[VectorSimplification] Simplified output:
  return (vec)._Mylast - (vec)._Myfirst;  // BEFORE
  return vec.size();                       // AFTER (expected)
```

## Questions?

- Check the install logs: `msvc_install.log` or `clangcl_build.log`
- Check what Wine installed: `./check_wine_msvc.sh`
- Look at Ghidra test output: `test/vector_test/ghidra_test.log`
