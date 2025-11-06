# MSVC Compilation Instructions

This directory contains test code for the VectorSimplification Ghidra extension.

## Quick Start (Automated)

Run the automated installation script:

```bash
cd /home/user/oni-decompiled
./install_msvc_and_build.sh
```

This script will:
1. Install Wine (if not present)
2. Download and install Visual Studio Build Tools in Wine
3. Compile `vector_test.cpp` with MSVC
4. Generate PDB debug symbols
5. Test with Ghidra
6. Commit the result

**Time required:** ~20-30 minutes (mostly MSVC download/install)

## Manual Compilation (Windows)

If you have access to a Windows machine with Visual Studio:

```cmd
cd test\vector_test
cl.exe /Zi /EHsc /std:c++17 /Fe:vector_test_msvc.exe vector_test.cpp /link /DEBUG:FULL
```

Then copy `vector_test_msvc.exe` and `vector_test_msvc.pdb` back to this directory.

## Manual Compilation (Linux with Wine)

### Prerequisites
```bash
sudo apt install wine64
```

### Install Visual Studio Build Tools

1. Download installer:
```bash
wget https://aka.ms/vs/17/release/vs_BuildTools.exe
```

2. Run installer in Wine:
```bash
wine vs_BuildTools.exe
```

3. Select workload: **Desktop development with C++**

4. Install and wait (~10 minutes)

### Compile

1. Locate cl.exe in Wine prefix:
```bash
find ~/.wine -name "cl.exe" -path "*/x64/*"
```

2. Create compile script:
```bash
cat > compile.bat << 'EOF'
@echo off
"C:\BuildTools\VC\Tools\MSVC\14.XX.XXXXX\bin\Hostx64\x64\cl.exe" ^
  /Zi /EHsc /std:c++17 ^
  /Fe:vector_test_msvc.exe ^
  vector_test.cpp ^
  /link /DEBUG:FULL
EOF
```

3. Run compilation:
```bash
wine cmd /c compile.bat
```

## Verifying the Build

Check the binary was created with PDB:

```bash
file vector_test_msvc.exe
ls -lh vector_test_msvc.pdb
```

## Testing with Ghidra

```bash
$GHIDRA_INSTALL_DIR/support/analyzeHeadless \
    . VectorTestMSVC \
    -import vector_test_msvc.exe \
    -scriptPath . \
    -postScript test_extension.py
```

Expected output:
```
[VectorSimplification] Simplifying N vector patterns in GetVectorSize
[VectorSimplification] Simplifying N vector patterns in IsVectorEmpty
...
```

## What Makes This Different from GCC?

**GCC** (already compiled as `vector_test`):
- Uses libstdc++ `std::vector` layout
- Members: `_M_start`, `_M_finish`, `_M_end_of_storage`
- Different offsets and calling conventions

**MSVC** (target for `vector_test_msvc.exe`):
- Uses MSVC STL `std::vector` layout
- Members: `_Myfirst`, `_Mylast`, `_Myend`
- Offsets: 0x8, 0x10, 0x18 (what our extension expects)
- Matches production binaries layout exactly

## Troubleshooting

### Wine: "Failed to find cl.exe"
The Build Tools didn't install correctly. Try:
```bash
rm -rf ~/.wine_msvc
# Re-run install_msvc_and_build.sh
```

### "error LNK2001: unresolved external symbol"
Missing Windows SDK. The Build Tools should include this automatically, but you may need to add SDK paths:
```
/I "C:\Program Files (x86)\Windows Kits\10\Include\10.0.22000.0\ucrt"
```

### "No vector patterns detected"
If using GCC binary, this is expected - the extension is MSVC-specific.
Make sure you compiled with MSVC and have the PDB file.
