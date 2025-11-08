# Build Environment Setup Methods

This directory contains scripts for setting up different build environments to compile MSVC-compatible Windows binaries on Linux.

## Why MSVC-Compatible Binaries?

The OptimizedVectorDecompiler extension specifically recognizes **MSVC's std::vector internal layout**:
- `_Myfirst` at offset 0x0
- `_Mylast` at offset 0x8
- `_Myend` at offset 0x10

GCC and Clang use different layouts, so we need MSVC-compatible toolchains to generate test binaries that match production Windows software.

## Quick Comparison

| Method              | Script                       | Status      | CI | Speed  | Download | Pros                                       | Cons                   |
|---------------------|------------------------------|-------------|-------|--------|----------|--------------------------------------------|------------------------|
| **clang-cl + xwin** | `setup_clangcl.sh`           | ✅ Primary | ✅    | Fast   | 3GB      | Reproducible, no Wine, works in containers | Not "real" MSVC        |
| **msvc-wine**       | `setup_msvc_wine.sh`         | ✅ Works   | ✅    | Slow   | 2.7GB    | Real MSVC toolchain                        | Requires Wine, slower  |
| **winetricks**      | `setup_msvc_winetricks.sh`   | ⚠️ Manual  | ❌    | Medium | 2.7GB    | Official Microsoft installer               | GUI required, manual   |
| **Native Windows**  | N/A                          | ✅ Works   | ❌    | Fast   | Large    | Native Microsoft toolchain                 | Windows-only           |

**Default**: The main `../setup_build_env.sh` uses the clang-cl + xwin method.

## Method 1: clang-cl + xwin (Primary)

### Overview
Uses clang-cl (LLVM's MSVC-compatible frontend) with Microsoft headers/libraries downloaded via the `msvc-wine` Python tool.

### Setup
```bash
cd demo
./setup_build_env.sh
# OR
./build_setup/setup_clangcl.sh
```

### What It Does
1. Installs clang-19 and lld-link from Ubuntu repositories
2. Downloads MSVC 14.44.35207 headers
3. Downloads Windows SDK 10.0.26100.0
4. Stores in `~/.msvc/` (~3GB)

### Pros
- ✅ Fast compilation (native LLVM, no emulation)
- ✅ Reproducible builds
- ✅ Works in Docker/CI without X11
- ✅ No Wine installation needed
- ✅ Binary-compatible with MSVC

### Cons
- ❌ Large download (~3GB)
- ❌ Not "real" MSVC (though output is compatible)
- ❌ Requires Ubuntu 24.04+ for clang-19 in repos

### Requirements
- Ubuntu 24.04 or compatible (for clang-19 in apt)
- ~9GB disk space
- Internet connection

### How It Works
```bash
# Compiler: clang-cl-19 (LLVM)
# Linker: lld-link (LLVM)
# Headers: Real MSVC 14.44 headers
# Libraries: Real Windows SDK 10.0.26100 libraries
# Output: PE32+ Windows executable with PDB symbols
```

The binary is functionally identical to MSVC output with the same std::vector layout.

---

## Method 2: msvc-wine

### Overview
Uses the real Microsoft Visual C++ compiler running under Wine emulation.

### Setup
```bash
./build_setup/setup_msvc_wine.sh
```

### What It Does
1. Installs Wine and dependencies
2. Downloads MSVC toolchain via `msvc-wine`
3. Installs Visual C++ Build Tools under Wine
4. Configures Wine environment

### Pros
- ✅ Real Microsoft compiler (not a clone)
- ✅ Scriptable (works in CI)
- ✅ Produces guaranteed MSVC-compatible output

### Cons
- ❌ Slower (Wine emulation overhead)
- ❌ Requires Wine installation and configuration
- ❌ More complex troubleshooting

### Requirements
- Wine (stable or development)
- Python 3
- ~9GB disk space

### How It Works
```bash
# Compiler: cl.exe (via Wine)
# Linker: link.exe (via Wine)
# Headers/Libs: Real MSVC toolchain
# Output: PE32+ Windows executable
```

---

## Method 3: winetricks (Manual)

### Overview
Uses the official Microsoft Visual Studio Build Tools installer through winetricks.

### Setup
```bash
./build_setup/setup_msvc_winetricks.sh
```

### What It Does
1. Installs Wine and winetricks
2. Launches GUI installer for Visual Studio Build Tools
3. Requires manual component selection
4. Installs to Wine prefix

### Pros
- ✅ Official Microsoft installer
- ✅ Real MSVC toolchain
- ✅ Familiar to Windows developers

### Cons
- ❌ Requires GUI (no headless CI)
- ❌ Manual steps (click through installer)
- ❌ Harder to automate
- ❌ Longer setup time

### Requirements
- Wine with X11 support
- Desktop environment or X11 forwarding
- ~10GB disk space

---

## Method 4: Native Windows Build

### Overview
Use Visual Studio or Build Tools on a Windows machine.

### Setup
1. Install Visual Studio 2022 or Build Tools
2. Select "C++ Build Tools" workload
3. Open Developer Command Prompt
4. Navigate to demo directory
5. Run: `cl /O2 /EHsc /Zi vector_extra.cpp /link /DEBUG:FULL`

### Pros
- ✅ Native performance
- ✅ Official toolchain
- ✅ No emulation

### Cons
- ❌ Requires Windows
- ❌ Not CI-friendly (Linux CI)
- ❌ Large installation (~7GB)

---

## Build Script Inventory

| Script | Purpose |
|--------|---------|
| `setup_clangcl.sh` | Primary: Sets up clang-cl + MSVC headers |
| `setup_msvc_wine.sh` | Alternative: Real MSVC via Wine |
| `setup_msvc_winetricks.sh` | Alternative: GUI installer via Wine |
| `install_wine_deps.sh` | Helper: Installs Wine dependencies |
| `check_wine_msvc.sh` | Utility: Tests Wine MSVC installation |

## Troubleshooting

### clang-cl Issues

**"clang-cl-19: command not found"**
```bash
# Install clang-19
sudo apt-get install clang-19 lld-19
sudo ln -s /usr/lib/llvm-19/bin/clang /usr/bin/clang-cl-19
```

**"MSVC headers not found"**
```bash
# Re-run header download
cd build_setup/tools/msvc-wine
python3 ./vsdownload.py --accept-license --dest ~/.msvc
```

**"kernel32.lib not found"**
```bash
# Fix case-sensitive filesystem issues
cd ~/.msvc/Windows\ Kits/10/Lib/10.0.26100.0/um/x64
ln -s kernel32.Lib kernel32.lib
```

### Wine Issues

**"wine: Bad EXE format"**
- Install wine-stable or wine-development
- Ensure 64-bit Wine support: `dpkg --add-architecture i386`

**"msiexec failed"**
- Check Wine configuration: `winecfg`
- Verify Wine version: `wine --version` (need 5.0+)

**Slow compilation**
- Wine has overhead; consider clang-cl method instead
- Use `/MP` flag for parallel compilation (if supported)

### General Issues

**"No space left on device"**
- MSVC toolchain requires ~9GB
- Clean up: `rm -rf ~/.msvc` and reinstall

**Download failures**
- Check internet connection
- Try alternate mirror (if using msvc-wine)
- Use VPN if region-blocked

## Verifying Installation

After setup, verify the environment:

```bash
cd demo
make check-env
```

Expected output:
```
Checking build environment...

GHIDRA_INSTALL_DIR: /path/to/ghidra
  ✓ Found

Compiler: clang-cl-19
  ✓ Found: clang version 19.1.1

MSVC Headers: ~/.msvc/unpack/VC/Tools/MSVC/14.44.35207/include
  ✓ Found

Windows SDK: ~/.msvc/Windows Kits/10/Include/10.0.26100.0
  ✓ Found

Environment OK!
```

## Choosing a Method

### For Development / Quick Testing
→ **Use clang-cl** (Method 1)
- Fastest compilation
- Easy to set up
- Reproducible

### For Production-Identical Binaries
→ **Use msvc-wine** (Method 2)
- Real Microsoft compiler
- Guaranteed compatibility
- Acceptable speed

### For Windows Environments
→ **Use Native Windows** (Method 4)
- Best performance
- Native toolchain
- Simplest

### For Manual Verification
→ **Use winetricks** (Method 3)
- Official installer
- Manual control
- Good for one-time builds

## Advanced: Custom MSVC Versions

The default setup uses MSVC 14.44 and SDK 10.0.26100. To use different versions:

### With msvc-wine
```bash
cd build_setup/tools/msvc-wine
python3 ./vsdownload.py --help
# Edit script to specify different versions
```

### In Makefile
Edit `demo/Makefile`:
```makefile
MSVC_VERSION := 14.40.33807  # Your version
SDK_VERSION := 10.0.22621.0   # Your SDK
```

## References

- [msvc-wine GitHub](https://github.com/mstorsjo/msvc-wine) - Python tool for downloading MSVC
- [clang-cl Documentation](https://clang.llvm.org/docs/MSVCCompatibility.html) - MSVC compatibility
- [Wine MSVC Guide](https://wiki.winehq.org/Building_MSVC) - Running MSVC under Wine
