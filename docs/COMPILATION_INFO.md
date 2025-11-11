# Binary Compilation Information

## PDB File Analysis

**PDB Format:** Microsoft C/C++ MSF 7.00 (PDB 7.0)
- Modern PDB format used by Visual Studio 2005 and later
- File size: 14,045,184 bytes (13.39 MB)
- Page size: 4,096 bytes
- Number of pages: 3,429

## Compiler Information

**Compiler:** Microsoft (R) Optimizing Compiler
**Linker Version:** 14.16 (Visual Studio 2017 version 15.9)
**Build Timestamp:** Wed Oct 8 04:27:11 2025
**Build System:** Jenkins CI (C:\Jenkins\workspace\Build\)

## Compilation Flags

### Compiler Flags

```
-c                              # Compile only, no linking
-Zi                             # Generate complete debug information (PDB)
-nologo                         # Suppress startup banner
-W3                             # Warning level 3
-WX-                            # Don't treat warnings as errors
-diagnostics:classic            # Classic diagnostic format
-MP                             # Multi-processor compilation
-Ox                             # Maximum optimizations (favor speed)
-Oi                             # Enable intrinsic functions
-Oy                             # Omit frame pointers (x64)
```

### Preprocessor Definitions

```
-DENABLE_MULTITHREADED          # Enable multithreading support
-DPLATFORM_64BIT                # 64-bit platform target
-DRELEASE                       # Release build
-DNDEBUG                        # Disable assertions
-D_ITERATOR_DEBUG_LEVEL=1       # Reduced iterator debugging
-D_SECURE_SCL=1                 # Secure SCL enabled
-D_CRT_SECURE_NO_WARNINGS       # Suppress CRT security warnings
```

### Runtime Library

**Runtime Linkage:** `/MT` (Static multithreaded runtime)
- The binary statically links the C/C++ runtime library (libcmt.lib)
- No external MSVCRT DLL dependency required
- Results in larger binary size but better portability

## Linker Flags

```
/ERRORREPORT:QUEUE              # Queue error reports
/INCREMENTAL:NO                 # Disable incremental linking
/NOLOGO                         # Suppress startup banner
/MANIFEST                       # Generate manifest
/MANIFESTUAC:level='asInvoker' uiAccess='false'
/manifest:embed                 # Embed manifest in binary
/DEBUG                          # Include debug information
/SUBSYSTEM:WINDOWS              # Windows subsystem
/OPT:REF                        # Eliminate unreferenced functions/data
/OPT:ICF                        # Enable COMDAT folding (identical code)
/TLBID:1                        # Type library ID
/DYNAMICBASE                    # ASLR (Address Space Layout Randomization)
/NXCOMPAT                       # DEP (Data Execution Prevention)
/MACHINE:X64                    # Target x64 architecture
/DLL                            # Build as dynamic link library
```

## Build Configuration Summary

| Property | Value |
|----------|-------|
| Configuration | Release (optimized) |
| Platform | x64 (64-bit) |
| Optimization | Maximum speed (/Ox) |
| Debug Info | Full (/Zi + /DEBUG) |
| Runtime Library | Static MT (/MT) |
| Security Features | ASLR, DEP enabled |
| Incremental Linking | Disabled |
| Frame Pointer Omission | Enabled (/Oy) |
| Intrinsics | Enabled (/Oi) |

## Notable Characteristics

1. **Release Build with Debug Symbols**: The binary is fully optimized for release but includes complete debugging information in the PDB file.

2. **Maximum Optimization**: Uses `/Ox` for maximum speed optimization, `/Oi` for intrinsics, and `/Oy` to omit frame pointers.

3. **Static Runtime**: Uses `/MT` to statically link the C runtime library, eliminating runtime DLL dependencies.

4. **Security Hardening**: Includes ASLR (`/DYNAMICBASE`) and DEP (`/NXCOMPAT`) support for enhanced security.

5. **Reduced Debug Checks**: Uses `_ITERATOR_DEBUG_LEVEL=1` instead of the default value for release builds, reducing some runtime checks while maintaining basic debugging capability.

6. **Multi-processor Build**: Compiled with `/MP` flag for parallel compilation across multiple CPU cores.

## Compiler Version Details

Based on linker version 14.16, this binary was built with:
- **Visual Studio 2017 version 15.9** (released November 2018)
- This corresponds to MSVC toolset v141
- Compatible with Windows 10 SDK

## PDB 7.0 Format Details

The PDB 7.0 format (MSF 7.00) provides:
- Support for edit-and-continue debugging
- Minimal rebuild information
- Full type information for C++ templates and STL
- Source line information for all compiled units
- Complete symbol information including private symbols
