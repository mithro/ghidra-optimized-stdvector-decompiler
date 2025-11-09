# GitHub Actions CI Design

**Date:** 2025-11-08
**Status:** Approved

## Overview

This document describes the GitHub Actions CI system for the Ghidra Optimized Vector Decompiler project. The CI performs full integration testing including building the extension, running Ghidra headless analysis, and verifying test binaries remain up to date.

## Requirements

- **Verification level:** Full integration (build + Ghidra + headless tests)
- **Platforms:** Linux (with future Windows support planned)
- **Triggers:** Pull requests, push to all branches, manual dispatch
- **Ghidra versions:** Matrix testing against 11.4.2 + 11.5.0 (latest stable)
- **Success criteria:** Test scripts detect expected patterns (2 EMPTY, 1 SIZE, 1 CAPACITY, 1 DATA)
- **Binary verification:** Ensure checked-in test binaries match their source files

## Architecture

The CI uses a **reusable actions approach** with modular composite actions for extensibility.

### Component 1: Setup-Ghidra Composite Action

**Location:** `.github/actions/setup-ghidra/action.yml`

**Purpose:** Reusable action that installs and caches Ghidra across workflows.

**Inputs:**
- `ghidra-version`: Version to install (e.g., "11.4.2", "11.5.0")
- `ghidra-url` (optional): Custom download URL (defaults to official GitHub releases)

**Implementation:**

1. **Cache check:**
   - Uses `actions/cache@v4` with key: `ghidra-${{ inputs.ghidra-version }}-${{ runner.os }}`
   - Cache path: `~/.ghidra-ci/ghidra_${{ inputs.ghidra-version }}`
   - Saves ~2-3 minutes on cache hits

2. **Download on cache miss:**
   - Downloads from `https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${VERSION}_build/ghidra_${VERSION}_PUBLIC_${DATE}.zip`
   - Extracts to cache directory
   - Verifies extraction (checks for `support/analyzeHeadless`)

3. **Environment setup:**
   - Exports `GHIDRA_INSTALL_DIR` environment variable
   - Adds to `$GITHUB_ENV` for subsequent steps
   - Adds `$GHIDRA_INSTALL_DIR/support` to PATH

**Error handling:**
- Retry download up to 3 times on network failures
- Validate ZIP integrity before extraction
- Fail fast with clear error messages

**Reusability:** OS-agnostic design supports Linux/Windows/macOS for future expansion.

### Component 2: Main CI Workflow

**Location:** `.github/workflows/ci.yml`

**Triggers:**
```yaml
on:
  push:
    branches: ['**']  # All branches
  pull_request:
    branches: ['**']
  workflow_dispatch:  # Manual trigger
```

**Matrix Strategy:**
```yaml
matrix:
  ghidra-version: ['11.4.2', '11.5.0']
  java-version: ['21']
```

**Jobs:**

#### Job 1: `build`
- **Runs on:** `ubuntu-latest`
- **Purpose:** Fast feedback on Gradle build
- **Steps:**
  1. Checkout code
  2. Setup Java 21 (`actions/setup-java@v4`)
  3. Cache Gradle dependencies (`~/.gradle/caches`)
  4. Run `cd extension && ./build.sh`
  5. Upload JAR artifact: `OptimizedVectorDecompiler.jar`

#### Job 2: `test`
- **Runs on:** `ubuntu-latest`
- **Depends on:** `build` job
- **Purpose:** Integration testing with Ghidra
- **Steps:**
  1. Checkout code
  2. Download build artifact (JAR from build job)
  3. Use `setup-ghidra` action with matrix version
  4. Install extension to Ghidra
  5. Run `uv run python test.py` (top-level test script from PR #9)
  6. Validate expected pattern counts in output
  7. Fail if test.py exits non-zero

**Expected Output Validation:**
- EMPTY patterns: 2
- SIZE patterns: 1
- CAPACITY patterns: 1
- DATA patterns: 1

**Caching:**
- Gradle dependencies
- Ghidra installations (via composite action)
- uv/Python dependencies

### Component 3: Linux Binary Verification Workflow

**Location:** `.github/workflows/verify-binaries-linux.yml`

**Purpose:** Rebuild test binaries using Wine + MSVC on Linux and compare to committed versions.

**Triggers:**
- Changes to `demo/*.cpp` files
- Pull requests
- Manual dispatch

**Jobs:**
```yaml
verify-binaries-linux:
  runs-on: ubuntu-latest
  steps:
    1. Checkout code
    2. Install Wine dependencies: sudo apt-get install wine64 wine32
    3. Run demo/build_environments/setup_msvc_wine.sh
    4. Build binaries: cd demo && make all
    5. Run comparison script
    6. Fail if any differences detected
```

### Component 4: Windows Binary Verification Workflow

**Location:** `.github/workflows/verify-binaries-windows.yml`

**Purpose:** Authoritative native Windows rebuild with MSVC.

**Triggers:**
- Changes to `demo/*.cpp` files
- Pull requests
- Manual dispatch

**Jobs:**
```yaml
verify-binaries-windows:
  runs-on: windows-latest
  steps:
    1. Checkout code
    2. Setup MSVC (microsoft/setup-msbuild@v2)
    3. Initialize MSVC environment (vcvarsall.bat x64)
    4. Build with cl.exe or Makefile (if nmake compatible)
    5. Compare rebuilt vs committed binaries
    6. Fail if differences found
```

**Note:** `setup_build_env.sh` is Linux-specific, so Windows workflow uses native MSVC tooling directly.

### Component 5: Binary Comparison Script

**Location:** `demo/scripts/compare_binaries.py`

**Purpose:** Compare rebuilt binaries against committed versions.

**Implementation:**
- Takes two binary paths as arguments
- Fast size comparison first
- Byte-by-byte comparison if needed
- Shows hexdump of first 100 differing bytes on mismatch
- Exits non-zero if differences found

**Usage:**
```bash
python demo/scripts/compare_binaries.py demo/vector_extra_O2.exe demo/vector_extra_O2_rebuilt.exe
```

## Integration with PR #9

The design leverages the new structure from PR #9:

- **Test execution:** Uses top-level `test.py` (single entry point)
- **Binary rebuilding:** Uses `demo/Makefile` targets
- **Build environment:** Leverages existing `demo/build_environments/` scripts
- **Clean paths:** `demo/` instead of `examples/vector_test/`
- **Binaries to verify:**
  - `demo/vector_extra_O2.exe` / `.pdb`
  - `demo/vector_extra_Od.exe` / `.pdb`

## Error Handling and Reporting

### Build Status Visibility
- GitHub Actions badge in README.md showing CI status
- Branch protection rules require all workflows to pass for PR merge

### Failure Modes

**1. Build Failures:**
- Full Gradle build log uploaded as artifact
- Clear error message with artifact download link

**2. Test Failures:**
- Pattern detection mismatches: Show expected vs actual counts
- Ghidra analysis errors: Capture full stderr/stdout from analyzeHeadless
- Upload decompiler output as artifact for debugging

**3. Binary Verification Failures:**
- Show which binary differs (filename + size)
- Upload both versions (rebuilt + committed) as artifacts
- Hexdump first 100 bytes of differences
- Instructions: "Run 'cd demo && make all' locally to update binaries"

**4. Ghidra Version Compatibility:**
- If latest version (11.5.0) fails but 11.4.2 passes:
  - Mark as warning, not hard failure
  - Add PR comment: "Works on 11.4.2, needs investigation for 11.5.0"
- Option: Use `continue-on-error: true` for latest-version test

### Caching Strategy

**Cached items:**
- Ghidra installations per version (~500MB each)
- Gradle dependencies (~200MB)
- Python/uv dependencies

**Cache invalidation:**
- Automatic after 7 days
- Manual invalidation via workflow_dispatch option

## Future Enhancements

**Windows CI support:**
- Composite action already OS-agnostic
- Main workflow can add `windows-latest` to matrix
- Native MSVC build testing

**Additional test binaries:**
- If `vector_basic.cpp` gets built, add to verification
- GCC/Clang builds for broader coverage

**Performance monitoring:**
- Track decompilation time across Ghidra versions
- Detect performance regressions

## Implementation Files

The implementation will create/modify these files:

```
.github/
├── actions/
│   └── setup-ghidra/
│       └── action.yml
└── workflows/
    ├── ci.yml
    ├── verify-binaries-linux.yml
    └── verify-binaries-windows.yml

demo/
└── scripts/
    └── compare_binaries.py

README.md (add CI badge)
```

## Success Metrics

The CI system is successful when:

1. All builds pass on every commit
2. Pattern detection tests catch regressions
3. Binary verification prevents stale test binaries
4. Ghidra version compatibility is validated
5. CI runs complete reliably without flakiness
6. Clear error messages enable quick debugging

## References

- PR #9: Clean up vector test examples directory
- Ghidra releases: https://github.com/NationalSecurityAgency/ghidra/releases
- GitHub Actions composite actions: https://docs.github.com/en/actions/creating-actions/creating-a-composite-action
