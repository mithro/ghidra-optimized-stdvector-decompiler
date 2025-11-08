# GitHub Actions CI Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement comprehensive GitHub Actions CI for the Ghidra Optimized Vector Decompiler with full integration testing, binary verification, and multi-version Ghidra support.

**Architecture:** Modular CI using reusable composite actions. Main workflow tests extension build + Ghidra integration. Separate workflows verify test binaries stay in sync with source files using both Linux (Wine+MSVC) and Windows (native MSVC) builds.

**Tech Stack:** GitHub Actions, Python 3, Ghidra 11.4.2 + 11.5.0, Gradle, Wine/MSVC, uv

---

## Task 1: Create Setup-Ghidra Composite Action

**Files:**
- Create: `.github/actions/setup-ghidra/action.yml`

**Step 1: Create action.yml with inputs and cache**

```yaml
name: 'Setup Ghidra'
description: 'Download, cache, and setup Ghidra for CI'
inputs:
  ghidra-version:
    description: 'Ghidra version to install (e.g., 11.4.2, 11.5.0)'
    required: true
  ghidra-url:
    description: 'Custom download URL (optional)'
    required: false
    default: ''

runs:
  using: 'composite'
  steps:
    - name: Cache Ghidra
      id: cache-ghidra
      uses: actions/cache@v4
      with:
        path: ~/.ghidra-ci/ghidra_${{ inputs.ghidra-version }}
        key: ghidra-${{ inputs.ghidra-version }}-${{ runner.os }}

    - name: Download Ghidra
      if: steps.cache-ghidra.outputs.cache-hit != 'true'
      shell: bash
      run: |
        set -e
        VERSION="${{ inputs.ghidra-version }}"
        INSTALL_DIR="$HOME/.ghidra-ci/ghidra_${VERSION}"
        mkdir -p "$INSTALL_DIR"

        # Determine download URL
        if [ -n "${{ inputs.ghidra-url }}" ]; then
          URL="${{ inputs.ghidra-url }}"
        else
          # Map version to release date
          case "$VERSION" in
            11.4.2)
              DATE="20240926"
              ;;
            11.5.0)
              DATE="20250109"
              ;;
            *)
              echo "ERROR: Unknown Ghidra version $VERSION"
              echo "Please provide custom ghidra-url input"
              exit 1
              ;;
          esac
          URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${VERSION}_build/ghidra_${VERSION}_PUBLIC_${DATE}.zip"
        fi

        echo "Downloading Ghidra ${VERSION} from ${URL}"

        # Download with retries
        for i in 1 2 3; do
          if curl -L -o /tmp/ghidra.zip "$URL"; then
            break
          fi
          echo "Download attempt $i failed, retrying..."
          sleep 5
        done

        # Verify download
        if [ ! -f /tmp/ghidra.zip ]; then
          echo "ERROR: Failed to download Ghidra"
          exit 1
        fi

        # Extract
        echo "Extracting Ghidra..."
        unzip -q /tmp/ghidra.zip -d /tmp/
        mv /tmp/ghidra_${VERSION}_PUBLIC "$INSTALL_DIR/ghidra"
        rm /tmp/ghidra.zip

        # Verify installation
        if [ ! -f "$INSTALL_DIR/ghidra/support/analyzeHeadless" ]; then
          echo "ERROR: Ghidra installation incomplete"
          exit 1
        fi

        echo "Ghidra ${VERSION} installed successfully"

    - name: Set environment variables
      shell: bash
      run: |
        GHIDRA_DIR="$HOME/.ghidra-ci/ghidra_${{ inputs.ghidra-version }}/ghidra"
        echo "GHIDRA_INSTALL_DIR=$GHIDRA_DIR" >> $GITHUB_ENV
        echo "$GHIDRA_DIR/support" >> $GITHUB_PATH
        echo "Ghidra ready at $GHIDRA_DIR"
```

**Step 2: Test action locally (manual verification)**

Create test workflow `.github/workflows/test-setup-action.yml`:
```yaml
name: Test Setup Action
on: workflow_dispatch
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/setup-ghidra
        with:
          ghidra-version: '11.4.2'
      - run: |
          echo "GHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR"
          ls -la "$GHIDRA_INSTALL_DIR"
          analyzeHeadless -help | head -5
```

Note: This test workflow will be deleted after main CI is working.

**Step 3: Commit composite action**

```bash
git add .github/actions/setup-ghidra/action.yml
git commit -m "feat: Add setup-ghidra composite action

Reusable action for downloading and caching Ghidra installations.
Supports 11.4.2 and 11.5.0 with automatic date mapping."
```

---

## Task 2: Create Main CI Workflow

**Files:**
- Create: `.github/workflows/ci.yml`

**Step 1: Create CI workflow with build job**

```yaml
name: CI

on:
  push:
    branches: ['**']
  pull_request:
    branches: ['**']
  workflow_dispatch:

jobs:
  build:
    name: Build Extension
    runs-on: ubuntu-latest
    strategy:
      matrix:
        java-version: ['21']

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Java
        uses: actions/setup-java@v4
        with:
          distribution: 'temurin'
          java-version: ${{ matrix.java-version }}
          cache: 'gradle'

      - name: Build extension
        run: |
          cd extension
          chmod +x build.sh
          ./build.sh
        env:
          GHIDRA_INSTALL_DIR: /tmp/ghidra-dummy

      - name: Upload JAR artifact
        uses: actions/upload-artifact@v4
        with:
          name: extension-jar-java${{ matrix.java-version }}
          path: extension/build/libs/*.jar
          retention-days: 7
```

**Step 2: Add test job to CI workflow**

Add after the `build` job:

```yaml
  test:
    name: Test with Ghidra ${{ matrix.ghidra-version }}
    runs-on: ubuntu-latest
    needs: build
    strategy:
      matrix:
        ghidra-version: ['11.4.2', '11.5.0']
        java-version: ['21']

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Java
        uses: actions/setup-java@v4
        with:
          distribution: 'temurin'
          java-version: ${{ matrix.java-version }}

      - name: Setup Ghidra
        uses: ./.github/actions/setup-ghidra
        with:
          ghidra-version: ${{ matrix.ghidra-version }}

      - name: Download extension JAR
        uses: actions/download-artifact@v4
        with:
          name: extension-jar-java${{ matrix.java-version }}
          path: extension/build/libs/

      - name: Install extension to Ghidra
        run: |
          mkdir -p "$GHIDRA_INSTALL_DIR/Extensions/Ghidra"
          cp extension/build/libs/*.jar "$GHIDRA_INSTALL_DIR/Extensions/Ghidra/"
          echo "Extension installed to $GHIDRA_INSTALL_DIR/Extensions/Ghidra/"
          ls -lh "$GHIDRA_INSTALL_DIR/Extensions/Ghidra/"

      - name: Copy extension to Decompiler lib (headless mode)
        run: |
          mkdir -p "$GHIDRA_INSTALL_DIR/Ghidra/Features/Decompiler/lib"
          cp extension/build/libs/*.jar "$GHIDRA_INSTALL_DIR/Ghidra/Features/Decompiler/lib/"

      - name: Setup Python and uv
        run: |
          curl -LsSf https://astral.sh/uv/install.sh | sh
          echo "$HOME/.cargo/bin" >> $GITHUB_PATH

      - name: Run integration tests
        run: |
          export PATH="$HOME/.cargo/bin:$PATH"
          uv run python test.py
        env:
          GHIDRA_INSTALL_DIR: ${{ env.GHIDRA_INSTALL_DIR }}

      - name: Upload test logs on failure
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: test-logs-ghidra${{ matrix.ghidra-version }}
          path: |
            **/*.log
            /tmp/*.log
          retention-days: 7
```

**Step 3: Commit main CI workflow**

```bash
git add .github/workflows/ci.yml
git commit -m "feat: Add main CI workflow

Builds extension and tests against Ghidra 11.4.2 and 11.5.0.
Matrix strategy ensures compatibility across versions."
```

---

## Task 3: Create Binary Comparison Script

**Files:**
- Create: `demo/scripts/compare_binaries.py`

**Step 1: Write comparison script**

```python
#!/usr/bin/env python3
"""Compare two binary files and report differences."""

import sys
import os
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
```

**Step 2: Make script executable**

```bash
chmod +x demo/scripts/compare_binaries.py
```

**Step 3: Test comparison script locally**

```bash
# Test identical files
cp demo/vector_extra_O2.exe /tmp/test_same.exe
uv run python demo/scripts/compare_binaries.py demo/vector_extra_O2.exe /tmp/test_same.exe
# Expected: exit 0, prints "IDENTICAL"

# Test different files
echo "different" > /tmp/test_diff.exe
uv run python demo/scripts/compare_binaries.py demo/vector_extra_O2.exe /tmp/test_diff.exe
# Expected: exit 1, prints "DIFFERENT" with hexdump

# Test missing file
uv run python demo/scripts/compare_binaries.py demo/vector_extra_O2.exe /tmp/nonexistent.exe
# Expected: exit 2, prints "ERROR: File not found"

rm -f /tmp/test_same.exe /tmp/test_diff.exe
```

**Step 4: Commit comparison script**

```bash
git add demo/scripts/compare_binaries.py
git commit -m "feat: Add binary comparison script

Compares two binaries and shows hexdump of differences.
Exits with 0 (identical), 1 (different), or 2 (error)."
```

---

## Task 4: Create Linux Binary Verification Workflow

**Files:**
- Create: `.github/workflows/verify-binaries-linux.yml`

**Step 1: Create Linux verification workflow**

```yaml
name: Verify Binaries (Linux)

on:
  pull_request:
    paths:
      - 'demo/*.cpp'
      - 'demo/Makefile'
      - 'demo/build_environments/**'
  push:
    paths:
      - 'demo/*.cpp'
      - 'demo/Makefile'
      - 'demo/build_environments/**'
  workflow_dispatch:

jobs:
  verify-linux:
    name: Rebuild and verify binaries (Wine + MSVC)
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Install Wine dependencies
        run: |
          sudo dpkg --add-architecture i386
          sudo apt-get update
          sudo apt-get install -y wine64 wine32 wine winetricks
          wine --version

      - name: Setup MSVC in Wine
        run: |
          cd demo/build_environments
          chmod +x setup_msvc_wine.sh install_wine_deps.sh
          ./setup_msvc_wine.sh
        timeout-minutes: 30

      - name: Build binaries with Wine+MSVC
        run: |
          cd demo
          make clean
          make all
        timeout-minutes: 10

      - name: Setup Python and uv
        run: |
          curl -LsSf https://astral.sh/uv/install.sh | sh
          echo "$HOME/.cargo/bin" >> $GITHUB_PATH

      - name: Compare rebuilt binaries to committed versions
        run: |
          export PATH="$HOME/.cargo/bin:$PATH"
          EXIT_CODE=0

          for binary in demo/vector_extra_O2.exe demo/vector_extra_Od.exe; do
            if [ -f "${binary}.rebuilt" ]; then
              echo "Comparing $binary..."
              if ! uv run python demo/scripts/compare_binaries.py "$binary" "${binary}.rebuilt"; then
                EXIT_CODE=1
              fi
            else
              echo "WARNING: Rebuilt binary not found: ${binary}.rebuilt"
              EXIT_CODE=1
            fi
          done

          if [ $EXIT_CODE -ne 0 ]; then
            echo ""
            echo "ERROR: Binaries are out of sync with source code!"
            echo "To update binaries, run locally:"
            echo "  cd demo && make all"
            echo "  git add *.exe *.pdb"
            echo "  git commit -m 'build: Update test binaries'"
          fi

          exit $EXIT_CODE

      - name: Upload rebuilt binaries for inspection
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: rebuilt-binaries-linux
          path: demo/*.rebuilt
          retention-days: 7
```

**Step 2: Commit Linux verification workflow**

```bash
git add .github/workflows/verify-binaries-linux.yml
git commit -m "feat: Add Linux binary verification workflow

Uses Wine + MSVC to rebuild test binaries and compare to committed versions.
Ensures binaries stay in sync with source code."
```

---

## Task 5: Create Windows Binary Verification Workflow

**Files:**
- Create: `.github/workflows/verify-binaries-windows.yml`

**Step 1: Create Windows verification workflow**

```yaml
name: Verify Binaries (Windows)

on:
  pull_request:
    paths:
      - 'demo/*.cpp'
  push:
    paths:
      - 'demo/*.cpp'
  workflow_dispatch:

jobs:
  verify-windows:
    name: Rebuild and verify binaries (Native MSVC)
    runs-on: windows-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup MSVC
        uses: microsoft/setup-msbuild@v2

      - name: Setup MSVC environment
        uses: ilammy/msvc-dev-cmd@v1
        with:
          arch: x64

      - name: Build binaries with MSVC
        shell: cmd
        run: |
          cd demo

          REM Build optimized version
          cl /EHsc /O2 /Fe:vector_extra_O2_rebuilt.exe vector_extra.cpp /link /DEBUG /PDB:vector_extra_O2_rebuilt.pdb

          REM Build debug version
          cl /EHsc /Od /Fe:vector_extra_Od_rebuilt.exe vector_extra.cpp /link /DEBUG /PDB:vector_extra_Od_rebuilt.pdb

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install uv
        shell: bash
        run: |
          curl -LsSf https://astral.sh/uv/install.sh | sh
          echo "$HOME/.cargo/bin" >> $GITHUB_PATH

      - name: Compare rebuilt binaries to committed versions
        shell: bash
        run: |
          export PATH="$HOME/.cargo/bin:$PATH"
          EXIT_CODE=0

          cd demo

          for base in vector_extra_O2 vector_extra_Od; do
            echo "Comparing ${base}.exe..."
            if ! uv run python scripts/compare_binaries.py "${base}.exe" "${base}_rebuilt.exe"; then
              EXIT_CODE=1
            fi
          done

          if [ $EXIT_CODE -ne 0 ]; then
            echo ""
            echo "ERROR: Binaries are out of sync with source code!"
            echo "To update binaries on Windows:"
            echo "  cd demo"
            echo "  cl /EHsc /O2 /Fe:vector_extra_O2.exe vector_extra.cpp /link /DEBUG"
            echo "  cl /EHsc /Od /Fe:vector_extra_Od.exe vector_extra.cpp /link /DEBUG"
            echo "  git add *.exe *.pdb"
            echo "  git commit -m 'build: Update test binaries'"
          fi

          exit $EXIT_CODE

      - name: Upload rebuilt binaries for inspection
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: rebuilt-binaries-windows
          path: demo/*_rebuilt.*
          retention-days: 7
```

**Step 2: Commit Windows verification workflow**

```bash
git add .github/workflows/verify-binaries-windows.yml
git commit -m "feat: Add Windows binary verification workflow

Uses native MSVC on Windows runners to rebuild test binaries.
Provides authoritative verification of binary freshness."
```

---

## Task 6: Add CI Status Badge to README

**Files:**
- Modify: `README.md`

**Step 1: Add CI badge at top of README**

Find the top of README.md (after the title) and add:

```markdown
# Ghidra Optimized Vector Decompiler

[![CI](https://github.com/mithro/ghidra-optimized-stdvector-decompiler/actions/workflows/ci.yml/badge.svg)](https://github.com/mithro/ghidra-optimized-stdvector-decompiler/actions/workflows/ci.yml)
[![Verify Binaries (Linux)](https://github.com/mithro/ghidra-optimized-stdvector-decompiler/actions/workflows/verify-binaries-linux.yml/badge.svg)](https://github.com/mithro/ghidra-optimized-stdvector-decompiler/actions/workflows/verify-binaries-linux.yml)
[![Verify Binaries (Windows)](https://github.com/mithro/ghidra-optimized-stdvector-decompiler/actions/workflows/verify-binaries-windows.yml/badge.svg)](https://github.com/mithro/ghidra-optimized-stdvector-decompiler/actions/workflows/verify-binaries-windows.yml)

[rest of README content...]
```

**Step 2: Commit README update**

```bash
git add README.md
git commit -m "docs: Add CI status badges to README

Shows build status and binary verification status at a glance."
```

---

## Task 7: Delete Test Workflow (Cleanup)

**Files:**
- Delete: `.github/workflows/test-setup-action.yml` (if created in Task 1)

**Step 1: Remove test workflow**

```bash
git rm .github/workflows/test-setup-action.yml
git commit -m "chore: Remove temporary test workflow

No longer needed now that main CI is working."
```

Note: Skip this task if you didn't create the test workflow in Task 1.

---

## Task 8: Test CI End-to-End

**Step 1: Push branch and create PR**

```bash
git push -u origin github-actions-ci
```

**Step 2: Create pull request**

```bash
gh pr create --title "Add GitHub Actions CI" --body "$(cat <<'EOF'
Implements comprehensive CI system:

- ✅ Build verification with Gradle
- ✅ Integration testing with Ghidra 11.4.2 and 11.5.0
- ✅ Binary verification (Linux + Windows)
- ✅ Status badges in README

Closes #[issue number if applicable]

## Testing

All workflows should pass:
- CI workflow runs on push/PR
- Binary verification workflows run when demo/*.cpp changes
- Caching works (second runs are faster)

## Design Document

See `docs/plans/2025-11-08-github-actions-ci-design.md` for full design.
EOF
)"
```

**Step 3: Monitor workflow runs**

```bash
# Watch CI workflow
gh run watch

# Check workflow status
gh run list --workflow=ci.yml --limit 5
```

**Step 4: Verify expected behavior**

Expected outcomes:
- ✅ Build job completes in ~2-3 minutes
- ✅ Test job completes in ~5-10 minutes per Ghidra version
- ✅ Both Ghidra 11.4.2 and 11.5.0 tests pass
- ✅ Pattern detection shows: 2 EMPTY, 1 SIZE, 1 CAPACITY, 1 DATA
- ✅ Binary verification workflows only run if demo/*.cpp changed
- ✅ Caching works (check workflow logs for "Cache restored")

If any workflow fails:
1. Check workflow logs in GitHub Actions tab
2. Download artifacts if tests failed
3. Fix issues and push new commit
4. Workflows automatically re-run

**Step 5: Request review when green**

```bash
# Add reviewers if applicable
gh pr ready
```

---

## Post-Implementation Tasks

After PR is merged:

1. **Update CLAUDE.md** with CI information:
   ```markdown
   ## Continuous Integration

   GitHub Actions CI automatically:
   - Builds extension for every commit
   - Tests against Ghidra 11.4.2 and 11.5.0
   - Verifies test binaries match source code

   All workflows must pass before merging PRs.
   ```

2. **Enable branch protection** in GitHub settings:
   - Require CI workflow to pass
   - Require binary verification to pass
   - Require review from code owners

3. **Monitor CI performance**:
   - Check cache hit rates
   - Watch for flaky tests
   - Update Ghidra versions as new releases come out

---

## Troubleshooting Guide

### Build Fails in CI but Works Locally

**Symptom:** Gradle build fails with "GHIDRA_INSTALL_DIR not set"

**Fix:** The build job uses a dummy GHIDRA_INSTALL_DIR. Ensure build.sh doesn't require actual Ghidra for compilation.

### Tests Fail with "Pattern not found"

**Symptom:** Integration tests can't find expected patterns

**Fix:**
1. Check test.py expects correct pattern counts
2. Verify extension JAR copied to both locations:
   - `$GHIDRA_INSTALL_DIR/Extensions/Ghidra/`
   - `$GHIDRA_INSTALL_DIR/Ghidra/Features/Decompiler/lib/`
3. Check Ghidra version compatibility

### Binary Verification Fails

**Symptom:** "Binaries are out of sync"

**Fix:**
1. Rebuild locally: `cd demo && make all`
2. Commit updated binaries: `git add demo/*.exe demo/*.pdb`
3. If intentional source change, this is expected

### Wine Setup Times Out

**Symptom:** Linux binary verification times out during MSVC setup

**Fix:**
1. Increase timeout in workflow (currently 30 min)
2. Consider caching Wine prefix
3. May need to mark as `continue-on-error: true` if unreliable

### Ghidra Download Fails

**Symptom:** "Failed to download Ghidra" error

**Fix:**
1. Check Ghidra version and date mapping in action.yml
2. Verify GitHub releases URL is correct
3. May need to update DATE for new Ghidra releases

---

## Skills Referenced

- @superpowers:test-driven-development - Not applicable (infrastructure, no unit tests needed)
- @superpowers:verification-before-completion - REQUIRED before claiming tasks complete
- @superpowers:brainstorming - Already completed (produced this plan)
