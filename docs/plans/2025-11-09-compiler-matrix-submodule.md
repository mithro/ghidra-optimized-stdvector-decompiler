# Compiler Matrix Submodule Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Move demo binaries to dedicated git submodule with multi-compiler support

**Architecture:** Create git submodule at demo/out organized by compiler (clang-19/, msvc-14.44/), update Makefile with COMPILER variable for flexible builds, modify test.py to validate all compiler variants automatically.

**Tech Stack:** Git submodules, GNU Make, Python 3, Ghidra headless analysis

---

## Task 1: Initialize Submodule

**Files:**
- Create: `.gitmodules`
- Modify: None

**Step 1: Add git submodule**

Run:
```bash
cd demo
git submodule add https://github.com/mithro/ghidra-optimized-stdvector-decompiler-demo-out.git out
```

Expected output: `Cloning into 'demo/out'...` and submodule created

**Step 2: Verify submodule initialized**

Run:
```bash
ls -la demo/out/.git
cat .gitmodules
```

Expected: `.git` file exists in demo/out/, `.gitmodules` contains submodule reference

**Step 3: Commit submodule addition**

Run:
```bash
git add .gitmodules demo/out
git commit -m "feat: add demo binary outputs submodule"
```

Expected: Commit created with submodule reference

---

## Task 2: Create Submodule Directory Structure

**Files:**
- Create: `demo/out/clang-19/` (directory)
- Create: `demo/out/README.md`

**Step 1: Create compiler directory**

Run:
```bash
cd demo/out
mkdir -p clang-19
```

Expected: Directory created

**Step 2: Create submodule README**

Create: `demo/out/README.md`

```markdown
# Demo Binary Outputs

Pre-compiled demonstration binaries for the [Ghidra Optimized Vector Decompiler](https://github.com/mithro/ghidra-optimized-stdvector-decompiler).

This submodule stores test binaries compiled with different Windows C++ compilers to verify the plugin works correctly across compiler variations.

**Main Repository**: https://github.com/mithro/ghidra-optimized-stdvector-decompiler

## Compiler Matrix

| Compiler | Version | Build Date | Notes |
|----------|---------|------------|-------|
| clang-19 | 19.x.x  | 2025-11-09 | LLVM 19 with clang-cl MSVC compatibility |
| clang-20 | 20.x.x  | TBD        | LLVM 20 with clang-cl MSVC compatibility |
| msvc-14.44 | 14.44.35207 | TBD   | Native MSVC via Wine |

## Directory Structure

Each compiler has its own directory with O2 (optimized) and Od (debug) variants:
- `{compiler}/vector_basic_O2.exe` - Basic vector operations, optimized
- `{compiler}/vector_basic_O2.pdb` - Debug symbols for optimized build
- `{compiler}/vector_basic_Od.exe` - Basic vector operations, debug
- `{compiler}/vector_basic_Od.pdb` - Debug symbols for debug build
- `{compiler}/vector_extra_O2.exe` - Extended patterns, optimized
- `{compiler}/vector_extra_O2.pdb` - Debug symbols for optimized build
- `{compiler}/vector_extra_Od.exe` - Extended patterns, debug
- `{compiler}/vector_extra_Od.pdb` - Debug symbols for debug build

All binaries include PDB debug symbols for proper Ghidra analysis.

## Building New Compiler Variants

From main repository:

```bash
cd demo

# Build with specific compiler
make COMPILER=clang-20 all

# Commit to submodule
cd out
git add clang-20/
git commit -m "Add clang-20 binaries"
git push

# Update main repo reference
cd ../..
git add demo/out
git commit -m "Update demo binaries: add clang-20"
```
```

**Step 3: Commit submodule README**

Run:
```bash
cd demo/out
git add README.md clang-19/
git commit -m "docs: add submodule README and directory structure"
git push origin main
```

Expected: README committed to submodule repo

**Step 4: Update submodule reference in main repo**

Run:
```bash
cd ../..
git add demo/out
git commit -m "chore: update submodule with README"
```

Expected: Main repo updated with new submodule commit

---

## Task 3: Move Existing Binaries

**Files:**
- Move: `demo/*.exe` → `demo/out/clang-19/`
- Move: `demo/*.pdb` → `demo/out/clang-19/`

**Step 1: Move binaries to submodule**

Run:
```bash
cd demo
mv *.exe *.pdb out/clang-19/ 2>/dev/null || echo "Some files may not exist"
ls -la out/clang-19/
```

Expected: All .exe and .pdb files moved to out/clang-19/

**Step 2: Commit binaries in submodule**

Run:
```bash
cd out
git add clang-19/
git commit -m "feat: add initial clang-19 binaries"
git push origin main
```

Expected: Binaries committed to submodule

**Step 3: Update main repo submodule reference**

Run:
```bash
cd ../..
git add demo/out
git commit -m "chore: update submodule with clang-19 binaries"
```

Expected: Main repo tracks new submodule commit

**Step 4: Remove old binaries from main repo**

Run:
```bash
git rm demo/*.exe demo/*.pdb 2>/dev/null || echo "Already removed"
git status
```

Expected: Old binary references removed from git index

**Step 5: Commit removal**

Run:
```bash
git commit -m "chore: remove binaries from main repo (now in submodule)"
```

Expected: Commit removing binary files from main repo history

---

## Task 4: Update Makefile - Add COMPILER Variable

**Files:**
- Modify: `demo/Makefile:1-50`

**Step 1: Add COMPILER and OUT_DIR variables**

Modify: `demo/Makefile` (add after line 9, before MSVC paths)

```makefile
# Compiler identification for output directory
COMPILER ?= clang-19
OUT_DIR = out/$(COMPILER)
```

**Step 2: Verify syntax**

Run:
```bash
cd demo
make -n check-env
```

Expected: No syntax errors, dry-run completes

**Step 3: Commit Makefile variable addition**

Run:
```bash
git add demo/Makefile
git commit -m "feat: add COMPILER variable to Makefile"
```

Expected: Commit with COMPILER variable added

---

## Task 5: Update Makefile - Modify Build Rules

**Files:**
- Modify: `demo/Makefile:67-78`

**Step 1: Update O2 pattern rule**

Replace lines 68-72 in `demo/Makefile`:

```makefile
%_O2.exe: %.cpp init-submodule
	@echo "Building optimized binary: $@ with $(COMPILER)"
	@mkdir -p $(OUT_DIR)
	$(CLANG_CL) $(CXXFLAGS_COMMON) $(CXXFLAGS_O2) \
		/Fe:$(OUT_DIR)/$@ $< \
		/link $(LINKFLAGS) $(LINKFLAGS_O2)
```

**Step 2: Update Od pattern rule**

Replace lines 74-78 in `demo/Makefile`:

```makefile
%_Od.exe: %.cpp init-submodule
	@echo "Building debug binary: $@ with $(COMPILER)"
	@mkdir -p $(OUT_DIR)
	$(CLANG_CL) $(CXXFLAGS_COMMON) $(CXXFLAGS_Od) \
		/Fe:$(OUT_DIR)/$@ $< \
		/link $(LINKFLAGS) $(LINKFLAGS_Od)
```

**Step 3: Add init-submodule target**

Add before the pattern rules (around line 67):

```makefile
# Initialize submodule if not already done
.PHONY: init-submodule
init-submodule:
	@if [ ! -f out/.git ]; then \
		echo "Initializing submodule..."; \
		git submodule update --init demo/out; \
	fi
```

**Step 4: Test dry-run**

Run:
```bash
cd demo
make -n vector_extra_O2.exe
```

Expected: Shows mkdir and compilation commands with $(OUT_DIR) path

**Step 5: Commit build rule updates**

Run:
```bash
git add demo/Makefile
git commit -m "feat: update build rules to output to submodule"
```

Expected: Commit with updated build rules

---

## Task 6: Update Makefile - Add Helper Targets

**Files:**
- Modify: `demo/Makefile:190-199` (after help section)

**Step 1: Add list-compilers target**

Add at end of `demo/Makefile`:

```makefile

# List available compiler directories
.PHONY: list-compilers
list-compilers:
	@echo "Available compilers in out/:"
	@if [ -d out ]; then \
		ls -d out/*/ 2>/dev/null | sed 's|out/||' | sed 's|/||' || echo "  (none found)"; \
	else \
		echo "  Submodule not initialized. Run: git submodule update --init"; \
	fi
```

**Step 2: Update clean target**

Replace clean target (around line 154):

```makefile
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -f *.obj *.ilk *.exp *.lib
	@echo "Note: Binaries are in out/$(COMPILER)/ - use 'make clean-binaries' to remove"
	@echo "Cleaned."

# Clean binaries for current compiler
.PHONY: clean-binaries
clean-binaries:
	@echo "Cleaning binaries for $(COMPILER)..."
	rm -f $(OUT_DIR)/*.exe $(OUT_DIR)/*.pdb
	@echo "Cleaned."
```

**Step 3: Test list-compilers**

Run:
```bash
cd demo
make list-compilers
```

Expected: Shows "clang-19" directory

**Step 4: Commit helper targets**

Run:
```bash
git add demo/Makefile
git commit -m "feat: add list-compilers and clean-binaries targets"
```

Expected: Commit with helper targets

---

## Task 7: Update Makefile - Fix Test Target

**Files:**
- Modify: `demo/Makefile:138-150`

**Step 1: Update test target**

Replace test target (lines 138-150):

```makefile
# Run pattern analysis
.PHONY: test
test: init-submodule
	@echo "Running pattern analysis on all compilers..."
	@if [ ! -f "../test.py" ]; then \
		echo "Warning: ../test.py not found"; \
		exit 1; \
	else \
		cd .. && python3 test.py; \
	fi
```

**Step 2: Test dry-run**

Run:
```bash
cd demo
make -n test
```

Expected: Shows init-submodule check and python3 test.py command

**Step 3: Commit test target update**

Run:
```bash
git add demo/Makefile
git commit -m "feat: update test target for multi-compiler validation"
```

Expected: Commit with updated test target

---

## Task 8: Update test.py - Add Compiler Discovery

**Files:**
- Modify: `test.py:1-50`

**Step 1: Read current test.py structure**

Run:
```bash
head -50 ../test.py
```

Expected: See current test.py implementation

**Step 2: Create backup**

Run:
```bash
cp test.py test.py.backup
```

Expected: Backup created

**Step 3: Update imports and add discover_compilers function**

Add after imports in `test.py`:

```python
import os
from pathlib import Path

def discover_compilers(demo_dir="demo"):
    """Discover all compiler directories in demo/out/"""
    out_dir = Path(demo_dir) / "out"

    if not out_dir.exists():
        print(f"ERROR: {out_dir} does not exist")
        print("Run: git submodule update --init")
        return []

    compilers = []
    for item in out_dir.iterdir():
        if item.is_dir() and not item.name.startswith('.'):
            compilers.append(item.name)

    return sorted(compilers)
```

**Step 4: Verify syntax**

Run:
```bash
python3 -m py_compile test.py
```

Expected: No syntax errors

**Step 5: Commit compiler discovery**

Run:
```bash
git add test.py
git commit -m "feat: add compiler discovery to test.py"
```

Expected: Commit with discovery function

---

## Task 9: Update test.py - Multi-Compiler Validation Loop

**Files:**
- Modify: `test.py:50-end`

**Step 1: Add test_compiler function**

Add function to wrap existing test logic:

```python
def test_compiler(compiler, demo_dir="demo"):
    """Test binaries for a specific compiler"""
    binary_path = Path(demo_dir) / "out" / compiler / "vector_extra_O2.exe"

    if not binary_path.exists():
        print(f"  ⚠ Skipping {compiler}: vector_extra_O2.exe not found")
        return None

    print(f"\nTesting {compiler}/vector_extra_O2.exe...")

    # Run existing Ghidra analysis here
    # (wrap existing test logic)

    # Return True for pass, False for fail
    return True  # placeholder
```

**Step 2: Update main() function**

Replace main test logic with multi-compiler loop:

```python
def main():
    compilers = discover_compilers()

    if not compilers:
        print("ERROR: No compilers found in demo/out/")
        return 1

    print(f"Found {len(compilers)} compiler(s): {', '.join(compilers)}")

    results = {}
    for compiler in compilers:
        result = test_compiler(compiler)
        if result is not None:
            results[compiler] = result

    # Print summary
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)

    passed = sum(1 for r in results.values() if r)
    total = len(results)

    for compiler, result in sorted(results.items()):
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status}: {compiler}")

    print(f"\nResult: {passed}/{total} compilers passed")

    return 0 if passed == total else 1

if __name__ == "__main__":
    sys.exit(main())
```

**Step 3: Verify syntax**

Run:
```bash
python3 -m py_compile test.py
```

Expected: No syntax errors

**Step 4: Commit multi-compiler validation**

Run:
```bash
git add test.py
git commit -m "feat: add multi-compiler validation loop"
```

Expected: Commit with validation loop

---

## Task 10: Update test.py - Integrate Existing Test Logic

**Files:**
- Modify: `test.py` (complete integration)

**Step 1: Move existing Ghidra analysis into test_compiler**

Integrate existing test.py Ghidra analysis code into `test_compiler()` function, updating paths to use `binary_path` parameter.

**Step 2: Test against clang-19**

Run:
```bash
python3 test.py
```

Expected: Runs analysis on clang-19/vector_extra_O2.exe, shows pattern counts

**Step 3: Verify output format**

Expected output format:
```
Found 1 compiler(s): clang-19

Testing clang-19/vector_extra_O2.exe...
  ✓ SIZE patterns: 5 found
  ✓ EMPTY patterns: 7 found
  ✓ CAPACITY patterns: 7 found
  ✓ DATA patterns: 2 found

============================================================
SUMMARY
============================================================
  ✓ PASS: clang-19

Result: 1/1 compilers passed
```

**Step 4: Commit integrated test**

Run:
```bash
git add test.py
git commit -m "feat: integrate Ghidra analysis into multi-compiler test"
```

Expected: Commit with complete integrated test

---

## Task 11: Update Documentation - CLAUDE.md

**Files:**
- Modify: `CLAUDE.md:30-80` (Build Commands section)

**Step 1: Update Build Commands section**

Replace Build Commands section in `CLAUDE.md`:

```markdown
## Build Commands

### Build the Extension
```bash
cd extension
export GHIDRA_INSTALL_DIR=/path/to/ghidra  # or set in environment
./build.sh
```

The build script automatically:
- Detects suitable Gradle version (requires 8.0+)
- Offers to install Gradle 8.10.2 locally if needed
- Builds the extension using Ghidra's buildExtension.gradle

### Build Demo Binaries

**Clone with submodule:**
```bash
git clone --recurse-submodules git@github.com:mithro/ghidra-optimized-stdvector-decompiler.git
# OR if already cloned:
git submodule update --init
```

**Build with default compiler (clang-19):**
```bash
cd demo
make
```

**Build with specific compiler:**
```bash
make COMPILER=clang-20 all
make COMPILER=msvc-14.44 optimized
```

**List available compilers:**
```bash
make list-compilers
```

### One-Step Setup (Recommended)
```bash
./setup.sh
```

This script:
1. Checks for Ghidra installation
2. Verifies Java version
3. Builds the extension
4. Installs to Ghidra Extensions directory
5. Copies JAR to Decompiler lib for headless mode
6. Auto-enables the extension in preferences
```

**Step 2: Verify markdown syntax**

Run:
```bash
python3 -c "import markdown; markdown.markdown(open('CLAUDE.md').read())"
```

Expected: No errors (or use markdown linter if available)

**Step 3: Commit CLAUDE.md updates**

Run:
```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md with compiler matrix usage"
```

Expected: Commit with updated documentation

---

## Task 12: Update Documentation - demo/README.md

**Files:**
- Modify: `demo/README.md` (add Multi-Compiler Build section)

**Step 1: Read current demo/README.md**

Run:
```bash
cat demo/README.md
```

Expected: See current structure

**Step 2: Add Multi-Compiler Build section**

Add section to `demo/README.md` (after build instructions):

```markdown
## Multi-Compiler Build Matrix

Demo binaries are stored in a git submodule at `demo/out/` organized by compiler.

### Available Compilers

List available compilers:
```bash
make list-compilers
```

Current matrix:
- `clang-19` - LLVM 19 with clang-cl MSVC compatibility
- `clang-20` - LLVM 20 with clang-cl MSVC compatibility
- `msvc-14.44` - Native MSVC 14.44.35207 via Wine

### Building for Different Compilers

**Default (clang-19):**
```bash
make
```

**Specific compiler:**
```bash
make COMPILER=clang-20 all
make COMPILER=msvc-14.44 optimized
```

**Output location:** `out/{compiler}/vector_*_O2.exe`

### Adding New Compiler Variants

1. Build binaries:
```bash
make COMPILER=clang-21 all
```

2. Commit to submodule:
```bash
cd out
git add clang-21/
git commit -m "Add clang-21 binaries"
git push
```

3. Update main repo:
```bash
cd ../..
git add demo/out
git commit -m "Update binaries: add clang-21"
```

### Testing

Test all compilers:
```bash
cd ..
python3 test.py
```

Tests automatically discover and validate all compiler variants.
```

**Step 3: Commit demo/README.md updates**

Run:
```bash
git add demo/README.md
git commit -m "docs: add multi-compiler build documentation"
```

Expected: Commit with updated demo README

---

## Task 13: Update Documentation - Root README.md

**Files:**
- Modify: `README.md` (add submodule clone instructions)

**Step 1: Find setup/installation section**

Run:
```bash
grep -n "git clone\|Installation\|Setup" README.md | head -5
```

Expected: Find line numbers for setup section

**Step 2: Update clone instructions**

Update git clone command in README.md to:

```markdown
## Installation

Clone the repository with submodules:

```bash
git clone --recurse-submodules git@github.com:mithro/ghidra-optimized-stdvector-decompiler.git
cd ghidra-optimized-stdvector-decompiler
```

If already cloned without submodules:

```bash
git submodule update --init
```
```

**Step 3: Commit README.md updates**

Run:
```bash
git add README.md
git commit -m "docs: add submodule clone instructions to README"
```

Expected: Commit with updated README

---

## Task 14: Verify End-to-End Workflow

**Files:**
- None (verification only)

**Step 1: Test submodule initialization**

Run:
```bash
# Simulate fresh clone
cd /tmp
git clone --recurse-submodules /home/tim/github/mithro/ghidra-optimized-stdvector-decompiler/.worktrees/compiler-matrix-submodule test-clone
cd test-clone
ls -la demo/out/
```

Expected: Submodule populated with clang-19/ and README.md

**Step 2: Test build with default compiler**

Run:
```bash
cd demo
make check-env
make COMPILER=clang-19 vector_extra_O2.exe
ls -la out/clang-19/vector_extra_O2.exe
```

Expected: Binary built in out/clang-19/

**Step 3: Test multi-compiler test script**

Run:
```bash
cd ..
python3 test.py
```

Expected: Tests run against clang-19, shows summary

**Step 4: Test list-compilers**

Run:
```bash
cd demo
make list-compilers
```

Expected: Shows "clang-19"

**Step 5: Clean up test clone**

Run:
```bash
cd /tmp
rm -rf test-clone
```

Expected: Test directory removed

---

## Task 15: Final Commit and Summary

**Files:**
- None (summary only)

**Step 1: Check git status**

Run:
```bash
git status
```

Expected: Working tree clean (all changes committed)

**Step 2: Review commit log**

Run:
```bash
git log --oneline origin/main..HEAD
```

Expected: See all implementation commits

**Step 3: Create summary of changes**

Document what was implemented:
- ✓ Git submodule initialized at demo/out
- ✓ Existing binaries moved to out/clang-19/
- ✓ Makefile updated with COMPILER variable
- ✓ Makefile build rules output to $(OUT_DIR)
- ✓ test.py updated for multi-compiler discovery
- ✓ Documentation updated (CLAUDE.md, README.md, demo/README.md)
- ✓ Submodule README.md created
- ✓ End-to-end workflow verified

**Step 4: Ready for code review**

Implementation complete. Ready for:
- Code review using superpowers:requesting-code-review
- Merge to main using superpowers:finishing-a-development-branch

---

## Verification Checklist

After completing all tasks:

- [ ] Submodule initialized and accessible
- [ ] Binaries moved from demo/ to demo/out/clang-19/
- [ ] `make` builds to out/clang-19/ by default
- [ ] `make COMPILER=clang-20` would build to out/clang-20/
- [ ] `make list-compilers` shows available compilers
- [ ] `python3 test.py` discovers and tests all compilers
- [ ] Fresh clone with `--recurse-submodules` populates submodule
- [ ] Documentation updated in all locations
- [ ] All commits follow conventional commit format

## Related Skills

- @superpowers:executing-plans - Execute this plan in controlled batches
- @superpowers:subagent-driven-development - Execute with fresh subagent per task
- @superpowers:requesting-code-review - Review implementation after completion
- @superpowers:finishing-a-development-branch - Merge/PR after review passes
