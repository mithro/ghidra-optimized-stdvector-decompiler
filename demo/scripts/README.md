# Demo Scripts

This directory contains utility scripts for working with the demo binaries and Ghidra analysis.

## Binary Management

### `download_binaries_from_ci.py`

Downloads rebuilt binaries from GitHub Actions workflow artifacts and places them in the correct locations.

**List available workflow runs:**
```bash
python scripts/download_binaries_from_ci.py --list
```

**Download from latest successful run (all compilers):**
```bash
python scripts/download_binaries_from_ci.py
```

**Download specific compiler only:**
```bash
python scripts/download_binaries_from_ci.py --compiler clang-19
```

**Download from specific workflow run:**
```bash
python scripts/download_binaries_from_ci.py --run-id 19216408103
```

**After downloading, commit to submodule:**
```bash
cd demo/out
git status
git add clang-19/*.exe clang-19/*.pdb  # or whichever compiler(s)
git commit -m "build: Update binaries from CI"
git push

# Then update main repo
cd ../..
git add demo/out
git commit -m "chore: Update demo binaries submodule"
git push
```

### `compare_binaries.py`

Compares two PE binaries to detect differences (used by CI workflows).

```bash
python scripts/compare_binaries.py binary1.exe binary2.exe
```

## Ghidra Analysis Scripts

These scripts run inside Ghidra's Jython environment via `analyzeHeadless`.

### `analyze_patterns.py`

Analyzes a binary for std::vector patterns detected by the extension.

```bash
$GHIDRA_INSTALL_DIR/support/analyzeHeadless \
    /tmp TestProject \
    -import demo/out/clang-19/vector_extra_O2.exe \
    -postScript demo/scripts/analyze_patterns.py
```

### `list_functions.py`

Lists all functions in a binary.

### `show_details.py`

Shows detailed information about a specific function.

## Requirements

- **Python 3.8+**: For standalone scripts
- **uv**: Python package manager (recommended: `uv run python script.py`)
- **gh CLI**: For downloading from GitHub Actions
- **Ghidra**: For analysis scripts (Jython environment)
