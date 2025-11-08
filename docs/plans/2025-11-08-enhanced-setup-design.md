# Enhanced Setup Script Design

**Date**: 2025-11-08
**Status**: Approved
**Author**: Claude Code

## Overview

Enhance the existing `setup.sh` script to automatically install all dependencies (Java, Ghidra) in addition to building and installing the plugin. This enables true one-step setup on fresh systems.

## Requirements

- **Platform**: Linux (Debian/Ubuntu) with apt package manager
- **Install location**: User-local at `$HOME/tools/` (no sudo for Ghidra)
- **Existing installations**: Skip if Ghidra found (any version works)
- **Java installation**: Use system apt packages (requires sudo)
- **Automation**: Fully automatic - no user prompts, handle sudo transparently
- **Success criteria**: User runs `./setup.sh` and gets fully working Ghidra + plugin without any manual intervention

## Architecture

### File Structure

```
setup.sh                    # Main orchestrator (enhanced)
scripts/
  common.sh                # Shared utilities
  install_java.sh          # Java dependency installer
  install_ghidra.sh        # Ghidra downloader/installer
```

### Component Responsibilities

#### common.sh
Shared utilities library providing:
- Color constants and print functions (`print_status`, `print_error`, `print_warning`, `print_info`)
- Error handling: `fail(message)` - prints error and exits with code 1
- Sudo checking: `has_sudo()` - checks if sudo is available without prompting
- Download helper: `download_file(url, dest)` - uses curl/wget with 3 retries and exponential backoff
- Archive extraction: `extract_archive(file, dest)` - handles .zip and .tar.gz based on extension

#### install_java.sh
Java installation module:
1. Check if Java 21+ is installed via `command -v java` and version parsing
2. If missing, install via apt:
   ```bash
   sudo apt-get update
   sudo apt-get install -y openjdk-21-jdk
   ```
3. Export `JAVA_HOME` if needed
4. Validate installation succeeded by running `java -version`

**Error handling**: If apt fails or sudo unavailable, exit with clear error message and manual instructions.

#### install_ghidra.sh
Ghidra installation module:
1. Check if Ghidra exists at `$GHIDRA_INSTALL_DIR/ghidraRun`
2. If found, skip download (any version acceptable)
3. If missing:
   - Create `$INSTALL_DIR` directory
   - Download from GitHub releases: `https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_*.zip`
   - Extract to temporary location
   - Move/rename to `$GHIDRA_INSTALL_DIR`
   - Clean up downloaded archive

**Platform handling**: Detect architecture (x86_64) to download correct release filename.

#### setup.sh (enhanced)
Main orchestrator:
1. Source the three library scripts (`common.sh`, `install_java.sh`, `install_ghidra.sh`)
2. Call `run_java_installer` before step 1
3. Call `run_ghidra_installer` at step 1 (replacing the manual check)
4. Execute existing plugin build/install logic unchanged

**Backward compatibility**: All existing environment variables still work, adds `INSTALL_DIR` as new optional variable.

### Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `INSTALL_DIR` | `$HOME/tools` | Root directory for installed tools |
| `GHIDRA_VERSION` | `11.4.2` | Version to download if installing |
| `GHIDRA_INSTALL_DIR` | `$INSTALL_DIR/ghidra` | Final Ghidra installation path |

## Error Handling

### Fail-Fast Strategy
- All scripts use `set -euo pipefail` to catch errors early
- Each installer function returns 0 on success, 1 on failure
- Common `fail()` function prints error and exits with code 1

### Specific Error Cases

1. **Network failures**:
   - `download_file()` retries up to 3 times with exponential backoff
   - If all retries fail, show error with manual download instructions

2. **Sudo not available**:
   - `install_java.sh` checks `has_sudo()` before attempting apt
   - If false, print error: "Java installation requires sudo. Please run: sudo apt-get install openjdk-21-jdk"

3. **Disk space**:
   - Check available space before downloading (~500MB for Ghidra)
   - Fail early if insufficient space

4. **Partial installations**:
   - If Ghidra download interrupted, remove incomplete extraction
   - Use temp directory for extraction, only move to final location when complete

### Edge Cases

| Case | Handling |
|------|----------|
| Multiple Ghidra versions | Check for `ghidraRun` - if found anywhere in GHIDRA_INSTALL_DIR, skip |
| Architecture mismatch | Detect if not x86_64 and show warning (Ghidra supports other archs but filenames differ) |
| Pre-existing tools directory | Don't fail if `$INSTALL_DIR` already exists |
| Running as root | Warn if `$USER == root` but allow to proceed |

## Testing Strategy

### Manual Testing Scenarios
- Fresh Ubuntu system (no Java, no Ghidra)
- System with Java 21 already installed
- System with Ghidra already present
- System with older Java version (should upgrade)
- Offline mode (network failures) - should fail gracefully

### Verification Steps Built Into Script
- After Java install: Run `java -version` and parse output
- After Ghidra install: Check `ghidraRun` is executable
- After plugin build: Verify JAR exists
- After plugin install: Verify extension directory created

## Implementation Notes

1. Extract existing helper functions from `setup.sh` to `scripts/common.sh`
2. Implement `scripts/install_java.sh` with apt-based installation
3. Implement `scripts/install_ghidra.sh` with GitHub release download
4. Modify `setup.sh` to source and call the new installers
5. Test on clean Ubuntu VM or container

## Backward Compatibility

- Existing `GHIDRA_INSTALL_DIR` environment variable continues to work
- Users who already have Ghidra installed experience no change in behavior
- Script remains executable from project root as `./setup.sh`
