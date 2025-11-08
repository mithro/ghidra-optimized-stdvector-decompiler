# Makefile for building MSVC-compatible vector demo binaries
# Uses clang-cl with MSVC headers/SDK

# Environment configuration
# Override these by setting environment variables or passing to make
GHIDRA_INSTALL_DIR ?= $(HOME)/tools/ghidra
MSVC_DIR ?= $(HOME)/.msvc
CLANG_CL ?= clang-cl-19
LLD_LINK ?= lld-link

# MSVC paths (auto-detected from MSVC_DIR)
MSVC_VERSION := 14.44.35207
SDK_VERSION := 10.0.26100.0
MSVC_INCLUDE := $(MSVC_DIR)/VC/Tools/MSVC/$(MSVC_VERSION)/include
SDK_INCLUDE := $(MSVC_DIR)/Windows Kits/10/Include/$(SDK_VERSION)
MSVC_LIB := $(MSVC_DIR)/VC/Tools/MSVC/$(MSVC_VERSION)/lib/x64
SDK_LIB := $(MSVC_DIR)/Windows Kits/10/Lib/$(SDK_VERSION)

# Compiler flags
CXXFLAGS_COMMON := /std:c++17 /EHsc /MD -fuse-ld=$(LLD_LINK) \
	-I"$(MSVC_INCLUDE)" \
	-I"$(SDK_INCLUDE)/ucrt" \
	-I"$(SDK_INCLUDE)/um" \
	-I"$(SDK_INCLUDE)/shared"

CXXFLAGS_O2 := /O2 /Zi
CXXFLAGS_Od := /Od /Zi

LINKFLAGS := /LIBPATH:"$(MSVC_LIB)" \
	/LIBPATH:"$(SDK_LIB)/ucrt/x64" \
	/LIBPATH:"$(SDK_LIB)/um/x64" \
	/DEBUG:FULL \
	/stub:build_setup/dosstub.exe \
	/Brepro

LINKFLAGS_O2 := /OPT:REF /OPT:ICF
LINKFLAGS_Od := /OPT:NOREF /OPT:NOICF

# Source files
SOURCES := vector_basic.cpp vector_extra.cpp

# Binary targets
BINARIES_O2 := $(SOURCES:.cpp=_O2.exe)
BINARIES_Od := $(SOURCES:.cpp=_Od.exe)
ALL_BINARIES := $(BINARIES_O2) $(BINARIES_Od)

# Ghidra project targets
GHIDRA_PROJECTS_O2 := $(SOURCES:.cpp=_O2.gpr)
GHIDRA_PROJECTS_Od := $(SOURCES:.cpp=_Od.gpr)
ALL_GHIDRA_PROJECTS := $(GHIDRA_PROJECTS_O2) $(GHIDRA_PROJECTS_Od)

# Default target: build all binaries
.PHONY: all
all: $(ALL_BINARIES)

# Build just optimized versions (faster)
.PHONY: optimized
optimized: $(BINARIES_O2)

# Build just debug versions
.PHONY: debug
debug: $(BINARIES_Od)

# Individual source targets
.PHONY: basic extra
basic: vector_basic_O2.exe vector_basic_Od.exe
extra: vector_extra_O2.exe vector_extra_Od.exe

# Pattern rules for building binaries
%_O2.exe: %.cpp
	@echo "Building optimized binary: $@"
	$(CLANG_CL) $(CXXFLAGS_COMMON) $(CXXFLAGS_O2) \
		/Fe:$@ $< \
		/link $(LINKFLAGS) $(LINKFLAGS_O2)

%_Od.exe: %.cpp
	@echo "Building debug binary: $@"
	$(CLANG_CL) $(CXXFLAGS_COMMON) $(CXXFLAGS_Od) \
		/Fe:$@ $< \
		/link $(LINKFLAGS) $(LINKFLAGS_Od)

# Generate Ghidra projects for all binaries
.PHONY: ghidra-projects
ghidra-projects: $(ALL_GHIDRA_PROJECTS)

# Pattern rule for creating Ghidra projects
%.gpr: %.exe
	@echo "Creating Ghidra project for $<"
	@mkdir -p $(basename $@).rep
	$(GHIDRA_INSTALL_DIR)/support/analyzeHeadless \
		. $(basename $@) \
		-import $< \
		-overwrite \
		-analysisTimeoutPerFile 300

# Verify build environment
.PHONY: check-env
check-env:
	@echo "Checking build environment..."
	@echo ""
	@echo "GHIDRA_INSTALL_DIR: $(GHIDRA_INSTALL_DIR)"
	@if [ ! -d "$(GHIDRA_INSTALL_DIR)" ]; then \
		echo "  ✗ ERROR: Ghidra not found"; \
		echo "  Set GHIDRA_INSTALL_DIR=/path/to/ghidra"; \
		exit 1; \
	else \
		echo "  ✓ Found"; \
	fi
	@echo ""
	@echo "Compiler: $(CLANG_CL)"
	@if ! command -v $(CLANG_CL) >/dev/null 2>&1; then \
		echo "  ✗ ERROR: $(CLANG_CL) not found"; \
		echo "  Run: ./setup_build_env.sh"; \
		exit 1; \
	else \
		echo "  ✓ Found: $$($(CLANG_CL) --version | head -1)"; \
	fi
	@echo ""
	@echo "MSVC Headers: $(MSVC_INCLUDE)"
	@if [ ! -d "$(MSVC_INCLUDE)" ]; then \
		echo "  ✗ ERROR: MSVC headers not found"; \
		echo "  Run: ./setup_build_env.sh"; \
		exit 1; \
	else \
		echo "  ✓ Found"; \
	fi
	@echo ""
	@echo "Windows SDK: $(SDK_INCLUDE)"
	@if [ ! -d "$(SDK_INCLUDE)" ]; then \
		echo "  ✗ ERROR: Windows SDK not found"; \
		echo "  Run: ./setup_build_env.sh"; \
		exit 1; \
	else \
		echo "  ✓ Found"; \
	fi
	@echo ""
	@echo "Environment OK!"

# Run pattern analysis
.PHONY: test
test: vector_extra_O2.exe
	@echo "Running pattern analysis on vector_extra_O2.exe..."
	@if [ ! -f "../test.py" ]; then \
		echo "Warning: ../test.py not found"; \
		echo "Running local analysis script instead..."; \
		$(GHIDRA_INSTALL_DIR)/support/analyzeHeadless \
			. VectorExtraDemo \
			-import vector_extra_O2.exe \
			-postScript scripts/analyze_patterns.py; \
	else \
		python3 ../test.py; \
	fi

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -f *.exe *.pdb *.obj *.ilk *.exp *.lib
	@echo "Cleaned."

# Clean Ghidra projects (keep binaries)
.PHONY: clean-ghidra
clean-ghidra:
	@echo "Cleaning Ghidra projects..."
	rm -f *.gpr
	rm -rf *.rep/
	@echo "Cleaned."

# Clean everything
.PHONY: distclean
distclean: clean clean-ghidra
	@echo "All artifacts removed."

# Help target
.PHONY: help
help:
	@echo "Vector Demo Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all              - Build all binaries (default)"
	@echo "  optimized        - Build only optimized versions (_O2)"
	@echo "  debug            - Build only debug versions (_Od)"
	@echo "  basic            - Build vector_basic binaries"
	@echo "  extra            - Build vector_extra binaries"
	@echo "  ghidra-projects  - Generate Ghidra projects for all binaries"
	@echo "  check-env        - Verify build environment is set up"
	@echo "  test             - Run pattern analysis"
	@echo "  clean            - Remove build artifacts"
	@echo "  clean-ghidra     - Remove Ghidra projects"
	@echo "  distclean        - Remove everything"
	@echo ""
	@echo "Environment Variables:"
	@echo "  GHIDRA_INSTALL_DIR  - Path to Ghidra installation"
	@echo "  MSVC_DIR            - Path to MSVC headers/SDK (default: ~/.msvc)"
	@echo "  CLANG_CL            - clang-cl compiler (default: clang-cl-19)"
	@echo ""
	@echo "Setup:"
	@echo "  1. Run: ./setup_build_env.sh"
	@echo "  2. Run: make check-env"
	@echo "  3. Run: make"
