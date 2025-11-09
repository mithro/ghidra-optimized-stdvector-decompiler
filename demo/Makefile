# Makefile for building MSVC-compatible vector demo binaries
# Supports both clang-cl (cross-compilation) and native MSVC (cl.exe)

# Environment configuration
# Override these by setting environment variables or passing to make
GHIDRA_INSTALL_DIR ?= $(HOME)/tools/ghidra
MSVC_DIR ?= $(HOME)/.msvc
CLANG_CL ?= clang-cl-20
LLD_LINK ?= lld-link-20

# Compiler identification for output directory
COMPILER ?= clang-19
OUT_DIR = out/$(COMPILER)

# Detect if using native MSVC (cl.exe) vs clang-cl
ifneq (,$(findstring msvc-,$(COMPILER)))
  # Native MSVC mode
  USE_NATIVE_MSVC := 1
  CXX := cl.exe
  LINKER := link.exe
else
  # clang-cl mode (cross-compilation)
  USE_NATIVE_MSVC := 0
  CXX := $(CLANG_CL)
  LINKER := $(LLD_LINK)
endif

# MSVC paths (for clang-cl or native MSVC on non-Windows)
MSVC_VERSION := 14.44.35207
SDK_VERSION := 10.0.26100.0
MSVC_INCLUDE := $(MSVC_DIR)/VC/Tools/MSVC/$(MSVC_VERSION)/include
SDK_INCLUDE := $(MSVC_DIR)/Windows Kits/10/Include/$(SDK_VERSION)
MSVC_LIB := $(MSVC_DIR)/VC/Tools/MSVC/$(MSVC_VERSION)/lib/x64
SDK_LIB := $(MSVC_DIR)/Windows Kits/10/Lib/$(SDK_VERSION)

# Compiler flags (common to both)
CXXFLAGS_BASE := /std:c++17 /EHsc /MD
CXXFLAGS_O2 := /O2 /Zi
CXXFLAGS_Od := /Od /Zi

# Compiler-specific flags
ifeq ($(USE_NATIVE_MSVC),1)
  # Native MSVC: Use system headers, no custom includes needed on Windows
  CXXFLAGS_COMMON := $(CXXFLAGS_BASE)

  # Native MSVC link flags
  LINKFLAGS := /DEBUG:FULL \
	/stub:$(CURDIR)/build_setup/dosstub.exe \
	/Brepro
else
  # clang-cl: Need explicit MSVC header paths for cross-compilation
  CXXFLAGS_COMMON := $(CXXFLAGS_BASE) -fuse-ld=$(LLD_LINK) \
	-I"$(MSVC_INCLUDE)" \
	-I"$(SDK_INCLUDE)/ucrt" \
	-I"$(SDK_INCLUDE)/um" \
	-I"$(SDK_INCLUDE)/shared"

  # clang-cl link flags
  LINKFLAGS := /LIBPATH:"$(MSVC_LIB)" \
	/LIBPATH:"$(SDK_LIB)/ucrt/x64" \
	/LIBPATH:"$(SDK_LIB)/um/x64" \
	/DEBUG:FULL \
	/stub:$(CURDIR)/build_setup/dosstub.exe \
	/Brepro
endif

LINKFLAGS_O2 := /OPT:REF /OPT:ICF
LINKFLAGS_Od := /OPT:NOREF /OPT:NOICF

# Source files
SOURCES := vector_basic.cpp vector_extra.cpp

# Binary targets
BINARIES_O2 := $(addprefix $(OUT_DIR)/,$(SOURCES:.cpp=_O2.exe))
BINARIES_Od := $(addprefix $(OUT_DIR)/,$(SOURCES:.cpp=_Od.exe))
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
basic: $(OUT_DIR)/vector_basic_O2.exe $(OUT_DIR)/vector_basic_Od.exe
extra: $(OUT_DIR)/vector_extra_O2.exe $(OUT_DIR)/vector_extra_Od.exe

# Initialize submodule if not already done
.PHONY: init-submodule
init-submodule:
	@if [ ! -f out/.git ]; then \
		echo "Initializing submodule..."; \
		git submodule update --init demo/out; \
	fi

# Pattern rules for building binaries
$(OUT_DIR)/%_O2.exe: %.cpp | init-submodule
	@echo "Building optimized binary: $@ with $(COMPILER) ($(CXX))"
	@mkdir -p $(OUT_DIR)
	$(CXX) $(CXXFLAGS_COMMON) $(CXXFLAGS_O2) \
		/Fe:$@ $< \
		/link $(LINKFLAGS) $(LINKFLAGS_O2)

$(OUT_DIR)/%_Od.exe: %.cpp | init-submodule
	@echo "Building debug binary: $@ with $(COMPILER) ($(CXX))"
	@mkdir -p $(OUT_DIR)
	$(CXX) $(CXXFLAGS_COMMON) $(CXXFLAGS_Od) \
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
test: init-submodule
	@echo "Running pattern analysis on all compilers..."
	@if [ ! -f "../test.py" ]; then \
		echo "Warning: ../test.py not found"; \
		exit 1; \
	else \
		cd .. && python3 test.py; \
	fi

# Clean build artifacts
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

# List available compiler directories
.PHONY: list-compilers
list-compilers:
	@echo "Available compilers in out/:"
	@if [ -d out ]; then \
		ls -d out/*/ 2>/dev/null | sed 's|out/||' | sed 's|/||' || echo "  (none found)"; \
	else \
		echo "  Submodule not initialized. Run: git submodule update --init"; \
	fi
