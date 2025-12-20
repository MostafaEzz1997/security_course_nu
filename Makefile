# Top-level Makefile to drive CMake for the AES project
# Usage:
#   make                   # configure+build library + example (Release, C++17)
#   make aes               # build library only
#   make BUILD_TYPE=Debug
#   make CXX_STANDARD=20   # configure+build with a different C++ standard
#   make doc               # generate documentation with Doxygen
#   make clean
#   make distclean
#   make rebuild

CMAKE ?= cmake
RM ?= rm -rf

BUILD_DIR := build
BUILD_TYPE ?= Release
JOBS ?= $(shell nproc 2>/dev/null || echo 1)
CMAKE_BUILD_FLAGS := -- -j$(JOBS)

# Choose C++ standard here (default: 17 -> C++17). You can override on the make command line:
#   make CXX_STANDARD=20
CXX_STANDARD ?= 17

# Doxygen options (can be overridden: e.g. make DOXYGEN=/usr/local/bin/doxygen DOXYFILE=docs/Doxyfile doc)
DOXYGEN ?= doxygen
DOXYFILE ?= docs/Doxyfile
DOC_OUTPUT_DIR ?= docs/out

.PHONY: all aes clean distclean rebuild doc clean-doc

# Default target: build library + example
all: $(BUILD_DIR)
	@echo "=== Building full project (library + example) ==="
	@$(CMAKE) --build $(BUILD_DIR) $(CMAKE_BUILD_FLAGS)

# Build only AES library
aes: $(BUILD_DIR)
	@echo "=== Building AES library only ==="
	@$(CMAKE) --build $(BUILD_DIR) $(CMAKE_BUILD_FLAGS) --target AesAlgo

# Configure the top-level CMake project
$(BUILD_DIR):
	@echo "=== Configuring CMake project in $(BUILD_DIR) (C++$(CXX_STANDARD)) ==="
	@command -v $(CMAKE) >/dev/null 2>&1 || (echo "ERROR: '$(CMAKE)' not found. Please install CMake or add it to your PATH." && exit 1)
	@$(CMAKE) -S . -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) \
		-DCMAKE_CXX_STANDARD=$(CXX_STANDARD) \
		-DCMAKE_CXX_STANDARD_REQUIRED=ON \
		-DCMAKE_CXX_EXTENSIONS=OFF

# Generate documentation with Doxygen
# Usage:
#   make doc                  # uses DOXYGEN and DOXYFILE defaults
#   make DOXYGEN=/path/to/doxygen DOXYFILE=path/to/Doxyfile doc
doc:
	@echo "=== Building documentation with Doxygen ==="
	@command -v $(DOXYGEN) >/dev/null 2>&1 || (echo "ERROR: '$(DOXYGEN)' not found. Install Doxygen or set DOXYGEN variable."; exit 1)
	@if [ ! -f "$(DOXYFILE)" ]; then \
		echo "ERROR: Doxyfile '$(DOXYFILE)' not found."; exit 1; \
	fi
	@mkdir -p $(DOC_OUTPUT_DIR)
	@$(DOXYGEN) $(DOXYFILE)
	@echo "=== Documentation built (check $(DOC_OUTPUT_DIR) or the OUTPUT_DIRECTORY configured in $(DOXYFILE)) ==="

# Remove generated documentation
clean-doc:
	@echo "=== Cleaning generated documentation ==="
	@$(RM) -rf $(DOC_OUTPUT_DIR)

# Clean build artifacts
clean:
	@echo "=== Cleaning build directory ==="
	@$(RM) -rf $(BUILD_DIR)

# Clean build + install (if any)
distclean: clean clean-doc
	@echo "=== Removing any installed artifacts (if exists) ==="

# Rebuild from scratch
rebuild: distclean all
