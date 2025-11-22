# Top-level Makefile to drive CMake for the AES project
# Usage:
#   make            # configure+build library + example (Release)
#   make aes        # build library only
#   make BUILD_TYPE=Debug
#   make clean
#   make distclean
#   make rebuild

CMAKE ?= cmake
RM ?= rm -rf

BUILD_DIR := build
BUILD_TYPE ?= Release
JOBS ?= $(shell nproc 2>/dev/null || echo 1)
CMAKE_BUILD_FLAGS := --config $(BUILD_TYPE) -- -j$(JOBS)

.PHONY: all aes clean distclean rebuild

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
	@echo "=== Configuring CMake project in $(BUILD_DIR) ==="
	@$(CMAKE) -S . -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=$(BUILD_TYPE)

# Clean build artifacts
clean:
	@echo "=== Cleaning build directory ==="
	@$(RM) -rf $(BUILD_DIR)

# Clean build + install (if any)
distclean: clean
	@echo "=== Removing any installed artifacts (if exists) ==="

# Rebuild from scratch
rebuild: distclean all