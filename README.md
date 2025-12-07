# RSA Implementation in C++

## Overview
This project provides a from-scratch implementation of the **RSA (Rivest–Shamir–Adleman)** algorithm in C++. It uses the OpenSSL library for the underlying arbitrary-precision integer arithmetic (`BIGNUM`) but implements the core cryptographic logic independently.

This implementation is intended for educational purposes to demonstrate the mathematics behind RSA. It does **not** include cryptographic padding schemes (like OAEP or PSS), which makes it insecure for real-world applications.

The main application demonstrates:
- **Key Pair Generation**: Creating public and private keys of various sizes (128, 1024, 2048, 4096 bits).
- **Encryption & Decryption**: Securing and recovering a message.
- **Digital Signatures**: Signing a message and verifying its authenticity.
- **Performance Measurement**: Timing the core cryptographic operations.

## Features

- **RSA Algorithm Implementation**:
  - Probabilistic primality testing (Miller-Rabin).
  - Prime number generation.
  - Modular inverse calculation (Extended Euclidean Algorithm).
  - Modular exponentiation (Square-and-Multiply).
- **Safe Resource Management**: Uses C++ smart pointers (`std::unique_ptr`) to automatically manage OpenSSL `BIGNUM` resources, preventing memory leaks.
- **Performance Benchmarking**: The example application measures and reports the time taken for key generation, encryption, decryption, signing, and verification.
- **Cross-Platform Build System**: Uses CMake for easy compilation on various platforms.

---

## Build Instructions (Using Makefile)

The project uses a top-level `Makefile` that configures and builds all components using **CMake**.

### 🔧 Prerequisites
- **CMake** (version 3.5 or higher)
- A C++ compiler supporting **C++17** (GCC, Clang, MSVC)
- **OpenSSL** development libraries (e.g., `libssl-dev` on Debian/Ubuntu).

---

### 🏗️ Build the entire project (library + example)

```bash
# Clean previous builds (optional)
make clean

# Build the project
make
```
