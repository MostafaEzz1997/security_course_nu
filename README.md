# AES Encryption Project

## Overview
This project implements the **Advanced Encryption Standard (AES)** algorithm in C++ with support for multiple modes of operation:

- **ECB (Electronic Codebook)**
- **CBC (Cipher Block Chaining)**
- **CFB (Cipher Feedback)**

It also includes:

- Optional **Galois Field (GF) multiplication optimization** for MixColumns.
- **Padding support** for unaligned blocks.
- Performance benchmarking and functional tests.

## Features

- AES-128 encryption and decryption
- Key expansion and round transformations
- Test cases for ECB, CBC, and CFB modes
- Speed test for encryption performance
- Optional GF multiplication lookup tables for faster MixColumns

---

## Build Instructions (Using Makefile)

The project uses a top-level `Makefile` that configures and builds all components using **CMake**.

### 🔧 Prerequisites
- CMake ≥ 3.5  
- A C++ compiler supporting **C++17** (GCC, Clang, MSVC)

---

### 🏗️ Build the entire project (library + example)
This is the default build:

```bash
make clean
make
```
