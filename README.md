# ECC + ECIES (OpenSSL) – Mini C++ Library

This repo contains two small building blocks:

- **ECC key generation** (`EccKeyGenerator`)
- **ECIES-style encryption** (`EciesCipher`) built from:
  - **ECDH** for key agreement
  - **HKDF-SHA256** for key derivation
  - **AES-256-GCM** for authenticated encryption

> ⚠️ This is an *ECIES-like* construction, intended for learning / controlled environments.  
> It provides confidentiality + integrity (via AES-GCM), but it does **not** authenticate the sender unless you also add a signature.

---
## What is ECC?

**Elliptic Curve Cryptography (ECC)** is public-key cryptography where a keypair is:

- **Private key**: scalar `d` (random integer mod curve order)
- **Public key**: point `Q = d · G` on the curve

This project exports keys as byte arrays:

- Private key: big-endian scalar bytes
- Public key: **SEC1 point encoding**
  - Uncompressed: `0x04 || X || Y`
  - Compressed: `0x02/0x03 || X`

---

## What is ECIES?

**ECIES (Elliptic Curve Integrated Encryption Scheme)** is a *hybrid* approach:

1) Use ECC (ECDH) to compute a shared secret  
2) Derive a symmetric key (KDF)  
3) Use symmetric AEAD to encrypt (AES-GCM)

In this implementation:

- **ECDH** derives shared secret `Z`
- **HKDF-SHA256** derives a 32-byte AES key from `Z`
- **AES-256-GCM** encrypts and authenticates the message

---

## AAD (Additional Authenticated Data)

AES-GCM supports **AAD**:

- **Authenticated**: included in the tag calculation
- **Not encrypted**: transmitted in clear
- If AAD differs between encryption and decryption → authentication fails

Use cases: protocol headers, message type, version, routing info, timestamps, etc.

---

## Encryption design in this repo

### Ephemeral ECDH key (always per message)

`EciesCipher::encrypt()` always generates a **fresh ephemeral sender ECDH keypair** per message.  
That public key is stored in:

- `EciesCiphertext::ephPublicKeyUncompressed`

The receiver must use it to derive the same ECDH secret.

### Optional sender identity public key (metadata)

If you construct `EciesCipher` with a sender keypair, the sender public key is included as:

- `EciesCiphertext::senderPublicKeyUncompressed` (**optional**)

This is **not** used for ECDH; it’s just identity metadata.

If you need *authenticity*, add a **signature** (e.g., ECDSA) over `(ephPub || nonce || ciphertext || tag || aad)`.

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
make run
```

## Example usage

```cpp
EccKeyGenerator keyGen;
EccKeyPair receiver = keyGen.generate();

// (A) With sender identity (optional)
EccKeyPair sender = keyGen.generate();
EciesCipher ecies(sender.privateKey, sender.publicKeyUncompressed, receiver.publicKeyUncompressed);

// Encrypt
std::vector<unsigned char> pt = {'h','i'};
std::vector<unsigned char> aad = {'v','1'};
EciesCiphertext ct = ecies.encrypt(pt, aad);

// Decrypt (receiver side)
std::vector<unsigned char> dec = ecies.decrypt(receiver.privateKey, ct, aad);
```

---

## Security notes / best practices

- Never print or log private keys in real applications.
- Always use strong randomness (OpenSSL DRBG) for ephemeral keys and nonces.
- Always check AES-GCM authentication result (tag verification).
- Prefer keeping secrets in secure containers and zeroizing after use.
- For real protocols, include:
  - sender authentication (signature)
  - replay protection (sequence numbers, timestamps)
  - explicit versioning and context binding

---
