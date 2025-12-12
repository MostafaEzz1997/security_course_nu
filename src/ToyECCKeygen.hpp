#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <openssl/bn.h>

class ToyECC {
public:
    struct KeyPair {
        // BIGNUMs are heap-allocated, so we use pointers.
        BIGNUM* privateKey;
        std::string publicKey;   // SEC1 compressed
    };

    ToyECC(const char* p_hex,
           const char* a_hex,
           const char* b_hex,
           const char* n_hex,
           const char* gx_hex,
           const char* gy_hex);

    ~ToyECC();

    // Disable copy/move to prevent issues with raw pointers.
    ToyECC(const ToyECC&) = delete;
    ToyECC& operator=(const ToyECC&) = delete;

    // Public API
    KeyPair generateKeyPair(); // Note: Caller is responsible for freeing KeyPair.privateKey

private:
    // Curve parameters
    BIGNUM *P, *A, *B, *N, *Gx, *Gy; // NOLINT

    // OpenSSL context for efficient BIGNUM operations
    BN_CTX* ctx_;

    struct Point {
        BIGNUM* x;
        BIGNUM* y;
        bool infinity;

        Point(BIGNUM* x_ = nullptr, BIGNUM* y_ = nullptr, bool inf = true);
    };

    // ECC internals
    Point basePoint(); // Not const anymore due to BIGNUM allocation
    Point infinity() const;

    // Encoding
    Point scalarMultiply(const BIGNUM* k, const Point& P0);
    Point pointAdd(const Point& P1, const Point& P2);
    Point pointDouble(const Point& P1);

    // Memory management for Points
    Point newPoint(const BIGNUM* x, const BIGNUM* y, bool inf = false);
    void freePoint(Point& p);

    std::vector<std::uint8_t> encodePointCompressed(const Point& P1);
    std::string base64Encode(const std::vector<uint8_t>& data);

    // Helpers
    BIGNUM* randomScalar();
};
