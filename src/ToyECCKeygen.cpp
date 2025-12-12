#include <stdexcept>
#include <iostream>
#include <vector>

#include "ToyECCKeygen.hpp"

// ---------------- Constructor ----------------
ToyECC::ToyECC(const char* p_hex, const char* a_hex, const char* b_hex,
               const char* n_hex, const char* gx_hex, const char* gy_hex) {
    P = BN_new(); A = BN_new(); B = BN_new();
    N = BN_new(); Gx = BN_new(); Gy = BN_new();
    ctx_ = BN_CTX_new();

    if (!ctx_ || !P || !A || !B || !N || !Gx || !Gy) {
        throw std::runtime_error("Failed to allocate BIGNUMs");
    }

    BN_hex2bn(&P, p_hex);
    BN_hex2bn(&A, a_hex);
    BN_hex2bn(&B, b_hex);
    BN_hex2bn(&N, n_hex);
    BN_hex2bn(&Gx, gx_hex);
    BN_hex2bn(&Gy, gy_hex);
}

ToyECC::~ToyECC() {
    BN_free(P); BN_free(A); BN_free(B);
    BN_free(N); BN_free(Gx); BN_free(Gy);
    BN_CTX_free(ctx_);
}

// ---------------- Point ctor ----------------
ToyECC::Point::Point(BIGNUM* x_, BIGNUM* y_, bool inf)
    : x(x_), y(y_), infinity(inf) {}

// ---------------- Public API ----------------
ToyECC::KeyPair ToyECC::generateKeyPair() {
    BIGNUM* d = randomScalar();
    Point Q = scalarMultiply(d, basePoint());

    KeyPair kp;
    kp.privateKey = d;
    kp.publicKey  = base64Encode(encodePointCompressed(Q));

    freePoint(Q);
    return kp;
}

// ---------------- Base point ----------------
ToyECC::Point ToyECC::basePoint() {
    return newPoint(Gx, Gy, false);
}

ToyECC::Point ToyECC::infinity() const {
    return Point(nullptr, nullptr, true);
}

// ---------------- Point Memory Management ----------------
ToyECC::Point ToyECC::newPoint(const BIGNUM* x, const BIGNUM* y, bool inf) {
    if (inf) return infinity();
    BIGNUM* new_x = BN_dup(x);
    BIGNUM* new_y = BN_dup(y);
    if (!new_x || !new_y) throw std::runtime_error("Failed to duplicate BIGNUM for Point.");
    return Point(new_x, new_y, false);
}

void ToyECC::freePoint(Point& p) {
    if (p.x) BN_free(p.x);
    if (p.y) BN_free(p.y);
    p.x = nullptr;
    p.y = nullptr;
    p.infinity = true;
}

// ---------------- ECC arithmetic ----------------
ToyECC::Point ToyECC::scalarMultiply(const BIGNUM* k, const Point& P0) {
    if (BN_is_zero(k) || P0.infinity) {
        return infinity();
    }

    Point result = infinity();
    Point addend = newPoint(P0.x, P0.y);

    for (int i = 0; i < BN_num_bits(k); ++i) {
        if (BN_is_bit_set(k, i)) {
            Point temp = pointAdd(result, addend);
            freePoint(result);
            result = temp;
        }
        Point temp = pointDouble(addend);
        freePoint(addend);
        addend = temp;
    }

    freePoint(addend);
    return result;
}

ToyECC::Point ToyECC::pointAdd(const Point& P1, const Point& P2) {
    if (P1.infinity) return newPoint(P2.x, P2.y);
    if (P2.infinity) return newPoint(P1.x, P1.y);

    BN_CTX_start(ctx_);
    BIGNUM *lambda = BN_CTX_get(ctx_);
    BIGNUM *x3 = BN_CTX_get(ctx_);
    BIGNUM *y3 = BN_CTX_get(ctx_);
    BIGNUM *temp = BN_CTX_get(ctx_);

    // Check for P1 == -P2
    BN_mod_add(temp, P1.y, P2.y, P, ctx_);
    if (BN_cmp(P1.x, P2.x) == 0 && BN_is_zero(temp)) {
        BN_CTX_end(ctx_);
        return infinity();
    }

    if (BN_cmp(P1.x, P2.x) == 0 && BN_cmp(P1.y, P2.y) == 0) {
        BN_CTX_end(ctx_);
        return pointDouble(P1);
    }

    // Calculate lambda = (y2 - y1) / (x2 - x1) mod P
    BIGNUM *num = BN_CTX_get(ctx_);
    BIGNUM *den = BN_CTX_get(ctx_);
    BN_mod_sub(num, P2.y, P1.y, P, ctx_);
    BN_mod_sub(den, P2.x, P1.x, P, ctx_);
    BN_mod_inverse(den, den, P, ctx_);
    BN_mod_mul(lambda, num, den, P, ctx_);

    // Calculate x3 = lambda^2 - x1 - x2 mod P
    BN_mod_sqr(x3, lambda, P, ctx_);
    BN_mod_sub(x3, x3, P1.x, P, ctx_);
    BN_mod_sub(x3, x3, P2.x, P, ctx_);

    // Calculate y3 = lambda * (x1 - x3) - y1 mod P
    BN_mod_sub(temp, P1.x, x3, P, ctx_);
    BN_mod_mul(y3, lambda, temp, P, ctx_);
    BN_mod_sub(y3, y3, P1.y, P, ctx_);

    Point result = newPoint(x3, y3);
    BN_CTX_end(ctx_);
    return result;
}


ToyECC::Point ToyECC::pointDouble(const Point& P1) {
    if (P1.infinity || BN_is_zero(P1.y)) {
        return infinity();
    }

    BN_CTX_start(ctx_);
    BIGNUM *lambda = BN_CTX_get(ctx_);
    BIGNUM *x3 = BN_CTX_get(ctx_);
    BIGNUM *y3 = BN_CTX_get(ctx_);
    BIGNUM *num = BN_CTX_get(ctx_);
    BIGNUM *den = BN_CTX_get(ctx_);

    // Calculate lambda = (3*x1^2 + A) / (2*y1) mod P
    BN_mod_sqr(num, P1.x, P, ctx_); // num = x1^2 mod P
    BN_mul_word(num, 3);            // num = (x1^2 mod P) * 3
    BN_mod_add(num, num, A, P, ctx_);
    BN_mul_word(den, 2);            // den = 2
    BN_mul(den, den, P1.y, ctx_);
    BN_mod_inverse(den, den, P, ctx_);
    BN_mod_mul(lambda, num, den, P, ctx_);

    // Calculate x3 = lambda^2 - 2*x1 mod P
    BN_mod_sqr(x3, lambda, P, ctx_);
    BN_mod_sub(x3, x3, P1.x, P, ctx_);
    BN_mod_sub(x3, x3, P1.x, P, ctx_);

    // Calculate y3 = lambda * (x1 - x3) - y1 mod P
    BN_mod_sub(y3, P1.x, x3, P, ctx_);
    BN_mod_mul(y3, lambda, y3, P, ctx_);
    BN_mod_sub(y3, y3, P1.y, P, ctx_);

    Point result = newPoint(x3, y3);
    BN_CTX_end(ctx_);
    return result;
}


// ---------------- Encoding ----------------
std::vector<std::uint8_t> ToyECC::encodePointCompressed(const Point& P1) {
    if (P1.infinity) {
        throw std::runtime_error("Cannot encode point at infinity");
    }

    // SEC1 compressed format: 1 byte prefix + 32 bytes for X-coordinate
    std::vector<std::uint8_t> encoded(33);
    encoded[0] = BN_is_odd(P1.y) ? 0x03 : 0x02;

    // Export the 256-bit X-coordinate to a 32-byte array (big-endian)
    BN_bn2binpad(P1.x, encoded.data() + 1, 32);

    return encoded;
}

std::string ToyECC::base64Encode(const std::vector<uint8_t>& data)
{
    // This implementation is fine and doesn't need to change.
    // For production, using OpenSSL's EVP_EncodeBlock is better.
    const char* table =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string out;
    size_t i = 0;

    while (i < data.size()) {
        uint32_t v = data[i++] << 16;
        if (i < data.size()) v |= data[i++] << 8;
        if (i < data.size()) v |= data[i++];

        out.push_back(table[(v >> 18) & 0x3F]);
        out.push_back(table[(v >> 12) & 0x3F]);
        out.push_back((i - 1 < data.size()) ? table[(v >> 6) & 0x3F] : '=');
        out.push_back((i < data.size())     ? table[v & 0x3F]        : '=');
    }
    return out;
}


// ---------------- Helpers ----------------
BIGNUM* ToyECC::randomScalar() {
    BIGNUM* r = BN_new();
    if (!r) throw std::runtime_error("Failed to allocate BIGNUM for random scalar.");
    // Generate a random number in the range [1, N-1]
    BN_rand_range(r, N);
    return r;
}
