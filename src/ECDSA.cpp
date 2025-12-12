#include "ECDSA.hpp"
#include <openssl/sha.h>
#include <stdexcept>

ECDSA::ECDSA(ToyECC& ecc) : ecc_(ecc) {}

ECDSA::Signature ECDSA::sign(const std::string& message, const BIGNUM* privateKey) {
    // 1. Calculate e = HASH(message).
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(message.c_str()), message.length(), hash);
    BIGNUM* e = BN_bin2bn(hash, SHA256_DIGEST_LENGTH, nullptr);

    BIGNUM* r = BN_new();
    BIGNUM* s = BN_new();

    // Get curve order n
    const BIGNUM* n = ecc_.getCurveOrder();

    // 2. Loop until a valid signature is found.
    while (true) {
        // 3. Select a cryptographically secure random integer k from [1, n-1].
        BIGNUM* k = ecc_.randomScalar();

        // 4. Calculate the curve point (x1, y1) = k * G.
        ToyECC::Point kG = ecc_.scalarMultiply(k, ecc_.basePoint());

        // 5. Calculate r = x1 mod n.
        BN_mod(r, kG.x, n, ecc_.getCtx());

        // If r = 0, start again with a new k.
        if (BN_is_zero(r)) {
            BN_free(k);
            ecc_.freePoint(kG);
            continue;
        }

        // 6. Calculate s = k^-1 * (e + r * d) mod n.
        BIGNUM* k_inv = BN_new();
        BN_mod_inverse(k_inv, k, n, ecc_.getCtx()); // k^-1

        BIGNUM* temp = BN_new();
        BN_mod_mul(temp, r, privateKey, n, ecc_.getCtx()); // r * d
        BN_mod_add(temp, e, temp, n, ecc_.getCtx());      // e + r*d
        BN_mod_mul(s, k_inv, temp, n, ecc_.getCtx());      // k^-1 * (e + r*d)

        // Clean up temporaries
        BN_free(k);
        BN_free(k_inv);
        BN_free(temp);
        ecc_.freePoint(kG);

        // If s = 0, start again with a new k.
        if (!BN_is_zero(s)) {
            break;
        }
    }

    BN_free(e);
    return {r, s};
}

bool ECDSA::verify(const std::string& message, const Signature& signature, const ToyECC::Point& publicKey) {
    const BIGNUM* n = ecc_.getCurveOrder();

    // 1. Verify that r and s are in [1, n-1].
    if (BN_is_zero(signature.r) || BN_cmp(signature.r, n) >= 0 ||
        BN_is_zero(signature.s) || BN_cmp(signature.s, n) >= 0) {
        return false;
    }

    // 2. Calculate e = HASH(message).
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(message.c_str()), message.length(), hash);
    BIGNUM* e = BN_bin2bn(hash, SHA256_DIGEST_LENGTH, nullptr);

    // 3. Calculate w = s^-1 mod n.
    BIGNUM* w = BN_new();
    BN_mod_inverse(w, signature.s, n, ecc_.getCtx());

    // 4. Calculate u1 = e * w mod n and u2 = r * w mod n.
    BIGNUM* u1 = BN_new();
    BIGNUM* u2 = BN_new();
    BN_mod_mul(u1, e, w, n, ecc_.getCtx());
    BN_mod_mul(u2, signature.r, w, n, ecc_.getCtx());

    // 5. Calculate curve point (x1, y1) = u1*G + u2*Q.
    ToyECC::Point p1 = ecc_.scalarMultiply(u1, ecc_.basePoint());
    ToyECC::Point p2 = ecc_.scalarMultiply(u2, publicKey);
    ToyECC::Point R = ecc_.pointAdd(p1, p2);

    if (R.infinity) {
        return false;
    }

    // 6. The signature is valid if r == x1 mod n.
    BIGNUM* r_check = BN_new();
    BN_mod(r_check, R.x, n, ecc_.getCtx());
    bool success = (BN_cmp(signature.r, r_check) == 0);

    // Cleanup
    BN_free(e);
    BN_free(w);
    BN_free(u1);
    BN_free(u2);
    BN_free(r_check);
    ecc_.freePoint(p1);
    ecc_.freePoint(p2);
    ecc_.freePoint(R);

    return success;
}