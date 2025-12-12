#pragma once

#include "ToyECCKeygen.hpp"
#include <string>

class ECDSA {
public:
    // The signature is a pair of large integers (r, s).
    struct Signature {
        BIGNUM* r;
        BIGNUM* s;
    };

    /**
     * @brief Constructor.
     * @param ecc A reference to an initialized ToyECC object.
     */
    explicit ECDSA(ToyECC& ecc);

    /**
     * @brief Signs a message digest using a private key.
     * @param message The message to sign.
     * @param privateKey The private key scalar (d).
     * @return The ECDSA signature (r, s). The caller is responsible for freeing r and s.
     */
    Signature sign(const std::string& message, const BIGNUM* privateKey);

    /**
     * @brief Verifies a signature against a message and public key.
     * @param message The original message.
     * @param signature The signature to verify.
     * @param publicKey The public key point (Q).
     * @return True if the signature is valid, false otherwise.
     */
    bool verify(const std::string& message, const Signature& signature, const ToyECC::Point& publicKey);

private:
    ToyECC& ecc_; // Reference to the underlying ECC implementation.
};