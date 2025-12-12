#pragma once

#include "ToyECCKeygen.hpp"
#include <string>

class ElGamal {
public:
    // Ciphertext is a pair of points on the curve.
    struct Ciphertext {
        ToyECC::Point C1;
        ToyECC::Point C2;
    };

    /**
     * @brief Constructor.
     * @param ecc A reference to an initialized ToyECC object which provides
     *            the curve parameters and arithmetic functions.
     */
    explicit ElGamal(ToyECC& ecc);

    /**
     * @brief Encrypts a message using the recipient's public key.
     * @param message The string message to encrypt.
     * @param publicKey The recipient's public key point (Y).
     * @return The resulting ciphertext (C1, C2).
     */
    Ciphertext encrypt(const std::string& message, const ToyECC::Point& publicKey);

    /**
     * @brief Decrypts a ciphertext using the recipient's private key.
     * @param ciphertext The ciphertext to decrypt.
     * @param original_message The original message to verify against.
     * @param privateKey The recipient's private key scalar (x).
     * @return True if the decrypted point matches the point derived from the original message.
     */
    bool decrypt(const Ciphertext& ciphertext, const std::string& original_message, const BIGNUM* privateKey);

private:
    ToyECC& ecc_; // Reference to the underlying ECC implementation.
};