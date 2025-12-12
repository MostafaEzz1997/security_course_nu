#include "ElGamal.hpp"
#include <openssl/sha.h>
#include <stdexcept>

ElGamal::ElGamal(ToyECC& ecc) : ecc_(ecc) {}

ElGamal::Ciphertext ElGamal::encrypt(const std::string& message, const ToyECC::Point& publicKey) {
    // For this demonstration, we'll map the message to a point by hashing it
    // and using the hash as a temporary private key to generate a point M.
    // This is a simplified approach.
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(message.c_str()), message.length(), hash);

    BIGNUM* msg_scalar = BN_bin2bn(hash, SHA256_DIGEST_LENGTH, nullptr);
    ToyECC::Point M = ecc_.scalarMultiply(msg_scalar, ecc_.basePoint());
    BN_free(msg_scalar);

    // 1. Choose a random integer r (nonce).
    BIGNUM* r = ecc_.randomScalar();

    // 2. Calculate C1 = r * G
    ToyECC::Point C1 = ecc_.scalarMultiply(r, ecc_.basePoint());

    // 3. Calculate C2 = M + (r * Y)
    ToyECC::Point rY = ecc_.scalarMultiply(r, publicKey);
    ToyECC::Point C2 = ecc_.pointAdd(M, rY);

    // Clean up temporary points and scalars
    ecc_.freePoint(M);
    ecc_.freePoint(rY);
    BN_free(r);

    return {C1, C2};
}

bool ElGamal::decrypt(const ElGamal::Ciphertext& ciphertext, const std::string& original_message, const BIGNUM* privateKey) {
    // 1. Calculate Shared Secret Point: x * C1
    ToyECC::Point sharedPoint = ecc_.scalarMultiply(privateKey, ciphertext.C1);

    // 2. Recover Message Point: M = C2 - (x * C1)
    // Point subtraction P - Q is equivalent to P + (-Q),
    // where -Q has the same x but a negated y coordinate.
    ToyECC::Point sharedPoint_inv = ecc_.newPoint(sharedPoint.x, sharedPoint.y, false);
    BN_set_negative(sharedPoint_inv.y, 1); // Negate y to prepare for subtraction via addition

    ToyECC::Point M_recovered = ecc_.pointAdd(ciphertext.C2, sharedPoint_inv);

    // 3. Re-create the original message point to verify correctness.
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(original_message.c_str()), original_message.length(), hash);
    BIGNUM* msg_scalar = BN_bin2bn(hash, SHA256_DIGEST_LENGTH, nullptr);
    ToyECC::Point M_original = ecc_.scalarMultiply(msg_scalar, ecc_.basePoint());

    // 4. Compare the x and y coordinates of the recovered point and the original.
    bool success = (BN_cmp(M_recovered.x, M_original.x) == 0) &&
                   (BN_cmp(M_recovered.y, M_original.y) == 0);

    // Clean up
    ecc_.freePoint(sharedPoint);
    ecc_.freePoint(sharedPoint_inv);
    ecc_.freePoint(M_recovered);
    ecc_.freePoint(M_original);
    BN_free(msg_scalar);

    return success;
}