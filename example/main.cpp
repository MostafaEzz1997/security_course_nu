/**
 * @file main.cpp
 * @brief Demonstrates RSA key generation, encryption/decryption, and signing/verification.
 */

#include <algorithm>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include "RsaAlgo.hpp"

/**
 * @brief Performs an RSA encryption and decryption test for a given key size.
 * @details Generates a new key pair, encrypts a sample message, decrypts the
 *          ciphertext, and verifies that the decrypted message matches the original.
 *          The message is truncated if it exceeds the key's capacity.
 * @param rsa An instance of the RsaAlgo class.
 * @param bits The desired bit length for the RSA key.
 */
void RunEncryptionTest(RsaAlgo &rsa, unsigned int bits) {
    std::cout << "\n=== Encryption/Decryption Test for " << bits << "-bit key ===" << std::endl;
    // 1. Generate a new RSA key pair for the specified bit length.
    auto keys = rsa.GenerateKeys(bits);

    // 2. Create a sample message to encrypt.
    std::string message = "Hello RSA " + std::to_string(bits);
    // Textbook RSA cannot encrypt messages larger than the modulus.
    // Calculate the maximum message size in bytes and truncate if necessary.
    size_t max_bytes = std::max<size_t>(1, bits / 8 - 1);
    if (message.size() > max_bytes) {
        message.resize(max_bytes);
    }

    // 3. Encrypt the message using the public key.
    // The result is a raw BIGNUM* which must be managed.
    // A unique_ptr with a custom deleter (BN_free) ensures it's freed automatically.
    std::unique_ptr<BIGNUM, decltype(&BN_free)> ciphertext(rsa.Encrypt(message, keys), BN_free);
    // 4. Decrypt the ciphertext using the private key.
    auto decrypted = rsa.Decrypt(ciphertext.get(), keys);

    // 5. Print the original and decrypted messages and verify correctness.
    std::cout << "Original : " << message << std::endl;
    std::cout << "Decrypted: " << decrypted << std::endl;
    std::cout << (message == decrypted ? "Result   : success" : "Result   : failure") << std::endl;
}

/**
 * @brief Performs an RSA signing and verification test for a given key size.
 * @details Generates a new key pair, signs a sample message, and then verifies
 *          the signature against the original message. The message is truncated
 *          if it exceeds the key's capacity.
 * @param rsa An instance of the RsaAlgo class.
 * @param bits The desired bit length for the RSA key.
 */
void RunSignatureTest(RsaAlgo &rsa, unsigned int bits) {
    std::cout << "\n=== Signature Test for " << bits << "-bit key ===" << std::endl;
    // 1. Generate a new RSA key pair.
    auto keys = rsa.GenerateKeys(bits);

    // 2. Create a sample message to sign.
    std::string message = "Signature test " + std::to_string(bits);
    // As with encryption, the message cannot be larger than the modulus.
    size_t max_bytes = std::max<size_t>(1, bits / 8 - 1);
    if (message.size() > max_bytes) {
        message.resize(max_bytes);
    }

    // 3. Sign the message using the private key.
    // The returned BIGNUM* is managed by a unique_ptr to prevent memory leaks.
    std::unique_ptr<BIGNUM, decltype(&BN_free)> signature(rsa.Sign(message, keys), BN_free);
    // 4. Verify the signature against the original message using the public key.
    bool verified = rsa.Verify(message, signature.get(), keys);

    // 5. Print the results.
    std::cout << "Message  : " << message << std::endl;
    // Convert the signature to a hex string for printing.
    char *sig_hex = BN_bn2hex(signature.get());
    std::cout << "Signature: " << sig_hex << std::endl;
    OPENSSL_free(sig_hex); // Free the memory allocated by BN_bn2hex.
    std::cout << (verified ? "Result   : verified" : "Result   : failed") << std::endl;
}

/**
 * @brief Main entry point for the RSA demonstration program.
 * @details Initializes the RsaAlgo and runs a series of encryption/decryption
 *          and signing/verification tests with various key lengths.
 * @return 0 on successful execution.
 */
int main() {
    // Create an instance of the RSA algorithm engine.
    RsaAlgo rsa;
    std::vector<unsigned int> bit_lengths = {128, 1024, 2048, 4096};

    // Loop through different key sizes and run both tests for each.
    for (auto bits : bit_lengths) {
        RunEncryptionTest(rsa, bits);
        RunSignatureTest(rsa, bits);
    }

    return 0;
}
