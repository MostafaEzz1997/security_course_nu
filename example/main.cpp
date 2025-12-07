/**
 * @file main.cpp
 * @brief Demonstrates RSA key generation, encryption/decryption, and signing/verification.
 */

#include <chrono>
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
    auto start_gen = std::chrono::high_resolution_clock::now();
    auto keys = rsa.GenerateKeys(bits);
    auto end_gen = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> gen_time = end_gen - start_gen;
    std::cout << "Key Generation: " << gen_time.count() << " ms" << std::endl;

    // 2. Create a sample message to encrypt.
    std::string message = "Hello RSA " + std::to_string(bits);
    // Textbook RSA cannot encrypt messages larger than the modulus.
    // Calculate the maximum message size in bytes and truncate if necessary.
    size_t max_bytes = std::max<size_t>(1, bits / 8 - 1);
    if (message.size() > max_bytes) {
        message.resize(max_bytes);
    }

    // 3. Encrypt the message using the public key.
    auto start_encrypt = std::chrono::high_resolution_clock::now();
    auto ciphertext = rsa.Encrypt(message, keys);
    auto end_encrypt = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::micro> encrypt_time = end_encrypt - start_encrypt;

    // 4. Decrypt the ciphertext using the private key.
    auto start_decrypt = std::chrono::high_resolution_clock::now();
    auto decrypted = rsa.Decrypt(ciphertext.get(), keys);
    auto end_decrypt = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::micro> decrypt_time = end_decrypt - start_decrypt;

    // 5. Print the original and decrypted messages and verify correctness.
    std::cout << "Original : " << message << std::endl;
    std::cout << "Decrypted: " << decrypted << std::endl;
    std::cout << (message == decrypted ? "Result   : success" : "Result   : failure") << std::endl;
    std::cout << "Time     : Encrypt " << encrypt_time.count() << " us | Decrypt " << decrypt_time.count() << " us" << std::endl;
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
    auto start_gen = std::chrono::high_resolution_clock::now();
    auto keys = rsa.GenerateKeys(bits);
    auto end_gen = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> gen_time = end_gen - start_gen;
    std::cout << "Key Generation: " << gen_time.count() << " ms" << std::endl;

    // 2. Create a sample message to sign.
    std::string message = "Signature test " + std::to_string(bits);
    // As with encryption, the message cannot be larger than the modulus.
    size_t max_bytes = std::max<size_t>(1, bits / 8 - 1);
    if (message.size() > max_bytes) {
        message.resize(max_bytes);
    }

    // 3. Sign the message using the private key.
    auto start_sign = std::chrono::high_resolution_clock::now();
    auto signature = rsa.Sign(message, keys);
    auto end_sign = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::micro> sign_time = end_sign - start_sign;

    // 4. Verify the signature against the original message using the public key.
    auto start_verify = std::chrono::high_resolution_clock::now();
    bool verified = rsa.Verify(message, signature.get(), keys);
    auto end_verify = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::micro> verify_time = end_verify - start_verify;

    // 5. Print the results.
    std::cout << "Message  : " << message << std::endl;

    // Convert the signature to a hex string for printing.
    char *sig_hex = BN_bn2hex(signature.get());
    std::cout << "Signature: " << sig_hex << std::endl;
    OPENSSL_free(sig_hex); // Free the memory allocated by BN_bn2hex.

    std::cout << (verified ? "Result   : verified" : "Result   : failed") << std::endl;
    std::cout << "Time     : Sign " << sign_time.count() << " us | Verify " << verify_time.count() << " us" << std::endl;
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
