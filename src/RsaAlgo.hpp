/**
 * @file RsaAlgo.hpp
 * @brief Defines the RsaAlgo class, which provides a from-scratch implementation
 * of the RSA algorithm for key generation, encryption, and digital signatures.
 *
 * This implementation is for educational purposes and demonstrates the core
 * mathematical principles of RSA. It uses OpenSSL's BIGNUM library for
 * arbitrary-precision arithmetic.
 *
 * @warning This implementation is not secure for production use as it lacks
 *          proper cryptographic padding (e.g., OAEP, PSS).
 */

#pragma once

#include <openssl/bn.h>
#include <memory>
#include <string>

/// @brief The main namespace for the RSA implementation.
namespace rsa {

/**
 * @brief A custom deleter for OpenSSL BIGNUM objects.
 *
 * This functor is used with std::unique_ptr to ensure that BN_free() is called
 * to release BIGNUM resources, enabling safe, automatic memory management.
 */
struct BigNumDeleter {
    /**
     * @brief The function call operator that frees the BIGNUM resource.
     * @param bn A pointer to the BIGNUM object to be freed.
     */
    void operator()(BIGNUM *bn) const noexcept {
        if (bn != nullptr) {
            BN_free(bn);
        }
    }
};
/// @brief A smart pointer for managing BIGNUM resources automatically.
using BigNumPtr = std::unique_ptr<BIGNUM, BigNumDeleter>;

/**
 * @brief A struct to hold a complete RSA key pair, including public, private,
 * and component parts.
 *
 * Smart pointers are used to manage the memory of all BIGNUM components.
 */
struct RsaKeyPair {
    BigNumPtr n;
    BigNumPtr e;
    BigNumPtr d;
    BigNumPtr p;
    BigNumPtr q;
    BigNumPtr phi;
    std::size_t key_bits{};

    RsaKeyPair() = default;
    RsaKeyPair(RsaKeyPair &&) noexcept = default;
    RsaKeyPair &operator=(RsaKeyPair &&) noexcept = default;
};

/**
 * @brief A class providing static methods to perform RSA operations.
 *
 * This class encapsulates the logic for key generation, encryption, decryption,
 * signing, and verification. All methods are static, making the class a
 * utility library rather than an object to be instantiated.
 */
class RsaAlgo {
public:
    /**
     * @brief Generates a new RSA key pair of a specified bit length.
     * @param key_bits The desired total bit length for the modulus `n`. Must be a
     * multiple of 128 and between 128 and 4096, inclusive.
     * @return An RsaKeyPair struct containing the generated keys.
     * @throws std::runtime_error if the key size is unsupported or if an
     *         OpenSSL error occurs during generation.
     */
    static RsaKeyPair generateKeyPair(std::size_t key_bits);

    /**
     * @brief Encrypts a message using a standard binary exponentiation algorithm.
     * @param message The BIGNUM representation of the message to encrypt.
     * @param e The public exponent.
     * @param n The public modulus.
     * @return A BigNumPtr to the resulting ciphertext.
     * @throws std::runtime_error if the message is too large for the modulus.
     */
    static BigNumPtr encryptNormal(const BIGNUM *message, const BIGNUM *e, const BIGNUM *n);

    /**
     * @brief Encrypts a message using the efficient square-and-multiply algorithm.
     * @param message The BIGNUM representation of the message to encrypt.
     * @param e The public exponent.
     * @param n The public modulus.
     * @return A BigNumPtr to the resulting ciphertext.
     * @throws std::runtime_error if the message is too large for the modulus.
     */
    static BigNumPtr encryptSquareMultiply(const BIGNUM *message, const BIGNUM *e, const BIGNUM *n);

    /**
     * @brief Decrypts a ciphertext using a standard binary exponentiation algorithm.
     * @param cipher The BIGNUM representation of the ciphertext to decrypt.
     * @param d The private exponent.
     * @param n The public modulus.
     * @return A BigNumPtr to the recovered plaintext message.
     */
    static BigNumPtr decryptNormal(const BIGNUM *cipher, const BIGNUM *d, const BIGNUM *n);

    /**
     * @brief Decrypts a ciphertext using the efficient square-and-multiply algorithm.
     * @param cipher The BIGNUM representation of the ciphertext to decrypt.
     * @param d The private exponent.
     * @param n The public modulus.
     * @return A BigNumPtr to the recovered plaintext message.
     */
    static BigNumPtr decryptSquareMultiply(const BIGNUM *cipher, const BIGNUM *d, const BIGNUM *n);

    /**
     * @brief Creates a digital signature for a message using the private key.
     * @param message The BIGNUM representation of the message to sign.
     * @param d The private exponent.
     * @param n The public modulus.
     * @return A BigNumPtr to the resulting signature.
     * @throws std::runtime_error if the message is too large for the modulus.
     */
    static BigNumPtr signMessage(const BIGNUM *message, const BIGNUM *d, const BIGNUM *n);

    /**
     * @brief Verifies a digital signature against a message using the public key.
     * @param signature The BIGNUM representation of the signature to verify.
     * @param expectedMessage The BIGNUM representation of the original message.
     * @param e The public exponent.
     * @param n The public modulus.
     * @return True if the signature is valid for the message, false otherwise.
     */
    static bool verifySignature(const BIGNUM *signature, const BIGNUM *expectedMessage, const BIGNUM *e,
                                const BIGNUM *n);

    /**
     * @brief Converts a raw string message into its BIGNUM integer representation.
     * @param message The string to convert.
     * @return A BigNumPtr containing the integer representation.
     */
    static BigNumPtr messageToInt(const std::string &message);

    /**
     * @brief Converts a BIGNUM integer back into a raw string message.
     * @param value The BIGNUM to convert.
     * @return The resulting string.
     */
    static std::string intToMessage(const BIGNUM *value);

private:
    /// @brief Creates a new, empty, and managed BIGNUM object.
    static BigNumPtr makeBigNum();
    /// @brief Creates a deep copy of a BIGNUM object.
    static BigNumPtr clone(const BIGNUM *source);

    /// @brief Generates a random integer of a specific bit length.
    static BigNumPtr generateRandomBigInt(std::size_t bits);
    /// @brief Performs a Miller-Rabin probabilistic primality test.
    static bool isProbablePrime(const BIGNUM *number, int iterations = 10);
    /// @brief Generates a large prime number of a specific bit length.
    static BigNumPtr generatePrime(std::size_t bits, const BIGNUM *other_prime);

    /// @brief Computes the greatest common divisor (GCD) of two BIGNUMs.
    static BigNumPtr gcd(const BIGNUM *a, const BIGNUM *b);
    /// @brief Computes the modular multiplicative inverse using the Extended Euclidean Algorithm.
    static BigNumPtr modInverse(const BIGNUM *a, const BIGNUM *modulus);

    /// @brief Computes modular exponentiation using a right-to-left binary method.
    static BigNumPtr modExpNormal(const BIGNUM *base, const BIGNUM *exponent, const BIGNUM *modulus);
    /// @brief Computes modular exponentiation using a left-to-right binary method (square-and-multiply).
    static BigNumPtr modExpSquareAndMultiply(const BIGNUM *base, const BIGNUM *exponent, const BIGNUM *modulus);
};

} // namespace rsa
