#ifndef _RSAALGO_HPP_
#define _RSAALGO_HPP_

#include <cstdint>
#include <memory>
#include <random>
#include <string>
#include <vector>
#include <openssl/bn.h>
#include <openssl/rand.h>

/**
 * @class RsaAlgo
 * @brief Implements a textbook RSA algorithm for key generation, encryption,
 *        decryption, signing, and verification using the OpenSSL BIGNUM library.
 * @warning This is a textbook implementation and lacks security features like
 *          padding (e.g., OAEP, PSS), making it vulnerable to attacks.
 *          It should be used for educational purposes only.
 */
class RsaAlgo {
public:
    /**
     * @struct KeyPair
     * @brief Holds the public and private components of an RSA key, represented as hex strings.
     */
    struct KeyPair {
        std::string n; ///< The modulus (part of the public and private key).
        std::string e; ///< The public exponent.
        std::string d; ///< The private exponent.
        std::string p; ///< The first prime factor of n (private).
        std::string q; ///< The second prime factor of n (private).
    };

    /**
     * @brief Constructs an RsaAlgo instance.
     * @param prime_checks The number of Miller-Rabin primality test rounds to perform.
     *                     Higher values increase confidence but take longer.
     */
    explicit RsaAlgo(unsigned int prime_checks = 16);

    /**
     * @brief Generates a new RSA public/private key pair.
     * @param key_bits The desired bit length of the modulus `n`. Must be >= 64.
     * @param min_delta_bytes The minimum required difference between the generated primes `p` and `q`
     *                        to avoid factorization attacks.
     * @return A KeyPair struct containing all key components as hex strings.
     * @throws std::invalid_argument if key_bits is too small.
     * @throws std::runtime_error on OpenSSL allocation or computation failures.
     */
    KeyPair GenerateKeys(unsigned int key_bits, unsigned int min_delta_bytes = 256);

    /**
     * @brief Encrypts a message using the public key (c = m^e mod n).
     * @param message The raw string data to encrypt.
     * @param public_key A KeyPair struct containing the public key components (n and e).
     * @return A raw pointer to a BIGNUM object holding the ciphertext. The caller is responsible for freeing this memory with BN_free().
     * @throws std::invalid_argument if the message is larger than the modulus `n`.
     * @throws std::runtime_error on OpenSSL allocation or computation failures.
     */
    BIGNUM* Encrypt(const std::string &message, const KeyPair &public_key);

    /**
     * @brief Decrypts a ciphertext using the private key (m = c^d mod n).
     * @param ciphertext A pointer to the BIGNUM object to decrypt.
     * @param private_key A KeyPair struct containing the private key components (n and d).
     * @return The decrypted message as a raw string.
     * @throws std::runtime_error on OpenSSL allocation or computation failures.
     */
    std::string Decrypt(const BIGNUM *ciphertext, const KeyPair &private_key);

    /**
     * @brief Signs a message using the private key (s = m^d mod n).
     * @param message The raw string data to sign.
     * @param private_key A KeyPair struct containing the private key components (n and d).
     * @return A raw pointer to a BIGNUM object holding the signature. The caller is responsible for freeing this memory with BN_free().
     * @throws std::invalid_argument if the message is larger than the modulus `n`.
     * @throws std::runtime_error on OpenSSL allocation or computation failures.
     */
    BIGNUM* Sign(const std::string &message, const KeyPair &private_key);

    /**
     * @brief Verifies a signature against a message using the public key.
     * @param message The original message that was signed.
     * @param signature A pointer to the BIGNUM signature to verify.
     * @param public_key A KeyPair struct containing the public key components (n and e).
     * @return True if the signature is valid for the message, false otherwise.
     */
    bool Verify(const std::string &message, const BIGNUM *signature, const KeyPair &public_key);

private:
    unsigned int _prime_checks; ///< Number of Miller-Rabin rounds for primality testing.
    std::mt19937_64 _rng;       ///< Random number generator for non-crypto purposes.

    /// @brief A smart pointer for managing BIGNUM resources.
    using BN_ptr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
    /// @brief A smart pointer for managing BN_CTX resources.
    using CTX_ptr = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;

    /**
     * @brief Generates a random prime number of a specified bit length.
     * @param bits The desired bit length of the prime.
     * @return A BN_ptr to the generated prime.
     */
    BN_ptr GeneratePrime(unsigned int bits);

    /**
     * @brief Generates a pair of distinct primes (p, q) suitable for RSA.
     * @param bits The desired bit length for each prime.
     * @param min_delta_bytes The minimum required difference between p and q.
     * @return A std::pair of BN_ptr objects for the two primes.
     */
    std::pair<BN_ptr, BN_ptr> GeneratePrimePair(unsigned int bits, unsigned int min_delta_bytes);

    /**
     * @brief Converts a vector of bytes to a BIGNUM.
     * @param bytes The byte vector to convert.
     * @return A BN_ptr to the resulting BIGNUM.
     */
    BN_ptr BytesToBigNum(const std::vector<uint8_t> &bytes);

    /**
     * @brief Converts a BIGNUM to a vector of bytes.
     * @param value The BIGNUM to convert.
     * @return A std::vector<uint8_t> containing the byte representation.
     */
    std::vector<uint8_t> BigNumToBytes(const BIGNUM *value);

    /**
     * @brief Loads a BIGNUM from its hexadecimal string representation.
     * @param hex The hex string to parse.
     * @return A BN_ptr to the resulting BIGNUM.
     */
    BN_ptr LoadFromHex(const std::string &hex);

    /**
     * @brief Converts a BIGNUM to its hexadecimal string representation.
     * @param value The BIGNUM to convert.
     * @return A std::string containing the hex representation.
     */
    std::string ToHex(const BIGNUM *value);
};

#endif // _RSAALGO_HPP_
