#pragma once
/**
 * @file EccKeyGenerator.hpp
 * @brief ECC key generation helpers (OpenSSL).
 *
 * This module provides a small C++ wrapper around OpenSSL to generate
 * Elliptic Curve (EC) keypairs for a selected curve.
 *
 * Keys are exported as raw byte vectors:
 * - Private key: big-endian scalar (d)
 * - Public key: SEC1 encoded point (compressed and uncompressed)
 *
 * @note This code uses OpenSSL's EC APIs. Internally, OpenSSL represents EC
 *       private keys as BIGNUM and public keys as EC_POINT on an EC_GROUP.
 */

#include <vector>
#include <string>

#include <openssl/ec.h>
#include <openssl/obj_mac.h>

/**
 * @brief Holds an ECC keypair in byte form.
 *
 * - @ref privateKey contains the private scalar d in big-endian encoding.
 * - @ref publicKeyCompressed contains SEC1 compressed public point encoding.
 * - @ref publicKeyUncompressed contains SEC1 uncompressed public point encoding.
 *
 * @warning Protect private keys as sensitive material. Do not log them in production.
 */
class EccKeyPair {
public:
    /** @brief Private key scalar (big-endian). For P-256 this is typically 32 bytes. */
    std::vector<unsigned char> privateKey;

    /**
     * @brief Public key in SEC1 compressed form.
     *
     * Encoding: 0x02/0x03 || X
     */
    std::vector<unsigned char> publicKeyCompressed;

    /**
     * @brief Public key in SEC1 uncompressed form.
     *
     * Encoding: 0x04 || X || Y
     */
    std::vector<unsigned char> publicKeyUncompressed;
};

/**
 * @brief ECC keypair generator for a specific curve.
 *
 * Example:
 * @code
 * EccKeyGenerator gen(NID_X9_62_prime256v1);
 * EccKeyPair kp = gen.generate();
 * @endcode
 */
class EccKeyGenerator {
public:
    /**
     * @brief Construct a key generator bound to an OpenSSL curve NID.
     * @param curveNid OpenSSL curve identifier (e.g. NID_X9_62_prime256v1, NID_secp256k1).
     * @throws std::runtime_error if OpenSSL RNG is not properly seeded.
     */
    explicit EccKeyGenerator(int curveNid = NID_X9_62_prime256v1);

    /**
     * @brief Generate a fresh ECC keypair.
     * @return A populated @ref EccKeyPair containing private scalar and public key encodings.
     * @throws std::runtime_error on any OpenSSL failure.
     */
    EccKeyPair generate() const;

private:
    /** @brief The curve used for key generation. */
    int curveNid_;

    /**
     * @brief Convert an EC_POINT to SEC1 byte encoding.
     * @param group Curve parameters.
     * @param point EC point to encode.
     * @param form Desired point conversion form (compressed/uncompressed).
     * @return SEC1 encoded point bytes.
     * @throws std::runtime_error on OpenSSL failure.
     */
    std::vector<unsigned char> pointToBytes(
        const EC_GROUP* group,
        const EC_POINT* point,
        point_conversion_form_t form) const;

    /**
     * @brief Throw a std::runtime_error containing the last OpenSSL error string.
     * @param msg Context message.
     * @throws std::runtime_error always.
     */
    [[noreturn]] void throwOpenSslError(const char* msg) const;
};
