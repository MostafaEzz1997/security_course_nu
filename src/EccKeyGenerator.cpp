/**
 * @file EccKeyGenerator.cpp
 * @brief Implementation of ECC key generation utilities.
 */

#include "EccKeyGenerator.hpp"

#include <memory>
#include <stdexcept>

#include <openssl/err.h>
#include <openssl/rand.h>

/* -------------------------------------------------------------------------- */
/* Constructor                                                                */
/* -------------------------------------------------------------------------- */

EccKeyGenerator::EccKeyGenerator(int curveNid)
    : curveNid_(curveNid)
{
    // Ensure OpenSSL RNG is properly seeded before generating keys.
    // RAND_status() == 1 means OpenSSL believes the DRBG is ready.
    if (RAND_status() != 1) {
        throw std::runtime_error("OpenSSL RNG is not properly seeded");
    }
}

/* -------------------------------------------------------------------------- */
/* Key Generation                                                             */
/* -------------------------------------------------------------------------- */

/**
 * @brief Generate an ECC keypair for the configured curve.
 *
 * Steps:
 * 1) Allocate an EC_KEY for the curve.
 * 2) Ask OpenSSL to generate a random private scalar and corresponding public point.
 * 3) Export private scalar (BIGNUM -> big-endian bytes).
 * 4) Export public point in SEC1 compressed and uncompressed formats.
 *
 * @return Newly generated keypair.
 * @throws std::runtime_error on OpenSSL failure.
 */
EccKeyPair EccKeyGenerator::generate() const
{
    EccKeyPair kp; // output container

    // EC_KEY is a C object that must be freed with EC_KEY_free().
    // Wrap it with unique_ptr to ensure exception-safe cleanup (RAII).
    auto deleter = [](EC_KEY* k) { if (k) EC_KEY_free(k); };
    std::unique_ptr<EC_KEY, decltype(deleter)> key(
        EC_KEY_new_by_curve_name(curveNid_), deleter);

    if (!key) {
        throwOpenSslError("Failed to create EC_KEY");
    }

    // Generate private scalar and public point: Q = d * G
    if (EC_KEY_generate_key(key.get()) != 1) {
        throwOpenSslError("EC_KEY_generate_key failed");
    }

    // ---- Export private scalar d ----
    const BIGNUM* privBn = EC_KEY_get0_private_key(key.get());
    if (!privBn) {
        throw std::runtime_error("Private key is null");
    }

    const int privLen = BN_num_bytes(privBn);
    kp.privateKey.resize(static_cast<size_t>(privLen));
    BN_bn2bin(privBn, kp.privateKey.data());

    // ---- Export public point Q ----
    const EC_POINT* pubPoint = EC_KEY_get0_public_key(key.get());
    const EC_GROUP* group    = EC_KEY_get0_group(key.get());
    if (!pubPoint || !group) {
        throw std::runtime_error("Public key or group is null");
    }

    kp.publicKeyUncompressed = pointToBytes(group, pubPoint, POINT_CONVERSION_UNCOMPRESSED);
    kp.publicKeyCompressed   = pointToBytes(group, pubPoint, POINT_CONVERSION_COMPRESSED);

    return kp;
}

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * @brief Encode an EC point as SEC1 bytes.
 * @param group Curve group.
 * @param point EC point.
 * @param form Encoding form (compressed/uncompressed).
 * @return Encoded bytes.
 * @throws std::runtime_error on OpenSSL error.
 */
std::vector<unsigned char>
EccKeyGenerator::pointToBytes(const EC_GROUP* group,
                              const EC_POINT* point,
                              point_conversion_form_t form) const
{
    // Query required length
    const size_t len = EC_POINT_point2oct(group, point, form, nullptr, 0, nullptr);
    if (len == 0) {
        throwOpenSslError("EC_POINT_point2oct (size) failed");
    }

    std::vector<unsigned char> out(len);

    // Encode into buffer
    const size_t written = EC_POINT_point2oct(group, point, form, out.data(), out.size(), nullptr);
    if (written != len) {
        throwOpenSslError("EC_POINT_point2oct (data) failed");
    }

    return out;
}

/**
 * @brief Throw with the last OpenSSL error (if present).
 * @param msg Context message.
 * @throws std::runtime_error always.
 */
[[noreturn]] void EccKeyGenerator::throwOpenSslError(const char* msg) const
{
    const unsigned long err = ERR_get_error();
    char buf[256] = {0};

    if (err != 0) {
        ERR_error_string_n(err, buf, sizeof(buf));
        throw std::runtime_error(std::string(msg) + ": " + buf);
    }

    throw std::runtime_error(msg);
}
