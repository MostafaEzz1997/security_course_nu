
#include <memory>
#include <stdexcept>

#include <openssl/err.h>
#include <openssl/rand.h>

#include "EccKeyGenerator.hpp"

// -------------------- Constructor --------------------
EccKeyGenerator::EccKeyGenerator(int curveNid)
    : curveNid_(curveNid)
{
    // Ensure OpenSSL RNG is properly seeded
    if (RAND_status() != 1) {
        throw std::runtime_error("OpenSSL RNG is not properly seeded");
    }
}

// -------------------- Key Generation --------------------
EccKeyPair EccKeyGenerator::generate() const {

    // Create an empty key-pair structure that will hold:
    //  - the private key scalar (bytes)
    //  - the public key (compressed & uncompressed)
    EccKeyPair kp;

    // ------------------------------------------------------
    // Create an RAII wrapper for OpenSSL's EC_KEY structure
    //
    // EC_KEY is a C-style object that must be freed manually
    // using EC_KEY_free(). To avoid memory leaks and ensure
    // exception safety, we wrap it in std::unique_ptr.
    //
    // The lambda 'deleter' defines how to properly destroy
    // the EC_KEY object when the unique_ptr goes out of scope.
    // ------------------------------------------------------
    auto deleter = [](EC_KEY* k) { if (k) EC_KEY_free(k); };

    // Create a new EC_KEY object for the specified elliptic curve.
    // curveNid_ identifies the curve (e.g. P-256, secp256k1, etc.)
    //
    // The unique_ptr now owns the EC_KEY and will free it
    // automatically when it goes out of scope.
    std::unique_ptr<EC_KEY, decltype(deleter)> key(
        EC_KEY_new_by_curve_name(curveNid_), deleter
    );

    // If OpenSSL failed to create the EC_KEY object,
    // throw an exception with the OpenSSL error details.
    if (!key) {
        throwOpenSslError("Failed to create EC_KEY");
    }

    // ------------------------------------------------------
    // Generate the actual ECC key pair
    //
    // This function:
    //  - randomly generates a private scalar d
    //  - computes the public point Q = d * G
    //
    // All heavy cryptographic operations are done internally
    // by OpenSSL.
    // ------------------------------------------------------
    if (EC_KEY_generate_key(key.get()) != 1) {
        throwOpenSslError("EC_KEY_generate_key failed");
    }

    // ------------------------------------------------------
    // Extract the private key
    //
    // OpenSSL stores the private key as a BIGNUM (big integer).
    // We obtain a *read-only* pointer to that BIGNUM.
    // ------------------------------------------------------
    const BIGNUM* privBn = EC_KEY_get0_private_key(key.get());

    // Sanity check: private key must exist after generation
    if (!privBn) {
        throw std::runtime_error("Private key is null");
    }

    // Determine how many bytes are needed to represent
    // the private key in big-endian format
    int privLen = BN_num_bytes(privBn);

    // Resize the output buffer to fit the private key
    kp.privateKey.resize(privLen);

    // Convert the BIGNUM into big-endian byte representation
    // and store it in kp.privateKey
    BN_bn2bin(privBn, kp.privateKey.data());

    // ------------------------------------------------------
    // Extract the public key
    //
    // The public key in ECC is an EC_POINT (x, y) on the curve.
    // The EC_GROUP contains the curve parameters.
    // ------------------------------------------------------
    const EC_POINT* pubPoint = EC_KEY_get0_public_key(key.get());
    const EC_GROUP* group    = EC_KEY_get0_group(key.get());

    // Sanity check: both the point and the curve must exist
    if (!pubPoint || !group) {
        throw std::runtime_error("Public key or group is null");
    }

    // ------------------------------------------------------
    // Convert the public key point to SEC1 uncompressed format
    //
    // Format:
    //   0x04 || X || Y
    //
    // This is the most explicit form of the EC public key and
    // is commonly used in certificates and debugging.
    // ------------------------------------------------------
    kp.publicKeyUncompressed =
        pointToBytes(group, pubPoint, POINT_CONVERSION_UNCOMPRESSED);

    // ------------------------------------------------------
    // Convert the public key point to SEC1 compressed format
    //
    // Format:
    //   0x02 || X   (if Y is even)
    //   0x03 || X   (if Y is odd)
    //
    // This saves space and is widely used in modern protocols.
    // ------------------------------------------------------
    kp.publicKeyCompressed =
        pointToBytes(group, pubPoint, POINT_CONVERSION_COMPRESSED);

    // Return the fully populated key pair
    return kp;
}

// -------------------- Helpers --------------------
std::vector<unsigned char>
EccKeyGenerator::pointToBytes(const EC_GROUP* group,
                              const EC_POINT* point,
                              point_conversion_form_t form)
{
    size_t len = EC_POINT_point2oct(
        group, point, form, nullptr, 0, nullptr);

    if (len == 0) {
        throwOpenSslError("EC_POINT_point2oct (size) failed");
    }

    std::vector<unsigned char> out(len);
    if (EC_POINT_point2oct(group, point, form,
                           out.data(), out.size(), nullptr) != len) {
        throwOpenSslError("EC_POINT_point2oct (data) failed");
    }

    return out;
}

void EccKeyGenerator::throwOpenSslError(const char* msg) {
    unsigned long err = ERR_get_error();
    char buf[256] = {0};

    if (err != 0) {
        ERR_error_string_n(err, buf, sizeof(buf));
        throw std::runtime_error(std::string(msg) + ": " + buf);
    } else {
        throw std::runtime_error(msg);
    }
}
