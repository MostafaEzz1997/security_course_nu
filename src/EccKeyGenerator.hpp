#pragma once
// ^ Prevents multiple-inclusion of this header (like include guards, but simpler)

// Standard library containers for holding raw key bytes
#include <vector>
#include <string>

// OpenSSL EC types (EC_GROUP, EC_POINT, point_conversion_form_t, etc.)
#include <openssl/ec.h>

// OpenSSL NID constants for curves (e.g., NID_X9_62_prime256v1)
#include <openssl/obj_mac.h>

// -------------------- Key Pair --------------------
// A simple container type to hold an ECC key pair as raw byte vectors.
//
// Notes:
// - "privateKey" is the scalar d (big-endian), e.g., 32 bytes for P-256.
// - "publicKeyCompressed" and "publicKeyUncompressed" store the public point Q
//   encoded using SEC1 point encoding.
class EccKeyPair {
public:
    // Big-endian scalar bytes representing the private key "d".
    // Length depends on the curve (P-256 => 32 bytes, P-384 => 48 bytes, etc.).
    std::vector<unsigned char> privateKey;

    // Public key encoded in SEC1 *compressed* form:
    // - Starts with 0x02 or 0x03 (depending on Y parity)
    // - Followed by X coordinate only.
    // Size for P-256 is typically 33 bytes (1 + 32).
    std::vector<unsigned char> publicKeyCompressed;

    // Public key encoded in SEC1 *uncompressed* form:
    // - Starts with 0x04
    // - Followed by X || Y coordinates.
    // Size for P-256 is typically 65 bytes (1 + 32 + 32).
    std::vector<unsigned char> publicKeyUncompressed;
};

// -------------------- Key Generator --------------------
// Generates ECC key pairs for a chosen curve using OpenSSL.
class EccKeyGenerator {
public:
    // Constructor selecting which curve to use.
    //
    // curveNid examples:
    // - NID_X9_62_prime256v1  (aka P-256 / prime256v1)
    // - NID_secp256k1
    // - NID_secp384r1, NID_secp521r1, ...
    explicit EccKeyGenerator(int curveNid = NID_X9_62_prime256v1);

    // Generate a new ECC key pair (private scalar + public point)
    // and return it as raw byte vectors in both compressed and uncompressed SEC1 formats.
    EccKeyPair generate() const;

private:
    // Stored curve identifier used when generating keys
    int curveNid_;

    // Convert an EC_POINT (public key point) to SEC1 bytes using a specified format.
    //
    // Inputs:
    // - group: curve parameters (EC_GROUP)
    // - point: the public key point (EC_POINT)
    // - form:  encoding format (POINT_CONVERSION_COMPRESSED or _UNCOMPRESSED)
    //
    // Output:
    // - a vector containing SEC1 encoded point bytes.
    std::vector<unsigned char> pointToBytes(
        const EC_GROUP* group,
        const EC_POINT* point,
        point_conversion_form_t form) const;

    // Helper to throw a std::runtime_error with OpenSSL's current error queue details.
    // Used when an OpenSSL API returns failure.
    void throwOpenSslError(const char* msg) const;
};
