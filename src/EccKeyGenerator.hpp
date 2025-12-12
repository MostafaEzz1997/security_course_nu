#pragma once

#include <vector>
#include <string>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

// -------------------- Key Pair --------------------
class EccKeyPair {
public:
    // Big-endian scalar bytes (length depends on curve; 32 bytes for P-256)
    std::vector<unsigned char> privateKey;

    // Public key in SEC1 format
    std::vector<unsigned char> publicKeyCompressed;
    std::vector<unsigned char> publicKeyUncompressed;
};

// -------------------- Key Generator --------------------
class EccKeyGenerator {
public:
    // curveNid: e.g. NID_X9_62_prime256v1 (P-256), NID_secp256k1, etc.
    explicit EccKeyGenerator(int curveNid = NID_X9_62_prime256v1);

    // Generate ECC key pair
    EccKeyPair generate() const;

private:
    int curveNid_;

    static std::vector<unsigned char> pointToBytes(
        const EC_GROUP* group,
        const EC_POINT* point,
        point_conversion_form_t form);

    static void throwOpenSslError(const char* msg);
};
