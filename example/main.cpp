#include <iostream>
#include <iomanip>

#include "ToyECCKeygen.hpp"

int main() {
    try {
        // secp256k1 parameters are required for the constructor
        const char* p_hex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
        const char* a_hex = "0";
        const char* b_hex = "7";
        const char* n_hex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
        const char* gx_hex = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
        const char* gy_hex = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";

        // Create the ECC object with secp256k1 parameters
        ToyECC ecc(p_hex, a_hex, b_hex, n_hex, gx_hex, gy_hex);

        // Generate a key pair
        ToyECC::KeyPair kp = ecc.generateKeyPair();

        char* private_key_hex = BN_bn2hex(kp.privateKey);
        std::cout << "Private key (hex): 0x" << private_key_hex << "\n";
        std::cout << "Public key (Base64 compressed): " << kp.publicKey << "\n";

        // Clean up memory
        OPENSSL_free(private_key_hex);
        BN_free(kp.privateKey);

    } catch (const std::exception& e) {
        std::cerr << "An error occurred: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
