#include <iostream>
#include <iomanip>
#include <chrono>

#include "ToyECCKeygen.hpp"
#include "ElGamal.hpp"
#include "ECDSA.hpp"

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

        std::cout << "\n--- ElGamal Encryption/Decryption Test ---\n";

        // The message to be encrypted
        std::string original_message = "This is a secret message for testing ElGamal!";
        std::cout << "Original Message: " << original_message << std::endl;

        // Get the public key as a Point object
        ToyECC::Point publicKeyPoint = ecc.scalarMultiply(kp.privateKey, ecc.basePoint());

        // Initialize ElGamal with our ECC instance
        ElGamal elgamal(ecc);

        // --- Encryption ---
        auto start_encrypt = std::chrono::high_resolution_clock::now();
        ElGamal::Ciphertext ciphertext = elgamal.encrypt(original_message, publicKeyPoint);
        auto end_encrypt = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> encrypt_time = end_encrypt - start_encrypt;

        std::cout << "Encryption successful. Ciphertext (C1, C2):" << std::endl;
        char* c1x_hex = BN_bn2hex(ciphertext.C1.x);
        char* c1y_hex = BN_bn2hex(ciphertext.C1.y);
        char* c2x_hex = BN_bn2hex(ciphertext.C2.x);
        char* c2y_hex = BN_bn2hex(ciphertext.C2.y);
        std::cout << "  C1.x: " << c1x_hex << std::endl;
        std::cout << "  C1.y: " << c1y_hex << std::endl;
        std::cout << "  C2.x: " << c2x_hex << std::endl;
        std::cout << "  C2.y: " << c2y_hex << std::endl;
        OPENSSL_free(c1x_hex);
        OPENSSL_free(c1y_hex);
        OPENSSL_free(c2x_hex);
        OPENSSL_free(c2y_hex);

        // --- Decryption ---
        auto start_decrypt = std::chrono::high_resolution_clock::now();
        bool decryption_ok = elgamal.decrypt(ciphertext, original_message, kp.privateKey);
        auto end_decrypt = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> decrypt_time = end_decrypt - start_decrypt;

        std::cout << "Decryption verification status: " << (decryption_ok ? "SUCCESS" : "FAILURE") << std::endl;
        if (decryption_ok) {
            std::cout << "Successfully decrypted message: \"" << original_message << "\"" << std::endl;
        } else {
            std::cout << "Failed to recover the original message." << std::endl;
        }

        // --- Performance Results ---
        std::cout << "\n--- Performance ---\n";
        std::cout << "Encryption time: " << encrypt_time.count() << " ms\n";
        std::cout << "Decryption time: " << decrypt_time.count() << " ms\n";
        std::chrono::duration<double, std::milli> sign_time;
        std::chrono::duration<double, std::milli> verify_time;

        std::cout << "\n--- ECDSA Signing/Verification Test ---\n";
        std::string sign_message = "This message will be signed by ECDSA.";
        std::cout << "Message to sign: \"" << sign_message << "\"" << std::endl;

        // Initialize ECDSA handler
        ECDSA ecdsa(ecc);

        // --- Signing ---
        auto start_sign = std::chrono::high_resolution_clock::now();
        ECDSA::Signature signature = ecdsa.sign(sign_message, kp.privateKey);
        auto end_sign = std::chrono::high_resolution_clock::now();
        sign_time = end_sign - start_sign;
        char* r_hex = BN_bn2hex(signature.r);
        char* s_hex = BN_bn2hex(signature.s);
        std::cout << "Signing successful. Signature (r, s):" << std::endl;
        std::cout << "  r: " << r_hex << std::endl;
        std::cout << "  s: " << s_hex << std::endl;
        OPENSSL_free(r_hex);
        OPENSSL_free(s_hex);

        // --- Verification ---
        auto start_verify = std::chrono::high_resolution_clock::now();
        bool signature_ok = ecdsa.verify(sign_message, signature, publicKeyPoint);
        auto end_verify = std::chrono::high_resolution_clock::now();
        verify_time = end_verify - start_verify;
        std::cout << "Signature verification status: " << (signature_ok ? "SUCCESS" : "FAILURE") << std::endl;
        BN_free(signature.r);
        BN_free(signature.s);

        // --- Updated Performance Results ---
        std::cout << "Signing time: " << sign_time.count() << " ms\n";
        std::cout << "Verification time: " << verify_time.count() << " ms\n";

        // --- Final Cleanup ---
        // Free all allocated resources at the very end.
        OPENSSL_free(private_key_hex);
        BN_free(kp.privateKey);
        ecc.freePoint(publicKeyPoint);
        ecc.freePoint(ciphertext.C1);
        ecc.freePoint(ciphertext.C2);

    } catch (const std::exception& e) {
        std::cerr << "An error occurred: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
