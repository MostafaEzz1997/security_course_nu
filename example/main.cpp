#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <chrono>

#include "EccKeyGenerator.hpp"
#include "EciesCipher.hpp"

// ---------- Helpers ----------
static void printHex(const std::string& label,
                     const std::vector<unsigned char>& data)
{
    std::cout << label << " (" << data.size() << " bytes): ";
    for (unsigned char b : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(b);
    }
    std::cout << std::dec << "\n";
}

// ---------- Main ----------
int main()
{
    try {
        std::cout << "=== ECIES Test Application (New Constructors) ===\n";

        // --------------------------------------------------
        // 1) Generate receiver keypair (recipient)
        // --------------------------------------------------
        EccKeyGenerator keyGen; // default: P-256
        EccKeyPair receiverKeys = keyGen.generate();

        printHex("Receiver private key", receiverKeys.privateKey);
        printHex("Receiver public key (uncompressed)", receiverKeys.publicKeyUncompressed);

        // --------------------------------------------------
        // 2) (Optional) Generate sender keypair (static sender identity)
        // --------------------------------------------------
        EccKeyPair senderKeys = keyGen.generate();
        printHex("Sender private key", senderKeys.privateKey);
        printHex("Sender public key (uncompressed)", senderKeys.publicKeyUncompressed);

        // --------------------------------------------------
        // 3) Create ECIES cipher
        //    Choose ONE of the two constructors:
        // --------------------------------------------------

        // (A) Static sender + mandatory receiver pubkey
        EciesCipher ecies(
            senderKeys.privateKey,
            senderKeys.publicKeyUncompressed,
            receiverKeys.publicKeyUncompressed
            // , NID_X9_62_prime256v1   // optional
        );

        // (B) Ephemeral sender per message + mandatory receiver pubkey
        // EciesCipher ecies(receiverKeys.publicKeyUncompressed /*, optional curveNid */);

        // --------------------------------------------------
        // 4) Message + AAD (Additional Authenticated Data)
        // --------------------------------------------------
        const std::string message = "Hello ECIES! 🚀";
        std::vector<unsigned char> plaintext(message.begin(), message.end());

        const std::string aadStr = "associated-data-v1";
        std::vector<unsigned char> aad(aadStr.begin(), aadStr.end());

        printHex("Plaintext", plaintext);
        printHex("AAD", aad);

        // --------------------------------------------------
        // 5) Encrypt
        // --------------------------------------------------
        // Measure encryption time (single run)
        const auto enc_t0 = std::chrono::high_resolution_clock::now();
        EciesCiphertext ct = ecies.encrypt(plaintext, aad);
        const auto enc_t1 = std::chrono::high_resolution_clock::now();
        const auto enc_us = std::chrono::duration_cast<std::chrono::microseconds>(enc_t1 - enc_t0).count();
        std::cout << "Encryption time (single): " << enc_us << " us\n";

        // Optional: measure average encryption time over multiple iterations to reduce noise
        constexpr int ENC_BENCH_ITERS = 200; // adjust as needed
        std::size_t sink = 0; // prevents the compiler from optimizing the loop away
        const auto enc_bench_t0 = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < ENC_BENCH_ITERS; ++i) {
            EciesCiphertext tmp = ecies.encrypt(plaintext, aad);
            sink ^= tmp.ciphertext.size();
        }
        const auto enc_bench_t1 = std::chrono::high_resolution_clock::now();
        const auto enc_bench_us = std::chrono::duration_cast<std::chrono::microseconds>(enc_bench_t1 - enc_bench_t0).count();
        std::cout << "Encryption time (avg over " << ENC_BENCH_ITERS << "): "
                  << (enc_bench_us / static_cast<double>(ENC_BENCH_ITERS)) << " us\n";
        (void)sink;

        printHex("Sender public key (getter)", ecies.getSenderPublicKeyUncompressed());
        printHex("Sender public key (in ciphertext)", ct.ephPublicKeyUncompressed);
        printHex("Nonce", ct.nonce);
        printHex("Ciphertext", ct.ciphertext);
        printHex("GCM tag", ct.tag);

        // --------------------------------------------------
        // 6) Decrypt
        // --------------------------------------------------
        // Measure decryption time (single run)
        const auto dec_t0 = std::chrono::high_resolution_clock::now();
        std::vector<unsigned char> decrypted = ecies.decrypt(receiverKeys.privateKey, ct, aad);
        const auto dec_t1 = std::chrono::high_resolution_clock::now();
        const auto dec_us = std::chrono::duration_cast<std::chrono::microseconds>(dec_t1 - dec_t0).count();
        std::cout << "Decryption time (single): " << dec_us << " us\n";

        // Optional: measure average decryption time over multiple iterations to reduce noise
        constexpr int DEC_BENCH_ITERS = 200; // adjust as needed
        std::size_t dec_sink = 0; // prevents optimizing away
        const auto dec_bench_t0 = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < DEC_BENCH_ITERS; ++i) {
            // Note: decrypt must use a valid ciphertext+tag; reuse the same ct for timing.
            std::vector<unsigned char> tmp = ecies.decrypt(receiverKeys.privateKey, ct, aad);
            dec_sink ^= tmp.size();
        }
        const auto dec_bench_t1 = std::chrono::high_resolution_clock::now();
        const auto dec_bench_us = std::chrono::duration_cast<std::chrono::microseconds>(dec_bench_t1 - dec_bench_t0).count();
        std::cout << "Decryption time (avg over " << DEC_BENCH_ITERS << "): "
                  << (dec_bench_us / static_cast<double>(DEC_BENCH_ITERS)) << " us\n";
        (void)dec_sink;

        printHex("Decrypted plaintext", decrypted);

        // --------------------------------------------------
        // 7) Verify
        // --------------------------------------------------
        if (decrypted == plaintext) {
            std::cout << "\n✅ SUCCESS: Decrypted plaintext matches original\n";
        } else {
            std::cout << "\n❌ FAILURE: Decrypted plaintext does NOT match\n";
        }

        std::cout << "Decrypted message: \""
                  << std::string(decrypted.begin(), decrypted.end())
                  << "\"\n";
    }
    catch (const std::exception& ex) {
        std::cerr << "\n❌ Exception: " << ex.what() << "\n";
        return 1;
    }

    return 0;
}
