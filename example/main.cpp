#include <iostream>
#include <vector>
#include <string>
#include <iomanip>

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
        EciesCiphertext ct = ecies.encrypt(plaintext, aad);

        printHex("Sender public key (getter)", ecies.getSenderPublicKeyUncompressed());
        printHex("Sender public key (in ciphertext)", ct.ephPublicKeyUncompressed);
        printHex("Nonce", ct.nonce);
        printHex("Ciphertext", ct.ciphertext);
        printHex("GCM tag", ct.tag);

        // --------------------------------------------------
        // 6) Decrypt
        // --------------------------------------------------
        std::vector<unsigned char> decrypted = ecies.decrypt(receiverKeys.privateKey, ct, aad);
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
