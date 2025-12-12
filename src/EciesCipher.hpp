#pragma once

#include <vector>
#include <string>
#include <openssl/obj_mac.h>

#include "EccKeyGenerator.hpp"

// ECIES-style output package (ECDH + HKDF-SHA256 + AES-256-GCM)
struct EciesCiphertext {
    std::vector<unsigned char> ephPublicKeyUncompressed; // SEC1: 0x04 || X || Y  (sender pubkey used for ECDH)
    std::vector<unsigned char> nonce;                    // 12 bytes (GCM)
    std::vector<unsigned char> ciphertext;               // encrypted payload
    std::vector<unsigned char> tag;                      // 16 bytes auth tag
};

class EciesCipher {
public:
    // (1) Static sender identity + mandatory receiver public key
    EciesCipher(
        const std::vector<unsigned char>& senderPrivateKey,
        const std::vector<unsigned char>& senderPublicKeyUncompressed,
        const std::vector<unsigned char>& receiverPublicKeyUncompressed,
        int curveNid = NID_X9_62_prime256v1
    );

    // (2) Ephemeral sender per message + mandatory receiver public key
    explicit EciesCipher(
        const std::vector<unsigned char>& receiverPublicKeyUncompressed,
        int curveNid = NID_X9_62_prime256v1
    );

    // Optional: allow changing receiver key after construction
    void setReceiverPublicKeyUncompressed(const std::vector<unsigned char>& receiverPublicKeyUncompressed);
    const std::vector<unsigned char>& getReceiverPublicKeyUncompressed() const noexcept;

    // Getter: returns configured sender public key if static sender is configured,
    // otherwise returns the last ephemeral sender public key used by encrypt().
    std::vector<unsigned char> getSenderPublicKeyUncompressed() const;

    EciesCiphertext encrypt(
        const std::vector<unsigned char>& plaintext,
        const std::vector<unsigned char>& aad = {}
    ) const;

    std::vector<unsigned char> decrypt(
        const std::vector<unsigned char>& receiverPrivateKey,
        const EciesCiphertext& ct,
        const std::vector<unsigned char>& aad = {}
    ) const;

private:
    int curveNid_;
    EccKeyGenerator eccKeyGen_;

    std::vector<unsigned char> receiverPubUncompressed_;

    bool hasStaticSender_ = false;
    std::vector<unsigned char> senderPrivScalar_;
    std::vector<unsigned char> senderPubUncompressed_;

    // Used when hasStaticSender_ == false (ephemeral sender), or for debugging/logging
    mutable std::vector<unsigned char> lastSenderPubUncompressed_;

    // ---- OpenSSL helpers ----
    [[noreturn]] void throwOpenSslError(const char* msg) const;

    // Key construction:
    // - Public key: parse SEC1 uncompressed octets using EC_POINT_oct2point
    // - Private key: build EC_KEY from scalar and compute public point (priv*G)
    void buildPublicKeyFromOctets(const std::vector<unsigned char>& pubOctetsUncompressed, void** outPkey) const;
    void buildKeypairFromPrivateScalar(const std::vector<unsigned char>& privScalar, void** outPkey) const;

    static std::vector<unsigned char> derivePublicFromPrivate(
        int curveNid,
        const std::vector<unsigned char>& privScalar
    );

    std::vector<unsigned char> ecdhDerive(void* myKey, void* peerKey) const;

    static std::vector<unsigned char> hkdfSha256(
        const std::vector<unsigned char>& ikm,
        const std::vector<unsigned char>& salt,
        const std::vector<unsigned char>& info,
        size_t outLen
    );

    static void aes256gcmEncrypt(
        const std::vector<unsigned char>& key,
        const std::vector<unsigned char>& nonce,
        const std::vector<unsigned char>& plaintext,
        const std::vector<unsigned char>& aad,
        std::vector<unsigned char>& outCiphertext,
        std::vector<unsigned char>& outTag
    );

    static bool aes256gcmDecrypt(
        const std::vector<unsigned char>& key,
        const std::vector<unsigned char>& nonce,
        const std::vector<unsigned char>& ciphertext,
        const std::vector<unsigned char>& aad,
        const std::vector<unsigned char>& tag,
        std::vector<unsigned char>& outPlaintext
    );
};
