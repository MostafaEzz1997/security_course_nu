#pragma once
/**
 * @file EciesCipher.hpp
 * @brief ECIES-style encryption using ECDH + HKDF-SHA256 + AES-256-GCM (OpenSSL 3 EVP).
 *
 * This is an "ECIES-like" construction:
 *  - Key agreement: ECDH
 *  - Key derivation: HKDF-SHA256
 *  - Authenticated encryption: AES-256-GCM
 *
 * Terminology:
 *  - "Ephemeral sender key": per-message ECDH keypair used to derive the shared secret.
 *  - "Sender identity key": optional long-term sender public key included for identification.
 *
 * @note Including a sender identity public key does NOT provide authenticity by itself.
 *       To authenticate the sender, add a signature (e.g., ECDSA) over the ciphertext.
 */

#include <vector>
#include <string>

#include <openssl/obj_mac.h>

#include "EccKeyGenerator.hpp"

/**
 * @brief Ciphertext package produced by @ref EciesCipher::encrypt().
 *
 * The receiver needs:
 *  - its private key (scalar)
 *  - @ref ephPublicKeyUncompressed (sender ephemeral public key)
 *  - nonce/ciphertext/tag
 *  - and the same AAD (if any)
 */
struct EciesCiphertext {
    /**
     * @brief Sender ephemeral public key in SEC1 uncompressed form (0x04 || X || Y).
     *
     * This key MUST be used for ECDH on the receiver side.
     */
    std::vector<unsigned char> ephPublicKeyUncompressed;

    /**
     * @brief Optional sender identity public key (SEC1 uncompressed).
     *
     * This is NOT used for ECDH key agreement. It may be used for metadata
     * or future signature verification.
     */
    std::vector<unsigned char> senderPublicKeyUncompressed;

    /** @brief AES-GCM nonce/IV (12 bytes recommended/used). */
    std::vector<unsigned char> nonce;

    /** @brief AES-GCM ciphertext (same length as plaintext). */
    std::vector<unsigned char> ciphertext;

    /** @brief AES-GCM authentication tag (16 bytes). */
    std::vector<unsigned char> tag;
};

/**
 * @brief ECIES-style cipher implementation.
 *
 * Two construction modes are supported:
 *  1) With static sender identity keypair (private + public), and a mandatory receiver public key.
 *  2) Without sender identity, and a mandatory receiver public key.
 *
 * Regardless of constructor, encryption ALWAYS uses a fresh ephemeral ECDH keypair
 * per call to @ref encrypt(). The ephemeral public key is carried in the ciphertext.
 */
class EciesCipher {
public:
    /**
     * @brief Construct with a static sender identity and a mandatory receiver public key.
     *
     * @param senderPrivateKey Sender private scalar (big-endian).
     * @param senderPublicKeyUncompressed Sender public key (SEC1 uncompressed).
     * @param receiverPublicKeyUncompressed Receiver public key (SEC1 uncompressed).
     * @param curveNid OpenSSL curve NID (default: P-256).
     *
     * @throws std::runtime_error if key formats are invalid or sender private/public mismatch.
     */
    EciesCipher(
        const std::vector<unsigned char>& senderPrivateKey,
        const std::vector<unsigned char>& senderPublicKeyUncompressed,
        const std::vector<unsigned char>& receiverPublicKeyUncompressed,
        int curveNid = NID_X9_62_prime256v1
    );

    /**
     * @brief Construct without sender identity, with a mandatory receiver public key.
     *
     * @param receiverPublicKeyUncompressed Receiver public key (SEC1 uncompressed).
     * @param curveNid OpenSSL curve NID (default: P-256).
     *
     * @throws std::runtime_error if receiver public key format is invalid.
     */
    explicit EciesCipher(
        const std::vector<unsigned char>& receiverPublicKeyUncompressed,
        int curveNid = NID_X9_62_prime256v1
    );

    /**
     * @brief Update the receiver public key stored in the object.
     *
     * Useful if you want to reuse the same cipher object for multiple receivers.
     *
     * @param receiverPublicKeyUncompressed Receiver public key (SEC1 uncompressed).
     * @throws std::runtime_error if the key format is invalid.
     */
    void setReceiverPublicKeyUncompressed(const std::vector<unsigned char>& receiverPublicKeyUncompressed);

    /**
     * @brief Get the currently configured receiver public key.
     * @return Reference to internal key bytes.
     */
    const std::vector<unsigned char>& getReceiverPublicKeyUncompressed() const noexcept;

    /**
     * @brief Get the sender identity public key if configured.
     *
     * - If constructed with a static sender identity, returns that public key.
     * - Otherwise, returns an empty vector (no identity configured).
     *
     * @return Sender identity public key bytes (SEC1 uncompressed) or empty.
     */
    std::vector<unsigned char> getSenderPublicKeyUncompressed() const;

    /**
     * @brief Encrypt plaintext to an ECIES ciphertext package.
     *
     * Steps (high-level):
     *  - Generate ephemeral sender keypair (ECDH).
     *  - Compute ECDH shared secret with receiver public key.
     *  - Derive AES-256 key with HKDF-SHA256 using context binding.
     *  - Encrypt plaintext with AES-256-GCM using optional AAD.
     *
     * @param plaintext Bytes to encrypt.
     * @param aad Additional Authenticated Data (authenticated, not encrypted).
     * @return Ciphertext package.
     * @throws std::runtime_error on OpenSSL failures.
     */
    EciesCiphertext encrypt(
        const std::vector<unsigned char>& plaintext,
        const std::vector<unsigned char>& aad = {}
    ) const;

    /**
     * @brief Decrypt and authenticate an ECIES ciphertext package.
     *
     * @param receiverPrivateKey Receiver private scalar (big-endian).
     * @param ct Ciphertext package from @ref encrypt().
     * @param aad The same AAD used in encryption (must match exactly).
     * @return Decrypted plaintext.
     * @throws std::runtime_error if authentication fails or on OpenSSL errors.
     */
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

    // Present for debugging/logging and for compatibility with the existing getter behavior.
    // This member is mutable because encrypt() is logically const but updates "last used" state.
    mutable std::vector<unsigned char> lastSenderPubUncompressed_;

    // ---- Error handling ----
    [[noreturn]] void throwOpenSslError(const char* msg) const;

    // ---- Key construction helpers (OpenSSL EVP_PKEY) ----
    void buildPublicKeyFromOctets(const std::vector<unsigned char>& pubOctetsUncompressed, void** outPkey) const;
    void buildKeypairFromPrivateScalar(const std::vector<unsigned char>& privScalar, void** outPkey) const;

    static std::vector<unsigned char> derivePublicFromPrivate(int curveNid, const std::vector<unsigned char>& privScalar);

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
