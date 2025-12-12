#include "EciesCipher.hpp" // Include the public API (class/struct declarations) for this .cpp

#include <stdexcept>       // std::runtime_error for throwing exceptions on failures
#include <memory>          // std::unique_ptr for RAII management of OpenSSL pointers
#include <cstring>         // std::strlen for building HKDF "info" buffer

#include <openssl/err.h>         // ERR_get_error / ERR_error_string_n for OpenSSL error strings
#include <openssl/rand.h>        // RAND_bytes for secure random nonce generation
#include <openssl/evp.h>         // EVP_* high-level crypto APIs (PKEY, CIPHER, derive, etc.)
#include <openssl/kdf.h>         // EVP_KDF / EVP_KDF_CTX for HKDF in OpenSSL 3
#include <openssl/core_names.h>  // OSSL_KDF_PARAM_* names (digest/key/salt/info)
#include <openssl/crypto.h>      // OPENSSL_cleanse for securely wiping secrets

#include <openssl/ec.h>      // EC_KEY, EC_POINT, EC_GROUP low-level elliptic curve helpers
#include <openssl/bn.h>      // BIGNUM helpers (BN_bin2bn) for private scalars
#include <openssl/objects.h> // OBJ_nid2sn for curve name string (used in HKDF info)

namespace { // Anonymous namespace = file-private helpers (not exported outside this translation unit)

// ---- RAII deleters so std::unique_ptr can free OpenSSL types automatically ----

// Custom deleter for EVP_PKEY*
struct EVP_PKEY_Deleter {
    void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); } // free EVP_PKEY
};

// Custom deleter for EVP_PKEY_CTX*
struct EVP_PKEY_CTX_Deleter {
    void operator()(EVP_PKEY_CTX* p) const noexcept { EVP_PKEY_CTX_free(p); } // free EVP_PKEY_CTX
};

// Custom deleter for EVP_CIPHER_CTX*
struct EVP_CIPHER_CTX_Deleter {
    void operator()(EVP_CIPHER_CTX* p) const noexcept { EVP_CIPHER_CTX_free(p); } // free cipher ctx
};

// Custom deleter for EVP_KDF*
struct EVP_KDF_Deleter {
    void operator()(EVP_KDF* k) const noexcept { EVP_KDF_free(k); } // free KDF object
};

// Custom deleter for EVP_KDF_CTX*
struct EVP_KDF_CTX_Deleter {
    void operator()(EVP_KDF_CTX* c) const noexcept { EVP_KDF_CTX_free(c); } // free KDF context
};

// Custom deleter for EC_KEY*
struct EC_KEY_Deleter {
    void operator()(EC_KEY* k) const noexcept { EC_KEY_free(k); } // free EC_KEY
};

// Custom deleter for EC_POINT*
struct EC_POINT_Deleter {
    void operator()(EC_POINT* p) const noexcept { EC_POINT_free(p); } // free EC_POINT
};

// Custom deleter for BIGNUM*
struct BN_Deleter {
    void operator()(BIGNUM* b) const noexcept { BN_free(b); } // free BIGNUM
};

// Validate SEC1 uncompressed public key form: 0x04 || X || Y.
// - First byte 0x04 indicates uncompressed EC point encoding (SEC1 standard).
// - Remaining bytes must be even length so it splits into X and Y coordinates.
static void require_uncompressed_sec1(const std::vector<unsigned char>& pub) {
    if (pub.size() < 1 || pub[0] != 0x04) // must exist and start with 0x04
        throw std::runtime_error("Invalid SEC1 uncompressed public key (expected 0x04||X||Y)");
    const size_t coordLen = (pub.size() - 1) / 2; // coordinate length in bytes
    if (pub.size() != 1 + 2 * coordLen)           // must be 1 + 2*coordLen exactly
        throw std::runtime_error("Invalid SEC1 uncompressed public key length");
}
} // namespace

// ---------------- Error handling ----------------

// Collect all pending OpenSSL errors and throw them as a single std::runtime_error.
// [[noreturn]] tells the compiler this function never returns (it always throws).
[[noreturn]] void EciesCipher::throwOpenSslError(const char* msg) const {
    unsigned long err = 0; // OpenSSL error code
    std::string all;       // concatenated error messages

    // Pull all errors from OpenSSL's thread-local error queue.
    while ((err = ERR_get_error()) != 0) {
        char buf[256];                         // buffer for error string
        ERR_error_string_n(err, buf, sizeof(buf)); // convert error code to readable text
        if (!all.empty()) all += " | ";        // separator if multiple errors exist
        all += buf;                            // append this error message
    }

    if (all.empty()) all = "(no OpenSSL error details)"; // fallback if queue is empty
    throw std::runtime_error(std::string(msg) + ": " + all); // throw combined message
}

// ---------------- Constructors ----------------

// Constructor #1: "static sender identity" + receiver pubkey (mandatory) + optional curveNid.
// - senderPrivateKey: sender's private scalar (d)
// - senderPublicKeyUncompressed: sender's pub key (Q = d*G) in SEC1 uncompressed form
// - receiverPublicKeyUncompressed: receiver's pub key in SEC1 uncompressed form
// - curveNid: OpenSSL curve identifier (default set in header)
EciesCipher::EciesCipher(
    const std::vector<unsigned char>& senderPrivateKey,
    const std::vector<unsigned char>& senderPublicKeyUncompressed,
    const std::vector<unsigned char>& receiverPublicKeyUncompressed,
    int curveNid)
    : curveNid_(curveNid)                          // store curve id
    , eccKeyGen_(curveNid)                         // init key generator for this curve
    , receiverPubUncompressed_(receiverPublicKeyUncompressed) // store receiver pubkey
    , hasStaticSender_(true)                       // this instance uses static sender keys
    , senderPrivScalar_(senderPrivateKey)          // store sender private scalar bytes
    , senderPubUncompressed_(senderPublicKeyUncompressed) // store sender pubkey bytes
{
    require_uncompressed_sec1(receiverPubUncompressed_); // validate receiver pub format
    require_uncompressed_sec1(senderPubUncompressed_);   // validate sender pub format
    if (senderPrivScalar_.empty())                       // private key must not be empty
        throw std::runtime_error("Sender private key is empty");

    // Validate that senderPrivScalar_ matches senderPubUncompressed_.
    // If they don't match, you would encrypt using a private key that does not correspond
    // to the public key you're claiming, which breaks key agreement expectations.
    const auto derived = derivePublicFromPrivate(curveNid_, senderPrivScalar_); // compute Q from d
    if (derived != senderPubUncompressed_) { // compare derived Q vs provided Q
        throw std::runtime_error("Sender private key does not match provided sender public key");
    }
}

// Constructor #2: ephemeral sender (generated per encrypt call) + receiver pubkey (mandatory) + optional curveNid.
EciesCipher::EciesCipher(
    const std::vector<unsigned char>& receiverPublicKeyUncompressed,
    int curveNid)
    : curveNid_(curveNid)                          // store curve id
    , eccKeyGen_(curveNid)                         // init key generator for this curve
    , receiverPubUncompressed_(receiverPublicKeyUncompressed) // store receiver pubkey
    , hasStaticSender_(false)                      // no static sender; will generate ephemeral sender key each time
{
    require_uncompressed_sec1(receiverPubUncompressed_); // validate receiver pub format
}

// Setter: update the stored receiver public key after construction.
// Useful if you want to reuse one EciesCipher instance for different receivers.
void EciesCipher::setReceiverPublicKeyUncompressed(const std::vector<unsigned char>& receiverPublicKeyUncompressed) {
    require_uncompressed_sec1(receiverPublicKeyUncompressed); // validate input format
    receiverPubUncompressed_ = receiverPublicKeyUncompressed; // store it
}

// Getter: return the stored receiver public key (reference, no copy).
const std::vector<unsigned char>& EciesCipher::getReceiverPublicKeyUncompressed() const noexcept {
    return receiverPubUncompressed_;
}

// Getter: return sender public key.
// - if static sender: return the configured sender pub key
// - else: return the last sender pub key used by encrypt() (ephemeral)
std::vector<unsigned char> EciesCipher::getSenderPublicKeyUncompressed() const {
    if (hasStaticSender_) return senderPubUncompressed_; // static sender case
    return lastSenderPubUncompressed_;                   // ephemeral case (last used)
}

// ---------------- Key construction helpers ----------------

// Build an EVP_PKEY public key from SEC1 uncompressed octets.
// Output is returned through outPkey (void** to avoid exposing OpenSSL types in header).
void EciesCipher::buildPublicKeyFromOctets(
    const std::vector<unsigned char>& pubOctetsUncompressed,
    void** outPkey) const
{
    if (!outPkey) return;                    // nothing to write to
    require_uncompressed_sec1(pubOctetsUncompressed); // validate format

    // Create a new EC_KEY object for the chosen curve
    std::unique_ptr<EC_KEY, EC_KEY_Deleter> ec(EC_KEY_new_by_curve_name(curveNid_));
    if (!ec) throwOpenSslError("EC_KEY_new_by_curve_name"); // fail if allocation/curve creation fails

    // Get the EC_GROUP (curve parameters) from the EC_KEY
    const EC_GROUP* group = EC_KEY_get0_group(ec.get());
    if (!group) throw std::runtime_error("EC_KEY group is null"); // should not happen if EC_KEY is valid

    // Create a new EC_POINT to store the public point
    std::unique_ptr<EC_POINT, EC_POINT_Deleter> pt(EC_POINT_new(group));
    if (!pt) throwOpenSslError("EC_POINT_new");

    // Parse SEC1 octets (0x04||X||Y) into an EC_POINT on this curve
    if (EC_POINT_oct2point(group, pt.get(),
                           pubOctetsUncompressed.data(),
                           pubOctetsUncompressed.size(),
                           nullptr) != 1) {
        throwOpenSslError("EC_POINT_oct2point");
    }

    // Set that point as the public key on EC_KEY
    if (EC_KEY_set_public_key(ec.get(), pt.get()) != 1) {
        throwOpenSslError("EC_KEY_set_public_key");
    }

    // Wrap EC_KEY inside an EVP_PKEY (the modern generic key container used by EVP APIs)
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) throwOpenSslError("EVP_PKEY_new");

    // EVP_PKEY_assign_EC_KEY transfers ownership of the EC_KEY to EVP_PKEY.
    // ec.release() hands over the raw pointer without freeing it.
    if (EVP_PKEY_assign_EC_KEY(pkey, ec.release()) != 1) {
        EVP_PKEY_free(pkey);                       // free partial object on failure
        throwOpenSslError("EVP_PKEY_assign_EC_KEY(public)");
    }

    *outPkey = pkey; // return ownership to caller (caller should free with EVP_PKEY_free)
}

// Build an EVP_PKEY keypair from a private scalar only.
// It computes the public point Q = d*G and sets both priv+pub on EC_KEY.
void EciesCipher::buildKeypairFromPrivateScalar(
    const std::vector<unsigned char>& privScalar,
    void** outPkey) const
{
    if (!outPkey) return;                         // no output pointer
    if (privScalar.empty()) throw std::runtime_error("Private scalar is empty"); // must have data

    // Create EC_KEY for curve
    std::unique_ptr<EC_KEY, EC_KEY_Deleter> ec(EC_KEY_new_by_curve_name(curveNid_));
    if (!ec) throwOpenSslError("EC_KEY_new_by_curve_name");

    // Get group params for curve
    const EC_GROUP* group = EC_KEY_get0_group(ec.get());
    if (!group) throw std::runtime_error("EC_KEY group is null");

    // Convert raw bytes into BIGNUM private scalar d
    std::unique_ptr<BIGNUM, BN_Deleter> d(BN_bin2bn(privScalar.data(), (int)privScalar.size(), nullptr));
    if (!d) throwOpenSslError("BN_bin2bn");

    // Set private key d on EC_KEY
    if (EC_KEY_set_private_key(ec.get(), d.get()) != 1) {
        throwOpenSslError("EC_KEY_set_private_key");
    }

    // Compute public key point Q = d * G (G is the curve generator)
    std::unique_ptr<EC_POINT, EC_POINT_Deleter> Q(EC_POINT_new(group));
    if (!Q) throwOpenSslError("EC_POINT_new");

    if (EC_POINT_mul(group, Q.get(), d.get(), nullptr, nullptr, nullptr) != 1) {
        throwOpenSslError("EC_POINT_mul");
    }

    // Store computed public key point Q in EC_KEY
    if (EC_KEY_set_public_key(ec.get(), Q.get()) != 1) {
        throwOpenSslError("EC_KEY_set_public_key(keypair)");
    }

    // Validate EC_KEY consistency (priv/pub on curve, etc.)
    if (EC_KEY_check_key(ec.get()) != 1) {
        throwOpenSslError("EC_KEY_check_key");
    }

    // Wrap EC_KEY in EVP_PKEY
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) throwOpenSslError("EVP_PKEY_new");

    // Transfer ownership of EC_KEY to EVP_PKEY
    if (EVP_PKEY_assign_EC_KEY(pkey, ec.release()) != 1) {
        EVP_PKEY_free(pkey);
        throwOpenSslError("EVP_PKEY_assign_EC_KEY(keypair)");
    }

    *outPkey = pkey; // output EVP_PKEY*
}

// Static helper: derive SEC1 uncompressed public key from a private scalar.
// Used to validate (senderPriv matches senderPub) in constructor #1.
std::vector<unsigned char> EciesCipher::derivePublicFromPrivate(int curveNid, const std::vector<unsigned char>& privScalar)
{
    std::unique_ptr<EC_KEY, EC_KEY_Deleter> ec(EC_KEY_new_by_curve_name(curveNid)); // create key for curve
    if (!ec) throw std::runtime_error("EC_KEY_new_by_curve_name failed");

    const EC_GROUP* group = EC_KEY_get0_group(ec.get()); // get curve group
    if (!group) throw std::runtime_error("EC_KEY group is null");

    std::unique_ptr<BIGNUM, BN_Deleter> d(BN_bin2bn(privScalar.data(), (int)privScalar.size(), nullptr)); // bytes->BIGNUM
    if (!d) throw std::runtime_error("BN_bin2bn failed");

    std::unique_ptr<EC_POINT, EC_POINT_Deleter> Q(EC_POINT_new(group)); // allocate point
    if (!Q) throw std::runtime_error("EC_POINT_new failed");

    if (EC_POINT_mul(group, Q.get(), d.get(), nullptr, nullptr, nullptr) != 1) // Q = d*G
        throw std::runtime_error("EC_POINT_mul failed");

    // First call to determine required output length for uncompressed point encoding
    size_t len = EC_POINT_point2oct(group, Q.get(), POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
    if (len == 0) throw std::runtime_error("EC_POINT_point2oct(size) failed");

    std::vector<unsigned char> out(len); // allocate output buffer
    // Second call actually writes the bytes (0x04||X||Y)
    if (EC_POINT_point2oct(group, Q.get(), POINT_CONVERSION_UNCOMPRESSED, out.data(), out.size(), nullptr) != len)
        throw std::runtime_error("EC_POINT_point2oct failed");

    return out; // return the derived public key bytes
}

// ---------------- ECDH ----------------

// Perform ECDH key agreement and return the shared secret bytes.
// myKey: EVP_PKEY containing private key
// peerKey: EVP_PKEY containing public key
std::vector<unsigned char> EciesCipher::ecdhDerive(void* myKey, void* peerKey) const {
    // Create a derivation context bound to "myKey"
    EVP_PKEY_CTX* raw = EVP_PKEY_CTX_new(static_cast<EVP_PKEY*>(myKey), nullptr);
    if (!raw) throwOpenSslError("EVP_PKEY_CTX_new");

    // Manage ctx with RAII
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> ctx(raw);

    // Initialize ECDH derivation
    if (EVP_PKEY_derive_init(ctx.get()) != 1) throwOpenSslError("EVP_PKEY_derive_init");

    // Set the peer public key used for ECDH
    if (EVP_PKEY_derive_set_peer(ctx.get(), static_cast<EVP_PKEY*>(peerKey)) != 1) throwOpenSslError("EVP_PKEY_derive_set_peer");

    // Ask OpenSSL how many bytes the shared secret will be
    size_t len = 0;
    if (EVP_PKEY_derive(ctx.get(), nullptr, &len) != 1) throwOpenSslError("EVP_PKEY_derive(size)");

    // Allocate buffer and perform the derivation
    std::vector<unsigned char> secret(len);
    if (EVP_PKEY_derive(ctx.get(), secret.data(), &len) != 1) throwOpenSslError("EVP_PKEY_derive");

    secret.resize(len); // trim to actual length in case OpenSSL wrote fewer bytes
    return secret;      // return shared secret (not yet a symmetric key)
}

// ---------------- HKDF ----------------

// Derive key material using HKDF-SHA256.
// ikm: input key material (here: ECDH shared secret)
// salt: HKDF salt (here: sender public key bytes)
// info: HKDF info (context binding label/curve/receiver pub)
// outLen: number of bytes to produce (32 for AES-256)
std::vector<unsigned char> EciesCipher::hkdfSha256(
    const std::vector<unsigned char>& ikm,
    const std::vector<unsigned char>& salt,
    const std::vector<unsigned char>& info,
    size_t outLen)
{
    // Fetch the HKDF implementation from OpenSSL
    EVP_KDF* raw = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!raw) throw std::runtime_error("EVP_KDF_fetch(HKDF) failed");
    std::unique_ptr<EVP_KDF, EVP_KDF_Deleter> kdf(raw); // RAII

    // Create a context for HKDF operations
    EVP_KDF_CTX* rawCtx = EVP_KDF_CTX_new(kdf.get());
    if (!rawCtx) throw std::runtime_error("EVP_KDF_CTX_new failed");
    std::unique_ptr<EVP_KDF_CTX, EVP_KDF_CTX_Deleter> kctx(rawCtx); // RAII

    // Describe the HKDF parameters:
    // - digest = SHA256
    // - key = IKM
    // - salt = salt
    // - info = info
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>("SHA256"), 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<unsigned char*>(ikm.data()), ikm.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<unsigned char*>(salt.data()), salt.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, const_cast<unsigned char*>(info.data()), info.size()),
        OSSL_PARAM_construct_end()
    };

    std::vector<unsigned char> out(outLen); // allocate output buffer
    size_t len = outLen;                    // requested output length
    if (EVP_KDF_derive(kctx.get(), out.data(), len, params) != 1)
        throw std::runtime_error("EVP_KDF_derive(HKDF) failed");

    return out; // HKDF output = symmetric key bytes
}

// ---------------- AES-256-GCM ----------------

// Encrypt plaintext using AES-256-GCM.
// key: 32 bytes
// nonce: 12 bytes
// plaintext: data to encrypt
// aad: Additional Authenticated Data (authenticated but not encrypted)
// outCiphertext/outTag: outputs
void EciesCipher::aes256gcmEncrypt(
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& nonce,
    const std::vector<unsigned char>& plaintext,
    const std::vector<unsigned char>& aad,
    std::vector<unsigned char>& outCiphertext,
    std::vector<unsigned char>& outTag)
{
    if (key.size() != 32) throw std::runtime_error("AES-256 key must be 32 bytes"); // sanity check
    if (nonce.size() != 12) throw std::runtime_error("GCM nonce must be 12 bytes"); // standard GCM IV length

    EVP_CIPHER_CTX* raw = EVP_CIPHER_CTX_new(); // allocate cipher context
    if (!raw) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter> ctx(raw); // RAII

    // Initialize context for AES-256-GCM
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("EVP_EncryptInit_ex failed");

    // Set IV length (nonce length)
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr) != 1)
        throw std::runtime_error("EVP_CTRL_GCM_SET_IVLEN failed");

    // Provide the key and nonce to the context
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1)
        throw std::runtime_error("EVP_EncryptInit_ex(key/iv) failed");

    int len = 0; // OpenSSL uses int for byte counts in EVP_EncryptUpdate
    if (!aad.empty()) {
        // Feed AAD: produces no output, but affects authentication tag
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), (int)aad.size()) != 1)
            throw std::runtime_error("EVP_EncryptUpdate(AAD) failed");
    }

    outCiphertext.resize(plaintext.size()); // ciphertext length same as plaintext in GCM
    int outLen = 0;
    if (!plaintext.empty()) {
        // Encrypt plaintext
        if (EVP_EncryptUpdate(ctx.get(), outCiphertext.data(), &outLen, plaintext.data(), (int)plaintext.size()) != 1)
            throw std::runtime_error("EVP_EncryptUpdate(PT) failed");
    }

    int finLen = 0;
    // Finalize encryption (GCM typically adds no extra bytes, but call is required)
    if (EVP_EncryptFinal_ex(ctx.get(), outCiphertext.data() + outLen, &finLen) != 1)
        throw std::runtime_error("EVP_EncryptFinal_ex failed");

    // Resize to actual output length
    outCiphertext.resize((size_t)outLen + (size_t)finLen);

    outTag.resize(16); // GCM tag commonly 16 bytes
    // Read the authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, (int)outTag.size(), outTag.data()) != 1)
        throw std::runtime_error("EVP_CTRL_GCM_GET_TAG failed");
}

// Decrypt ciphertext using AES-256-GCM.
// Returns true on success (tag verified), false on authentication failure.
bool EciesCipher::aes256gcmDecrypt(
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& nonce,
    const std::vector<unsigned char>& ciphertext,
    const std::vector<unsigned char>& aad,
    const std::vector<unsigned char>& tag,
    std::vector<unsigned char>& outPlaintext)
{
    if (key.size() != 32) throw std::runtime_error("AES-256 key must be 32 bytes"); // sanity
    if (nonce.size() != 12) throw std::runtime_error("GCM nonce must be 12 bytes"); // sanity

    EVP_CIPHER_CTX* raw = EVP_CIPHER_CTX_new(); // allocate cipher ctx
    if (!raw) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter> ctx(raw); // RAII

    // Initialize context for AES-256-GCM
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("EVP_DecryptInit_ex failed");

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr) != 1)
        throw std::runtime_error("EVP_CTRL_GCM_SET_IVLEN failed");

    // Provide key and IV
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1)
        throw std::runtime_error("EVP_DecryptInit_ex(key/iv) failed");

    int len = 0;
    if (!aad.empty()) {
        // Feed AAD (must be identical to encrypt's AAD)
        if (EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(), (int)aad.size()) != 1)
            throw std::runtime_error("EVP_DecryptUpdate(AAD) failed");
    }

    outPlaintext.resize(ciphertext.size()); // allocate output buffer
    int outLen = 0;
    if (!ciphertext.empty()) {
        // Decrypt ciphertext (still not authenticated until Final)
        if (EVP_DecryptUpdate(ctx.get(), outPlaintext.data(), &outLen, ciphertext.data(), (int)ciphertext.size()) != 1)
            throw std::runtime_error("EVP_DecryptUpdate(CT) failed");
    }

    // Provide expected tag before finalizing
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, (int)tag.size(),
                            const_cast<unsigned char*>(tag.data())) != 1) {
        throw std::runtime_error("EVP_CTRL_GCM_SET_TAG failed");
    }

    int finLen = 0;
    // Finalize: verifies the tag. If tag mismatch => returns 0 (or -1).
    const int ok = EVP_DecryptFinal_ex(ctx.get(), outPlaintext.data() + outLen, &finLen);
    if (ok != 1) {
        outPlaintext.clear(); // wipe output on auth failure
        return false;         // tell caller authentication failed
    }

    outPlaintext.resize((size_t)outLen + (size_t)finLen); // resize to real plaintext length
    return true; // success
}

// ---------------- ECIES API ----------------

// Encrypt plaintext to an ECIES-style ciphertext package.
// Uses:
// - receiverPubUncompressed_ as the receiver public key
// - sender key either static (constructor #1) or ephemeral (constructor #2)
// - ECDH shared secret -> HKDF -> AES-256-GCM
EciesCiphertext EciesCipher::encrypt(
    const std::vector<unsigned char>& plaintext,
    const std::vector<unsigned char>& aad) const
{
    // ---- Build receiver public key (EVP_PKEY) from stored SEC1 bytes ----
    EVP_PKEY* rawReceiverPub = nullptr; // will hold raw EVP_PKEY*
    buildPublicKeyFromOctets(receiverPubUncompressed_, (void**)&rawReceiverPub); // parse SEC1 bytes -> EC_KEY -> EVP_PKEY
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> receiverPub(rawReceiverPub); // RAII wrapper

    // ---- Prepare sender key ----
    std::vector<unsigned char> senderPubUncompressed; // the sender public key that will be put in ciphertext
    EVP_PKEY* rawSenderPriv = nullptr;                // sender private key (EVP_PKEY*) used for ECDH

    if (hasStaticSender_) { // If we were constructed with a static sender keypair
        senderPubUncompressed = senderPubUncompressed_; // use the configured sender pub
        buildKeypairFromPrivateScalar(senderPrivScalar_, (void**)&rawSenderPriv); // rebuild sender keypair from private scalar
    } else { // Otherwise generate a fresh ephemeral sender keypair for this encryption
        EccKeyPair eph = eccKeyGen_.generate();         // generate ephemeral keypair
        senderPubUncompressed = eph.publicKeyUncompressed; // record ephemeral pub
        buildKeypairFromPrivateScalar(eph.privateKey, (void**)&rawSenderPriv); // build EVP keypair from eph priv
        OPENSSL_cleanse(eph.privateKey.data(), eph.privateKey.size()); // wipe ephemeral private key bytes from stack/heap
    }

    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> senderPriv(rawSenderPriv); // RAII wrapper for sender private EVP key
    lastSenderPubUncompressed_ = senderPubUncompressed; // remember last sender pub for getter()

    // ---- ECDH: compute shared secret Z = ECDH(senderPriv, receiverPub) ----
    std::vector<unsigned char> secret = ecdhDerive(senderPriv.get(), receiverPub.get()); // raw ECDH shared secret bytes

    // ---- HKDF: derive AES key from secret ----
    // salt = sender public key bytes (binds derived key to sender key)
    std::vector<unsigned char> salt = senderPubUncompressed;

    // info = label || curveName || 0x00 || receiverPub (binds derived key to context, curve, receiver)
    std::vector<unsigned char> info;
    {
        const char* label = "ECIESv1-AES256GCM";            // domain separation label
        info.insert(info.end(), label, label + std::strlen(label)); // append label bytes
        const char* sn = OBJ_nid2sn(curveNid_);             // short name of curve (e.g., "prime256v1")
        if (sn) info.insert(info.end(), sn, sn + std::strlen(sn)); // append curve name
        info.push_back(0x00);                               // separator byte (avoid ambiguity)
        info.insert(info.end(), receiverPubUncompressed_.begin(), receiverPubUncompressed_.end()); // append receiver pub
    }

    std::vector<unsigned char> aesKey = hkdfSha256(secret, salt, info, 32); // derive 32-byte AES-256 key
    OPENSSL_cleanse(secret.data(), secret.size()); // wipe raw ECDH secret from memory

    // ---- Prepare output ciphertext structure ----
    EciesCiphertext out;                            // output package
    out.ephPublicKeyUncompressed = senderPubUncompressed; // store sender pub so receiver can derive the same secret
    out.nonce.resize(12);                           // allocate 12-byte GCM nonce
    if (RAND_bytes(out.nonce.data(), (int)out.nonce.size()) != 1) // fill nonce with cryptographically secure randomness
        throwOpenSslError("RAND_bytes failed");     // throw with OpenSSL error details on failure

    // ---- Encrypt using AES-256-GCM ----
    aes256gcmEncrypt(aesKey, out.nonce, plaintext, aad, out.ciphertext, out.tag); // fill ciphertext and tag

    OPENSSL_cleanse(aesKey.data(), aesKey.size()); // wipe AES key bytes from memory
    return out;                                    // return ciphertext package
}

// Decrypt ECIES ciphertext package back to plaintext.
// Requires receiverPrivateKey (private scalar of receiver).
// Uses sender public key from ciphertext (ct.ephPublicKeyUncompressed) for ECDH.
std::vector<unsigned char> EciesCipher::decrypt(
    const std::vector<unsigned char>& receiverPrivateKey,
    const EciesCiphertext& ct,
    const std::vector<unsigned char>& aad) const
{
    // ---- Build receiver keypair from receiver private scalar only ----
    EVP_PKEY* rawReceiverPriv = nullptr; // raw EVP receiver private key
    buildKeypairFromPrivateScalar(receiverPrivateKey, (void**)&rawReceiverPriv); // compute receiver pub internally from priv
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> receiverPriv(rawReceiverPriv); // RAII

    // ---- Build sender public key from ciphertext ----
    EVP_PKEY* rawSenderPub = nullptr; // raw EVP sender pub key
    buildPublicKeyFromOctets(ct.ephPublicKeyUncompressed, (void**)&rawSenderPub); // parse sender pub bytes -> EVP_PKEY
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> senderPub(rawSenderPub); // RAII

    // ---- ECDH: compute shared secret Z = ECDH(receiverPriv, senderPub) ----
    std::vector<unsigned char> secret = ecdhDerive(receiverPriv.get(), senderPub.get()); // same secret as encrypt side

    // ---- HKDF: derive AES key (must match encrypt exactly) ----
    std::vector<unsigned char> salt = ct.ephPublicKeyUncompressed; // same salt = sender pub from ciphertext
    std::vector<unsigned char> info;
    {
        const char* label = "ECIESv1-AES256GCM"; // same label
        info.insert(info.end(), label, label + std::strlen(label)); // append label
        const char* sn = OBJ_nid2sn(curveNid_); // same curve name
        if (sn) info.insert(info.end(), sn, sn + std::strlen(sn)); // append curve
        info.push_back(0x00); // same separator
        info.insert(info.end(), receiverPubUncompressed_.begin(), receiverPubUncompressed_.end()); // same receiver pub binding
    }

    std::vector<unsigned char> aesKey = hkdfSha256(secret, salt, info, 32); // derive same AES-256 key
    OPENSSL_cleanse(secret.data(), secret.size()); // wipe ECDH secret

    // ---- Decrypt and authenticate ----
    std::vector<unsigned char> plaintext; // output plaintext
    if (!aes256gcmDecrypt(aesKey, ct.nonce, ct.ciphertext, aad, ct.tag, plaintext)) {
        OPENSSL_cleanse(aesKey.data(), aesKey.size()); // wipe AES key before throwing
        throw std::runtime_error("ECIES decrypt failed: authentication error"); // tag mismatch -> wrong key/nonce/aad/ciphertext/tag
    }

    OPENSSL_cleanse(aesKey.data(), aesKey.size()); // wipe AES key
    return plaintext; // return decrypted plaintext
}
