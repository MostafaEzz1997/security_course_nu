#include "EciesCipher.hpp"

#include <stdexcept>
#include <memory>
#include <cstring>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/objects.h>

namespace {
struct EVP_PKEY_Deleter { void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); } };
struct EVP_PKEY_CTX_Deleter { void operator()(EVP_PKEY_CTX* p) const noexcept { EVP_PKEY_CTX_free(p); } };
struct EVP_CIPHER_CTX_Deleter { void operator()(EVP_CIPHER_CTX* p) const noexcept { EVP_CIPHER_CTX_free(p); } };
struct EVP_KDF_Deleter { void operator()(EVP_KDF* k) const noexcept { EVP_KDF_free(k); } };
struct EVP_KDF_CTX_Deleter { void operator()(EVP_KDF_CTX* c) const noexcept { EVP_KDF_CTX_free(c); } };

struct EC_KEY_Deleter { void operator()(EC_KEY* k) const noexcept { EC_KEY_free(k); } };
struct EC_POINT_Deleter { void operator()(EC_POINT* p) const noexcept { EC_POINT_free(p); } };
struct BN_Deleter { void operator()(BIGNUM* b) const noexcept { BN_free(b); } };

static void require_uncompressed_sec1(const std::vector<unsigned char>& pub) {
    if (pub.size() < 1 || pub[0] != 0x04)
        throw std::runtime_error("Invalid SEC1 uncompressed public key (expected 0x04||X||Y)");
    const size_t coordLen = (pub.size() - 1) / 2;
    if (pub.size() != 1 + 2 * coordLen)
        throw std::runtime_error("Invalid SEC1 uncompressed public key length");
}
} // namespace

// ---------------- Error handling ----------------
[[noreturn]] void EciesCipher::throwOpenSslError(const char* msg) const {
    unsigned long err = 0;
    std::string all;

    while ((err = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        if (!all.empty()) all += " | ";
        all += buf;
    }

    if (all.empty()) all = "(no OpenSSL error details)";
    throw std::runtime_error(std::string(msg) + ": " + all);
}

// ---------------- Constructors ----------------
EciesCipher::EciesCipher(
    const std::vector<unsigned char>& senderPrivateKey,
    const std::vector<unsigned char>& senderPublicKeyUncompressed,
    const std::vector<unsigned char>& receiverPublicKeyUncompressed,
    int curveNid)
    : curveNid_(curveNid)
    , eccKeyGen_(curveNid)
    , receiverPubUncompressed_(receiverPublicKeyUncompressed)
    , hasStaticSender_(true)
    , senderPrivScalar_(senderPrivateKey)
    , senderPubUncompressed_(senderPublicKeyUncompressed)
{
    require_uncompressed_sec1(receiverPubUncompressed_);
    require_uncompressed_sec1(senderPubUncompressed_);
    if (senderPrivScalar_.empty())
        throw std::runtime_error("Sender private key is empty");

    // Validate that senderPrivScalar_ matches senderPubUncompressed_.
    // If they don't match, ECDH will derive a different secret than expected.
    const auto derived = derivePublicFromPrivate(curveNid_, senderPrivScalar_);
    if (derived != senderPubUncompressed_) {
        throw std::runtime_error("Sender private key does not match provided sender public key");
    }
}

EciesCipher::EciesCipher(
    const std::vector<unsigned char>& receiverPublicKeyUncompressed,
    int curveNid)
    : curveNid_(curveNid)
    , eccKeyGen_(curveNid)
    , receiverPubUncompressed_(receiverPublicKeyUncompressed)
    , hasStaticSender_(false)
{
    require_uncompressed_sec1(receiverPubUncompressed_);
}

void EciesCipher::setReceiverPublicKeyUncompressed(const std::vector<unsigned char>& receiverPublicKeyUncompressed) {
    require_uncompressed_sec1(receiverPublicKeyUncompressed);
    receiverPubUncompressed_ = receiverPublicKeyUncompressed;
}

const std::vector<unsigned char>& EciesCipher::getReceiverPublicKeyUncompressed() const noexcept {
    return receiverPubUncompressed_;
}

std::vector<unsigned char> EciesCipher::getSenderPublicKeyUncompressed() const {
    if (hasStaticSender_) return senderPubUncompressed_;
    return lastSenderPubUncompressed_;
}

// ---------------- Key construction helpers ----------------
void EciesCipher::buildPublicKeyFromOctets(
    const std::vector<unsigned char>& pubOctetsUncompressed,
    void** outPkey) const
{
    if (!outPkey) return;
    require_uncompressed_sec1(pubOctetsUncompressed);

    std::unique_ptr<EC_KEY, EC_KEY_Deleter> ec(EC_KEY_new_by_curve_name(curveNid_));
    if (!ec) throwOpenSslError("EC_KEY_new_by_curve_name");

    const EC_GROUP* group = EC_KEY_get0_group(ec.get());
    if (!group) throw std::runtime_error("EC_KEY group is null");

    std::unique_ptr<EC_POINT, EC_POINT_Deleter> pt(EC_POINT_new(group));
    if (!pt) throwOpenSslError("EC_POINT_new");

    if (EC_POINT_oct2point(group, pt.get(),
                           pubOctetsUncompressed.data(),
                           pubOctetsUncompressed.size(),
                           nullptr) != 1) {
        throwOpenSslError("EC_POINT_oct2point");
    }

    if (EC_KEY_set_public_key(ec.get(), pt.get()) != 1) {
        throwOpenSslError("EC_KEY_set_public_key");
    }

    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) throwOpenSslError("EVP_PKEY_new");

    // EVP_PKEY_assign_EC_KEY takes ownership of ec
    if (EVP_PKEY_assign_EC_KEY(pkey, ec.release()) != 1) {
        EVP_PKEY_free(pkey);
        throwOpenSslError("EVP_PKEY_assign_EC_KEY(public)");
    }

    *outPkey = pkey;
}

void EciesCipher::buildKeypairFromPrivateScalar(
    const std::vector<unsigned char>& privScalar,
    void** outPkey) const
{
    if (!outPkey) return;
    if (privScalar.empty()) throw std::runtime_error("Private scalar is empty");

    std::unique_ptr<EC_KEY, EC_KEY_Deleter> ec(EC_KEY_new_by_curve_name(curveNid_));
    if (!ec) throwOpenSslError("EC_KEY_new_by_curve_name");

    const EC_GROUP* group = EC_KEY_get0_group(ec.get());
    if (!group) throw std::runtime_error("EC_KEY group is null");

    std::unique_ptr<BIGNUM, BN_Deleter> d(BN_bin2bn(privScalar.data(), (int)privScalar.size(), nullptr));
    if (!d) throwOpenSslError("BN_bin2bn");

    if (EC_KEY_set_private_key(ec.get(), d.get()) != 1) {
        throwOpenSslError("EC_KEY_set_private_key");
    }

    // Compute Q = d * G
    std::unique_ptr<EC_POINT, EC_POINT_Deleter> Q(EC_POINT_new(group));
    if (!Q) throwOpenSslError("EC_POINT_new");

    if (EC_POINT_mul(group, Q.get(), d.get(), nullptr, nullptr, nullptr) != 1) {
        throwOpenSslError("EC_POINT_mul");
    }

    if (EC_KEY_set_public_key(ec.get(), Q.get()) != 1) {
        throwOpenSslError("EC_KEY_set_public_key(keypair)");
    }

    if (EC_KEY_check_key(ec.get()) != 1) {
        throwOpenSslError("EC_KEY_check_key");
    }

    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) throwOpenSslError("EVP_PKEY_new");

    if (EVP_PKEY_assign_EC_KEY(pkey, ec.release()) != 1) {
        EVP_PKEY_free(pkey);
        throwOpenSslError("EVP_PKEY_assign_EC_KEY(keypair)");
    }

    *outPkey = pkey;
}

std::vector<unsigned char> EciesCipher::derivePublicFromPrivate(int curveNid, const std::vector<unsigned char>& privScalar)
{
    std::unique_ptr<EC_KEY, EC_KEY_Deleter> ec(EC_KEY_new_by_curve_name(curveNid));
    if (!ec) throw std::runtime_error("EC_KEY_new_by_curve_name failed");

    const EC_GROUP* group = EC_KEY_get0_group(ec.get());
    if (!group) throw std::runtime_error("EC_KEY group is null");

    std::unique_ptr<BIGNUM, BN_Deleter> d(BN_bin2bn(privScalar.data(), (int)privScalar.size(), nullptr));
    if (!d) throw std::runtime_error("BN_bin2bn failed");

    std::unique_ptr<EC_POINT, EC_POINT_Deleter> Q(EC_POINT_new(group));
    if (!Q) throw std::runtime_error("EC_POINT_new failed");

    if (EC_POINT_mul(group, Q.get(), d.get(), nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("EC_POINT_mul failed");

    // SEC1 uncompressed
    size_t len = EC_POINT_point2oct(group, Q.get(), POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
    if (len == 0) throw std::runtime_error("EC_POINT_point2oct(size) failed");

    std::vector<unsigned char> out(len);
    if (EC_POINT_point2oct(group, Q.get(), POINT_CONVERSION_UNCOMPRESSED, out.data(), out.size(), nullptr) != len)
        throw std::runtime_error("EC_POINT_point2oct failed");

    return out;
}

// ---------------- ECDH ----------------
std::vector<unsigned char> EciesCipher::ecdhDerive(void* myKey, void* peerKey) const {
    EVP_PKEY_CTX* raw = EVP_PKEY_CTX_new(static_cast<EVP_PKEY*>(myKey), nullptr);
    if (!raw) throwOpenSslError("EVP_PKEY_CTX_new");

    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> ctx(raw);

    if (EVP_PKEY_derive_init(ctx.get()) != 1) throwOpenSslError("EVP_PKEY_derive_init");
    if (EVP_PKEY_derive_set_peer(ctx.get(), static_cast<EVP_PKEY*>(peerKey)) != 1) throwOpenSslError("EVP_PKEY_derive_set_peer");

    size_t len = 0;
    if (EVP_PKEY_derive(ctx.get(), nullptr, &len) != 1) throwOpenSslError("EVP_PKEY_derive(size)");

    std::vector<unsigned char> secret(len);
    if (EVP_PKEY_derive(ctx.get(), secret.data(), &len) != 1) throwOpenSslError("EVP_PKEY_derive");
    secret.resize(len);
    return secret;
}

// ---------------- HKDF ----------------
std::vector<unsigned char> EciesCipher::hkdfSha256(
    const std::vector<unsigned char>& ikm,
    const std::vector<unsigned char>& salt,
    const std::vector<unsigned char>& info,
    size_t outLen)
{
    EVP_KDF* raw = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!raw) throw std::runtime_error("EVP_KDF_fetch(HKDF) failed");
    std::unique_ptr<EVP_KDF, EVP_KDF_Deleter> kdf(raw);

    EVP_KDF_CTX* rawCtx = EVP_KDF_CTX_new(kdf.get());
    if (!rawCtx) throw std::runtime_error("EVP_KDF_CTX_new failed");
    std::unique_ptr<EVP_KDF_CTX, EVP_KDF_CTX_Deleter> kctx(rawCtx);

    // Per OpenSSL, "digest" param name is OSSL_KDF_PARAM_DIGEST
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>("SHA256"), 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<unsigned char*>(ikm.data()), ikm.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<unsigned char*>(salt.data()), salt.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, const_cast<unsigned char*>(info.data()), info.size()),
        OSSL_PARAM_construct_end()
    };

    std::vector<unsigned char> out(outLen);
    size_t len = outLen;
    if (EVP_KDF_derive(kctx.get(), out.data(), len, params) != 1)
        throw std::runtime_error("EVP_KDF_derive(HKDF) failed");

    return out;
}

// ---------------- AES-256-GCM ----------------
void EciesCipher::aes256gcmEncrypt(
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& nonce,
    const std::vector<unsigned char>& plaintext,
    const std::vector<unsigned char>& aad,
    std::vector<unsigned char>& outCiphertext,
    std::vector<unsigned char>& outTag)
{
    if (key.size() != 32) throw std::runtime_error("AES-256 key must be 32 bytes");
    if (nonce.size() != 12) throw std::runtime_error("GCM nonce must be 12 bytes");

    EVP_CIPHER_CTX* raw = EVP_CIPHER_CTX_new();
    if (!raw) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter> ctx(raw);

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("EVP_EncryptInit_ex failed");

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr) != 1)
        throw std::runtime_error("EVP_CTRL_GCM_SET_IVLEN failed");

    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1)
        throw std::runtime_error("EVP_EncryptInit_ex(key/iv) failed");

    int len = 0;
    if (!aad.empty()) {
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), (int)aad.size()) != 1)
            throw std::runtime_error("EVP_EncryptUpdate(AAD) failed");
    }

    outCiphertext.resize(plaintext.size());
    int outLen = 0;
    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(ctx.get(), outCiphertext.data(), &outLen, plaintext.data(), (int)plaintext.size()) != 1)
            throw std::runtime_error("EVP_EncryptUpdate(PT) failed");
    }

    int finLen = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), outCiphertext.data() + outLen, &finLen) != 1)
        throw std::runtime_error("EVP_EncryptFinal_ex failed");

    outCiphertext.resize((size_t)outLen + (size_t)finLen);

    outTag.resize(16);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, (int)outTag.size(), outTag.data()) != 1)
        throw std::runtime_error("EVP_CTRL_GCM_GET_TAG failed");
}

bool EciesCipher::aes256gcmDecrypt(
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& nonce,
    const std::vector<unsigned char>& ciphertext,
    const std::vector<unsigned char>& aad,
    const std::vector<unsigned char>& tag,
    std::vector<unsigned char>& outPlaintext)
{
    if (key.size() != 32) throw std::runtime_error("AES-256 key must be 32 bytes");
    if (nonce.size() != 12) throw std::runtime_error("GCM nonce must be 12 bytes");

    EVP_CIPHER_CTX* raw = EVP_CIPHER_CTX_new();
    if (!raw) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter> ctx(raw);

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("EVP_DecryptInit_ex failed");

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr) != 1)
        throw std::runtime_error("EVP_CTRL_GCM_SET_IVLEN failed");

    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1)
        throw std::runtime_error("EVP_DecryptInit_ex(key/iv) failed");

    int len = 0;
    if (!aad.empty()) {
        if (EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(), (int)aad.size()) != 1)
            throw std::runtime_error("EVP_DecryptUpdate(AAD) failed");
    }

    outPlaintext.resize(ciphertext.size());
    int outLen = 0;
    if (!ciphertext.empty()) {
        if (EVP_DecryptUpdate(ctx.get(), outPlaintext.data(), &outLen, ciphertext.data(), (int)ciphertext.size()) != 1)
            throw std::runtime_error("EVP_DecryptUpdate(CT) failed");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, (int)tag.size(),
                            const_cast<unsigned char*>(tag.data())) != 1) {
        throw std::runtime_error("EVP_CTRL_GCM_SET_TAG failed");
    }

    int finLen = 0;
    const int ok = EVP_DecryptFinal_ex(ctx.get(), outPlaintext.data() + outLen, &finLen);
    if (ok != 1) {
        outPlaintext.clear();
        return false;
    }

    outPlaintext.resize((size_t)outLen + (size_t)finLen);
    return true;
}

// ---------------- ECIES API ----------------
EciesCiphertext EciesCipher::encrypt(
    const std::vector<unsigned char>& plaintext,
    const std::vector<unsigned char>& aad) const
{
    // Receiver public key
    EVP_PKEY* rawReceiverPub = nullptr;
    buildPublicKeyFromOctets(receiverPubUncompressed_, (void**)&rawReceiverPub);
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> receiverPub(rawReceiverPub);

    // Sender key (static or ephemeral)
    std::vector<unsigned char> senderPubUncompressed;
    EVP_PKEY* rawSenderPriv = nullptr;

    if (hasStaticSender_) {
        senderPubUncompressed = senderPubUncompressed_;
        buildKeypairFromPrivateScalar(senderPrivScalar_, (void**)&rawSenderPriv);
    } else {
        EccKeyPair eph = eccKeyGen_.generate();
        senderPubUncompressed = eph.publicKeyUncompressed;
        buildKeypairFromPrivateScalar(eph.privateKey, (void**)&rawSenderPriv);
        OPENSSL_cleanse(eph.privateKey.data(), eph.privateKey.size());
    }

    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> senderPriv(rawSenderPriv);
    lastSenderPubUncompressed_ = senderPubUncompressed;

    // ECDH secret
    std::vector<unsigned char> secret = ecdhDerive(senderPriv.get(), receiverPub.get());

    // HKDF: salt = senderPub, info = "ECIESv1-AES256GCM" || curveNid || receiverPub
    std::vector<unsigned char> salt = senderPubUncompressed;
    std::vector<unsigned char> info;
    {
        const char* label = "ECIESv1-AES256GCM";
        info.insert(info.end(), label, label + std::strlen(label));
        // Bind to curve and receiver pub
        const char* sn = OBJ_nid2sn(curveNid_);
        if (sn) info.insert(info.end(), sn, sn + std::strlen(sn));
        info.push_back(0x00);
        info.insert(info.end(), receiverPubUncompressed_.begin(), receiverPubUncompressed_.end());
    }

    std::vector<unsigned char> aesKey = hkdfSha256(secret, salt, info, 32);
    OPENSSL_cleanse(secret.data(), secret.size());

    EciesCiphertext out;
    out.ephPublicKeyUncompressed = senderPubUncompressed;
    out.nonce.resize(12);
    if (RAND_bytes(out.nonce.data(), (int)out.nonce.size()) != 1)
        throwOpenSslError("RAND_bytes failed");

    aes256gcmEncrypt(aesKey, out.nonce, plaintext, aad, out.ciphertext, out.tag);

    OPENSSL_cleanse(aesKey.data(), aesKey.size());
    return out;
}

std::vector<unsigned char> EciesCipher::decrypt(
    const std::vector<unsigned char>& receiverPrivateKey,
    const EciesCiphertext& ct,
    const std::vector<unsigned char>& aad) const
{
    // Receiver keypair from priv ONLY (do not inject receiver pub)
    EVP_PKEY* rawReceiverPriv = nullptr;
    buildKeypairFromPrivateScalar(receiverPrivateKey, (void**)&rawReceiverPriv);
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> receiverPriv(rawReceiverPriv);

    // Sender public key (from ciphertext)
    EVP_PKEY* rawSenderPub = nullptr;
    buildPublicKeyFromOctets(ct.ephPublicKeyUncompressed, (void**)&rawSenderPub);
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> senderPub(rawSenderPub);

    // ECDH secret
    std::vector<unsigned char> secret = ecdhDerive(receiverPriv.get(), senderPub.get());

    // HKDF: MUST match encrypt()
    std::vector<unsigned char> salt = ct.ephPublicKeyUncompressed;
    std::vector<unsigned char> info;
    {
        const char* label = "ECIESv1-AES256GCM";
        info.insert(info.end(), label, label + std::strlen(label));
        const char* sn = OBJ_nid2sn(curveNid_);
        if (sn) info.insert(info.end(), sn, sn + std::strlen(sn));
        info.push_back(0x00);
        info.insert(info.end(), receiverPubUncompressed_.begin(), receiverPubUncompressed_.end());
    }

    std::vector<unsigned char> aesKey = hkdfSha256(secret, salt, info, 32);
    OPENSSL_cleanse(secret.data(), secret.size());

    std::vector<unsigned char> plaintext;
    if (!aes256gcmDecrypt(aesKey, ct.nonce, ct.ciphertext, aad, ct.tag, plaintext)) {
        OPENSSL_cleanse(aesKey.data(), aesKey.size());
        throw std::runtime_error("ECIES decrypt failed: authentication error");
    }

    OPENSSL_cleanse(aesKey.data(), aesKey.size());
    return plaintext;
}
