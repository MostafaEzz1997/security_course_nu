#include "RsaAlgo.hpp"
#include <algorithm>
#include <chrono>
#include <limits>
#include <stdexcept>

/**
 * @brief Constructs an RsaAlgo instance and seeds the random number generator.
 */
RsaAlgo::RsaAlgo(unsigned int prime_checks)
    : _prime_checks(prime_checks),
      _rng(static_cast<std::mt19937_64::result_type>(std::chrono::high_resolution_clock::now().time_since_epoch().count())) {}

/**
 * @brief Implements the RSA key generation algorithm.
 */
RsaAlgo::KeyPair RsaAlgo::GenerateKeys(unsigned int key_bits, unsigned int min_delta_bytes) {
    if (key_bits < 64) {
        throw std::invalid_argument("Key size too small");
    }

    auto primes = GeneratePrimePair(key_bits / 2, min_delta_bytes);
    BN_ptr &p = primes.first;
    BN_ptr &q = primes.second;

    // Create a context for temporary variables in OpenSSL functions
    CTX_ptr ctx(BN_CTX_new(), BN_CTX_free);
    if (!ctx) {
        throw std::runtime_error("Failed to create BN_CTX");
    }

    // Calculate n = p * q
    BN_ptr n(BN_new(), BN_free);
    BN_mul(n.get(), p.get(), q.get(), ctx.get());

    // Calculate Euler's totient function: phi(n) = (p-1) * (q-1)
    BN_ptr phi(BN_new(), BN_free);
    BN_ptr p_minus(BN_dup(p.get()), BN_free);
    BN_ptr q_minus(BN_dup(q.get()), BN_free);
    // p_minus = p - 1
    BN_sub(p_minus.get(), p.get(), BN_value_one());
    // q_minus = q - 1
    BN_sub(q_minus.get(), q.get(), BN_value_one());
    // phi = (p - 1) * (q - 1)
    BN_mul(phi.get(), p_minus.get(), q_minus.get(), ctx.get());

    // Choose public exponent 'e'. 65537 is a common choice as it is prime and has computational advantages.
    BN_ptr e(BN_new(), BN_free);
    BN_set_word(e.get(), 65537);

    BN_ptr gcd(BN_new(), BN_free);
    BN_gcd(gcd.get(), e.get(), phi.get(), ctx.get());
    if (!BN_is_one(gcd.get())) {
        std::uniform_int_distribution<uint64_t> dist(3, std::numeric_limits<uint64_t>::max());
        // If 65537 is not coprime to phi, find another 'e' that is.
        do {
            BN_set_word(e.get(), dist(_rng) | 1ULL);
            BN_gcd(gcd.get(), e.get(), phi.get(), ctx.get());
        } while (!BN_is_one(gcd.get()));
    }

    // Calculate private exponent 'd', the modular multiplicative inverse of e mod phi(n).
    BN_ptr d(BN_mod_inverse(nullptr, e.get(), phi.get(), ctx.get()), BN_free);
    if (!d) {
        throw std::runtime_error("Failed to compute modular inverse");
    }

    return {ToHex(n.get()), ToHex(e.get()), ToHex(d.get()), ToHex(p.get()), ToHex(q.get())};
}

/**
 * @brief Implements the RSA encryption algorithm (c = m^e mod n).
 */
BIGNUM* RsaAlgo::Encrypt(const std::string &message, const KeyPair &public_key) {
    // Convert the message string and hex key components into BIGNUM objects.
    BN_ptr m = BytesToBigNum(std::vector<uint8_t>(message.begin(), message.end()));
    BN_ptr n = LoadFromHex(public_key.n);
    BN_ptr e = LoadFromHex(public_key.e);

    if (BN_cmp(m.get(), n.get()) >= 0) {
        throw std::invalid_argument("Message too large for modulus");
    }

    // Perform the modular exponentiation: ciphertext = message^e mod n
    CTX_ptr ctx(BN_CTX_new(), BN_CTX_free);
    BN_ptr out(BN_new(), BN_free);
    BN_mod_exp(out.get(), m.get(), e.get(), n.get(), ctx.get());

    // Release ownership of the BIGNUM to the caller
    return out.release();
}

/**
 * @brief Implements the RSA decryption algorithm (m = c^d mod n).
 */
std::string RsaAlgo::Decrypt(const BIGNUM *ciphertext, const KeyPair &private_key) {
    // Duplicate the input ciphertext and load hex key components into BIGNUM objects.
    BN_ptr c(BN_dup(ciphertext), BN_free);
    BN_ptr n = LoadFromHex(private_key.n);
    BN_ptr d = LoadFromHex(private_key.d);

    // Perform the modular exponentiation: message = ciphertext^d mod n
    CTX_ptr ctx(BN_CTX_new(), BN_CTX_free);
    BN_ptr m(BN_new(), BN_free);
    BN_mod_exp(m.get(), c.get(), d.get(), n.get(), ctx.get());
    // Convert the resulting BIGNUM back to a string.
    auto bytes = BigNumToBytes(m.get());
    return std::string(bytes.begin(), bytes.end());
}

/**
 * @brief Implements the RSA signing algorithm (s = m^d mod n).
 */
BIGNUM* RsaAlgo::Sign(const std::string &message, const KeyPair &private_key) {
    // Convert the message string and hex key components into BIGNUM objects.
    BN_ptr m = BytesToBigNum(std::vector<uint8_t>(message.begin(), message.end()));
    BN_ptr n = LoadFromHex(private_key.n);
    BN_ptr d = LoadFromHex(private_key.d);

    if (BN_cmp(m.get(), n.get()) >= 0) {
        throw std::invalid_argument("Message too large for modulus");
    }

    // Perform the modular exponentiation: signature = message^d mod n
    CTX_ptr ctx(BN_CTX_new(), BN_CTX_free);
    BN_ptr sig(BN_new(), BN_free);
    BN_mod_exp(sig.get(), m.get(), d.get(), n.get(), ctx.get());

    // Release ownership of the BIGNUM to the caller
    return sig.release();
}

/**
 * @brief Implements the RSA signature verification algorithm.
 */
bool RsaAlgo::Verify(const std::string &message, const BIGNUM *signature, const KeyPair &public_key) {
    // Duplicate the input signature and load hex key components into BIGNUM objects.
    BN_ptr sig(BN_dup(signature), BN_free);
    BN_ptr n = LoadFromHex(public_key.n);
    BN_ptr e = LoadFromHex(public_key.e);

    CTX_ptr ctx(BN_CTX_new(), BN_CTX_free);
    BN_ptr recovered(BN_new(), BN_free);
    // Recover the original message from the signature: m' = signature^e mod n
    BN_mod_exp(recovered.get(), sig.get(), e.get(), n.get(), ctx.get());

    // Convert the original message to a BIGNUM and compare it with the recovered one.
    auto expected = BytesToBigNum(std::vector<uint8_t>(message.begin(), message.end()));
    return BN_cmp(recovered.get(), expected.get()) == 0;
}

/**
 * @brief Generates a random prime number using OpenSSL's primality test.
 */
RsaAlgo::BN_ptr RsaAlgo::GeneratePrime(unsigned int bits) {
    BN_ptr prime(BN_new(), BN_free);
    CTX_ptr ctx(BN_CTX_new(), BN_CTX_free);
    while (true) {
        // Generate a random number of the specified bit length.
        BN_rand(prime.get(), bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);
        // Check if the number is prime using Miller-Rabin test.
        int is_prime = BN_is_prime_ex(prime.get(), _prime_checks, ctx.get(), nullptr);
        if (is_prime == 1) {
            return prime;
        }
    }
}

/**
 * @brief Generates a pair of distinct prime numbers (p, q) suitable for RSA.
 */
std::pair<RsaAlgo::BN_ptr, RsaAlgo::BN_ptr> RsaAlgo::GeneratePrimePair(unsigned int bits, unsigned int min_delta_bytes) {
    // Generate two candidate primes.
    BN_ptr p = GeneratePrime(bits);
    BN_ptr q = GeneratePrime(bits);

    BN_ptr delta(BN_new(), BN_free);
    BN_set_word(delta.get(), min_delta_bytes);

    BN_ptr diff(BN_new(), BN_free);

    while (true) {
        // Loop until p and q are distinct and sufficiently far apart.
        // Calculate the absolute difference between p and q
        int cmp = BN_cmp(p.get(), q.get());
        if (cmp > 0) {
            BN_sub(diff.get(), p.get(), q.get());
        } else if (cmp < 0) {
            BN_sub(diff.get(), q.get(), p.get());
        } else {
            BN_zero(diff.get());
        }

        // Check if p and q are not equal and their difference is large enough to avoid factorization attacks.
        if (cmp != 0 && BN_cmp(diff.get(), delta.get()) >= 0) {
            break;
        }

        // If conditions are not met, generate a new 'q' and try again.
        q = GeneratePrime(bits);
    }

    return {std::move(p), std::move(q)};
}

/**
 * @brief Utility to convert a byte vector to a BIGNUM.
 */
RsaAlgo::BN_ptr RsaAlgo::BytesToBigNum(const std::vector<uint8_t> &bytes) {
    // BN_bin2bn converts a big-endian byte array to a BIGNUM.
    BN_ptr value(BN_bin2bn(bytes.data(), static_cast<int>(bytes.size()), nullptr), BN_free);
    if (!value) {
        throw std::runtime_error("Failed to convert bytes to BIGNUM");
    }
    return value;
}

/**
 * @brief Utility to convert a BIGNUM to a byte vector.
 */
std::vector<uint8_t> RsaAlgo::BigNumToBytes(const BIGNUM *value) {
    int size = BN_num_bytes(value);
    std::vector<uint8_t> bytes(static_cast<size_t>(size));
    // BN_bn2bin converts a BIGNUM to a big-endian byte array.
    BN_bn2bin(value, bytes.data());
    return bytes;
}

/**
 * @brief Utility to load a BIGNUM from a hexadecimal string.
 */
RsaAlgo::BN_ptr RsaAlgo::LoadFromHex(const std::string &hex) {
    BIGNUM *raw = nullptr;
    // BN_hex2bn converts a hexadecimal string to a BIGNUM.
    if (BN_hex2bn(&raw, hex.c_str()) == 0) {
        throw std::runtime_error("Failed to parse hex BIGNUM");
    }
    return BN_ptr(raw, BN_free);
}

/**
 * @brief Utility to convert a BIGNUM to its hexadecimal string representation.
 */
std::string RsaAlgo::ToHex(const BIGNUM *value) {
    // BN_bn2hex converts a BIGNUM to a dynamically allocated hexadecimal string.
    char *hex = BN_bn2hex(value);
    if (!hex) {
        throw std::runtime_error("Failed to convert BIGNUM to hex");
    }
    std::string out(hex);
    // The memory allocated by OpenSSL must be freed with OPENSSL_free.
    OPENSSL_free(hex);
    return out;
}
