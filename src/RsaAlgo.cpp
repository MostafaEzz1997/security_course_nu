/**
 * @file RsaAlgo.cpp
 * @brief Implements the methods of the RsaAlgo class for RSA operations.
 */

#include "RsaAlgo.hpp"

#include <chrono>
#include <random>
#include <stdexcept>

namespace rsa {

// Anonymous namespace for internal constants and helpers.
namespace {

/// Minimum supported key size in bits.
constexpr std::size_t MIN_KEY_BITS = 128;
/// Maximum supported key size in bits.
constexpr std::size_t MAX_KEY_BITS = 4096;

/**
 * @brief A custom deleter for OpenSSL BN_CTX objects.
 * Used with std::unique_ptr to ensure BN_CTX_free() is called.
 */
struct CtxDeleter {
    void operator()(BN_CTX *ctx) const noexcept {
        if (ctx != nullptr) {
            BN_CTX_free(ctx);
        }
    }
};

/// A smart pointer for managing BN_CTX resources automatically.
using CTX_ptr = std::unique_ptr<BN_CTX, CtxDeleter>;

/**
 * @brief Factory function to create a new, managed BIGNUM object.
 * @return A BigNumPtr holding the new BIGNUM.
 * @throws std::runtime_error if allocation fails.
 */
BigNumPtr makeInitialized() {
    BigNumPtr bn(BN_new());
    if (!bn) {
        throw std::runtime_error("Failed to allocate BIGNUM");
    }
    return bn;
}

} // namespace

BigNumPtr RsaAlgo::makeBigNum() {
    return makeInitialized();
}

BigNumPtr RsaAlgo::clone(const BIGNUM *source) {
    // Creates a new BIGNUM and performs a deep copy of the source's value.
    // This is crucial for functions that modify their inputs, ensuring the
    // original BIGNUM remains unchanged.
    BigNumPtr result = makeInitialized();
    if (!BN_copy(result.get(), source)) {
        throw std::runtime_error("Failed to copy BIGNUM");
    }
    return result;
}

BigNumPtr RsaAlgo::generateRandomBigInt(std::size_t bits) {
    // This function generates a random integer of a specific bit length.
    // It ensures the generated number has its most significant bit set,
    // guaranteeing it has the desired magnitude.
    if (bits == 0) {
        return makeBigNum();
    }

    // Use a high-quality random number generator from the C++ standard library.
    std::random_device rd;
    std::mt19937_64 gen(rd());

    // Generate a buffer of random bytes.
    std::size_t byteLength = (bits + 7) / 8;
    std::string buffer(byteLength, '\0');
    for (std::size_t i = 0; i < byteLength; ++i) {
        buffer[i] = static_cast<char>(gen() & 0xFF);
    }
    // Ensure the number is not small by setting a high bit in the first byte.
    buffer[0] |= static_cast<char>(0x80);

    // Convert the binary buffer to a BIGNUM.
    BigNumPtr bn = makeInitialized();
    BN_bin2bn(reinterpret_cast<const unsigned char *>(buffer.data()), static_cast<int>(buffer.size()), bn.get());

    // If the generated number is larger than the target bit size, shift it down.
    int shift = static_cast<int>((byteLength * 8) - bits);
    if (shift > 0) {
        BN_rshift(bn.get(), bn.get(), shift);
    }
    BN_set_bit(bn.get(), static_cast<int>(bits - 1));
    return bn;
}

BigNumPtr RsaAlgo::gcd(const BIGNUM *a, const BIGNUM *b) {
    // Implements the Euclidean algorithm to find the greatest common divisor (GCD).
    // The algorithm repeatedly applies the logic: gcd(a, b) = gcd(b, a mod b).
    BigNumPtr x = clone(a);
    BigNumPtr y = clone(b);
    BigNumPtr mod = makeInitialized();
    CTX_ptr ctx(BN_CTX_new());

    while (!BN_is_zero(y.get())) { // Loop until the remainder (y) is zero.
        BN_div(nullptr, mod.get(), x.get(), y.get(), ctx.get());
        BN_copy(x.get(), y.get());
        BN_copy(y.get(), mod.get());
    }
    return x;
}

bool RsaAlgo::isProbablePrime(const BIGNUM *number, int iterations) {
    // Implements the Miller-Rabin probabilistic primality test.
    // It's a probabilistic test: a non-prime will never be reported as prime,
    // but a prime might be reported as non-prime with a very low probability.
    // More iterations reduce this probability.

    // Basic checks for small or even numbers.
    if (BN_is_negative(number) || BN_is_zero(number) || BN_is_one(number)) {
        return false;
    }
    if (!BN_is_odd(number)) {
        return false;
    }

    // The core of Miller-Rabin is to test the primality based on the identity:
    // a^(n-1) ≡ 1 (mod n) for a prime n.
    // First, we decompose (n-1) into 2^s * d, where d is odd.
    BigNumPtr n_minus_one = clone(number);
    BN_sub_word(n_minus_one.get(), 1);

    BigNumPtr d = clone(n_minus_one.get());
    unsigned int s = 0;
    while (!BN_is_zero(d.get()) && !BN_is_bit_set(d.get(), 0)) { // While d is even
        BN_rshift1(d.get(), d.get());
        ++s;
    }

    // Use a seeded random generator for choosing witnesses 'a'.
    std::mt19937_64 gen(static_cast<unsigned long long>(std::chrono::high_resolution_clock::now().time_since_epoch().count()));
    std::uniform_int_distribution<unsigned long long> dist;

    CTX_ptr ctx(BN_CTX_new());

    // Pre-calculate n-2 for generating random witnesses in the range [2, n-2].
    BigNumPtr a = makeInitialized();
    BigNumPtr x = makeInitialized();
    BigNumPtr n_sub_two = clone(number);
    BN_sub_word(n_sub_two.get(), 2);

    // Perform the test for `iterations` number of random witnesses.
    for (int i = 0; i < iterations; ++i) {
        // Choose a random witness 'a'. Note: For crypto-strength, BN_rand_range is better.
        BN_set_word(a.get(), 2 + (dist(gen) % BN_get_word(n_sub_two.get())));

        // Calculate x = a^d mod n.
        x = modExpSquareAndMultiply(a.get(), d.get(), number);

        // If x is 1 or n-1, the number might be prime. Continue to the next witness.
        if (BN_is_one(x.get()) || BN_cmp(x.get(), n_minus_one.get()) == 0) {
            continue;
        }

        // Otherwise, repeatedly square x (s-1 times) and check if it becomes n-1.
        bool continueLoop = false;
        for (unsigned int r = 1; r < s; ++r) {
            BN_mod_mul(x.get(), x.get(), x.get(), number, ctx.get());
            if (BN_cmp(x.get(), n_minus_one.get()) == 0) {
                continueLoop = true;
                break;
            }
        }
        if (continueLoop) {
            continue;
        }

        // If after all squaring, x is not n-1, then 'number' is definitely composite.
        return false;
    }

    return true;
}

BigNumPtr RsaAlgo::generatePrime(std::size_t bits, const BIGNUM *other_prime) {
    // Generates a probable prime number of a specified bit length.
    // It repeatedly generates random candidates and tests them with Miller-Rabin.

    if (bits < 4) {
        throw std::runtime_error("Prime size too small");
    }

    BigNumPtr candidate = makeInitialized();
    BigNumPtr difference = makeInitialized();
    BigNumPtr minDistance = makeInitialized();
    CTX_ptr ctx(BN_CTX_new());

    // To prevent certain attacks, the generated primes p and q should not be too close.
    // We define a minimum distance between them.
    BN_one(minDistance.get());
    unsigned int distanceBits = static_cast<unsigned int>(std::max<std::size_t>(1, std::min<std::size_t>(bits - 4, 256)));
    BN_lshift(minDistance.get(), minDistance.get(), distanceBits);

    while (true) {
        // 1. Generate a random number of the desired bit length.
        candidate = generateRandomBigInt(bits);
        // 2. Make it odd, as all primes (except 2) are odd.
        if (!BN_is_odd(candidate.get())) {
            BN_add_word(candidate.get(), 1);
        }

        // 3. If generating the second prime (q), ensure it's not too close to the first (p).
        if (other_prime && !BN_is_zero(other_prime)) {
            BN_sub(difference.get(), candidate.get(), other_prime);
            if (BN_is_negative(difference.get())) {
                // Absolute difference
                BN_sub(difference.get(), other_prime, candidate.get());
            }
            if (BN_cmp(difference.get(), minDistance.get()) < 0) {
                continue;
            }
        }

        // 4. Test if the candidate is probably prime. If so, we're done.
        if (isProbablePrime(candidate.get())) {
            return candidate;
        }
    }
}

BigNumPtr RsaAlgo::modInverse(const BIGNUM *a, const BIGNUM *modulus) {
    // Implements the Extended Euclidean Algorithm to find the modular multiplicative inverse.
    // It finds a value 't' such that (a * t) mod modulus = 1.
    // This is used to calculate the private exponent 'd' from the public exponent 'e' and phi.

    CTX_ptr ctx(BN_CTX_new());

    BigNumPtr t = makeInitialized();
    BigNumPtr new_t = makeInitialized();
    BigNumPtr r = clone(modulus);
    BigNumPtr new_r = clone(a);

    // Initialize coefficients for the extended algorithm.
    BN_zero(t.get());
    BN_one(new_t.get());

    BigNumPtr quotient = makeInitialized();
    BigNumPtr temp = makeInitialized();

    while (!BN_is_zero(new_r.get())) {
        // Calculate quotient and update coefficients (t, new_t) and remainders (r, new_r).
        BN_div(quotient.get(), nullptr, r.get(), new_r.get(), ctx.get());

        BN_mul(temp.get(), quotient.get(), new_t.get(), ctx.get());
        BN_sub(temp.get(), t.get(), temp.get());
        BN_copy(t.get(), new_t.get());
        BN_copy(new_t.get(), temp.get());

        BN_mul(temp.get(), quotient.get(), new_r.get(), ctx.get());
        BN_sub(temp.get(), r.get(), temp.get());
        BN_copy(r.get(), new_r.get());
        BN_copy(new_r.get(), temp.get());
    }

    // If the final remainder 'r' is not 1, then 'a' and 'modulus' are not coprime,
    // and no modular inverse exists.
    if (BN_cmp(r.get(), BN_value_one()) > 0) {
        throw std::runtime_error("Modular inverse does not exist");
    }
    // If 't' is negative, add the modulus to bring it into the range [0, modulus-1].
    if (BN_is_negative(t.get())) {
        BN_add(t.get(), t.get(), modulus);
    }
    return t;
}

BigNumPtr RsaAlgo::modExpNormal(const BIGNUM *base, const BIGNUM *exponent, const BIGNUM *modulus) {
    // Implements modular exponentiation using the right-to-left binary method.
    // This is a variant of the square-and-multiply algorithm.
    // It computes (base ^ exponent) mod modulus.

    if (BN_is_zero(modulus)) {
        return makeBigNum();
    }

    CTX_ptr ctx(BN_CTX_new());

    BigNumPtr result = makeInitialized();
    BigNumPtr baseCopy = clone(base);
    BigNumPtr expCopy = clone(exponent);

    BN_one(result.get());
    // Reduce the base modulo the modulus to keep intermediate numbers small.
    BN_mod(baseCopy.get(), baseCopy.get(), modulus, ctx.get());

    while (!BN_is_zero(expCopy.get())) {
        // If the current LSB of the exponent is 1, multiply the result by the current base.
        if (BN_is_odd(expCopy.get())) {
            BN_mod_mul(result.get(), result.get(), baseCopy.get(), modulus, ctx.get());
        }
        // Right-shift the exponent (divide by 2) and square the base for the next iteration.
        BN_rshift1(expCopy.get(), expCopy.get());
        BN_mod_mul(baseCopy.get(), baseCopy.get(), baseCopy.get(), modulus, ctx.get());
    }
    return result;
}

BigNumPtr RsaAlgo::modExpSquareAndMultiply(const BIGNUM *base, const BIGNUM *exponent, const BIGNUM *modulus) {
    // Implements modular exponentiation using the left-to-right binary method (square-and-multiply).
    // It iterates through the bits of the exponent from most significant to least significant.
    // This is generally more efficient and is the standard approach.

    if (BN_is_zero(modulus)) {
        return makeBigNum();
    }

    CTX_ptr ctx(BN_CTX_new());

    BigNumPtr result = makeInitialized();
    BigNumPtr baseCopy = clone(base);

    BN_one(result.get());
    // Reduce the base initially.
    BN_mod(baseCopy.get(), baseCopy.get(), modulus, ctx.get());

    int bits = BN_num_bits(exponent);
    for (int i = bits - 1; i >= 0; --i) {
        // Always square the result.
        BN_mod_mul(result.get(), result.get(), result.get(), modulus, ctx.get());
        // If the current bit of the exponent is 1, multiply by the base.
        if (BN_is_bit_set(exponent, i)) {
            BN_mod_mul(result.get(), result.get(), baseCopy.get(), modulus, ctx.get());
        }
    }
    return result;
}

BigNumPtr RsaAlgo::encryptNormal(const BIGNUM *message, const BIGNUM *e, const BIGNUM *n) {
    // Textbook RSA encryption: ciphertext = message^e mod n.
    if (BN_cmp(message, n) >= 0) {
        throw std::runtime_error("Message too large for modulus");
    }
    return modExpNormal(message, e, n);
}

BigNumPtr RsaAlgo::encryptSquareMultiply(const BIGNUM *message, const BIGNUM *e, const BIGNUM *n) {
    // Textbook RSA encryption using the more efficient square-and-multiply.
    if (BN_cmp(message, n) >= 0) {
        throw std::runtime_error("Message too large for modulus");
    }
    return modExpSquareAndMultiply(message, e, n);
}

BigNumPtr RsaAlgo::decryptNormal(const BIGNUM *cipher, const BIGNUM *d, const BIGNUM *n) {
    // Textbook RSA decryption: message = ciphertext^d mod n.
    return modExpNormal(cipher, d, n);
}

BigNumPtr RsaAlgo::decryptSquareMultiply(const BIGNUM *cipher, const BIGNUM *d, const BIGNUM *n) {
    // Textbook RSA decryption using the more efficient square-and-multiply.
    return modExpSquareAndMultiply(cipher, d, n);
}

BigNumPtr RsaAlgo::signMessage(const BIGNUM *message, const BIGNUM *d, const BIGNUM *n) {
    // Textbook RSA signing: signature = message^d mod n.
    if (BN_cmp(message, n) >= 0) {
        throw std::runtime_error("Message too large for modulus");
    }
    return modExpSquareAndMultiply(message, d, n);
}

bool RsaAlgo::verifySignature(const BIGNUM *signature, const BIGNUM *expectedMessage, const BIGNUM *e,
                              const BIGNUM *n) {
    BigNumPtr recovered = modExpSquareAndMultiply(signature, e, n);
    return BN_cmp(recovered.get(), expectedMessage) == 0;
}

RsaKeyPair RsaAlgo::generateKeyPair(std::size_t key_bits) {
    if (key_bits % 128 != 0 || key_bits < MIN_KEY_BITS || key_bits > MAX_KEY_BITS) {
        throw std::runtime_error("Unsupported key size; choose 128, 256, 512, 1024, 2048, or 4096 bits");
    }

    std::size_t primeBits = key_bits / 2;

    BigNumPtr p = generatePrime(primeBits, nullptr);
    BigNumPtr q = generatePrime(primeBits, p.get());

    CTX_ptr ctx(BN_CTX_new());

    BigNumPtr n = makeInitialized();
    BigNumPtr phi = makeInitialized();
    BigNumPtr p_minus = clone(p.get());
    BigNumPtr q_minus = clone(q.get());

    // 2. Calculate the modulus n = p * q.
    BN_mul(n.get(), p.get(), q.get(), ctx.get());

    // 3. Calculate Euler's totient function: phi(n) = (p-1) * (q-1).
    BN_sub_word(p_minus.get(), 1);
    BN_sub_word(q_minus.get(), 1);
    BN_mul(phi.get(), p_minus.get(), q_minus.get(), ctx.get());

    // 4. Choose a public exponent 'e'. 65537 is a common choice as it's prime
    //    and has only two '1' bits, making exponentiation fast.
    BigNumPtr e = makeInitialized();
    BN_set_word(e.get(), 65537);
    BigNumPtr one = makeInitialized();
    BN_one(one.get());

    // Ensure that e is coprime to phi(n). If not, try other small odd numbers.
    BigNumPtr g = gcd(e.get(), phi.get());
    if (BN_cmp(g.get(), one.get()) != 0) { // If gcd(e, phi) is not 1
        BN_set_word(e.get(), 3);
        while (BN_cmp(g.get(), one.get()) != 0) {
            BN_add_word(e.get(), 2);
            g = gcd(e.get(), phi.get());
        }
    }

    // 5. Calculate the private exponent 'd' as the modular multiplicative inverse
    //    of e modulo phi(n).
    BigNumPtr d = modInverse(e.get(), phi.get());

    // 6. Assemble the key pair struct and return it.
    RsaKeyPair pair;
    pair.n = std::move(n);
    pair.e = std::move(e);
    pair.d = std::move(d);
    pair.p = std::move(p);
    pair.q = std::move(q);
    pair.phi = std::move(phi);
    pair.key_bits = key_bits;

    return pair;
}

BigNumPtr RsaAlgo::messageToInt(const std::string &message) {
    // Converts a raw byte string into a BIGNUM integer (big-endian).
    // This is a direct, "textbook" conversion without any padding.
    BigNumPtr value = makeInitialized();
    BN_bin2bn(reinterpret_cast<const unsigned char *>(message.data()), static_cast<int>(message.size()), value.get());
    return value;
}

std::string RsaAlgo::intToMessage(const BIGNUM *value) {
    // Converts a BIGNUM integer back into a raw byte string (big-endian).
    // This is the reverse of messageToInt.
    int size = BN_num_bytes(value);
    std::string output(size, '\0');
    BN_bn2bin(value, reinterpret_cast<unsigned char *>(&output[0]));
    return output;
}

} // namespace rsa
