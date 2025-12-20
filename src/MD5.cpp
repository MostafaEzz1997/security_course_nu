/**
 * @file MD5.cpp
 * @brief Implements the MD5 hashing algorithm (RFC 1321 compliant).
 */

#include "MD5.hpp"
#include <cstring>

namespace crypto {

namespace {

/**
 * @brief MD5 auxiliary nonlinear functions (F, G, H, I).
 */
inline uint32_t F(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
inline uint32_t G(uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); }
inline uint32_t H(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
inline uint32_t I(uint32_t x, uint32_t y, uint32_t z) { return y ^ (x | ~z); }

inline uint32_t rotate_left(uint32_t x, uint32_t n) { return (x << n) | (x >> (32 - n)); }

// Table of sine-based constants (T-values)
constexpr uint32_t T[] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

/// Shift amounts for each operation step across the four rounds.
constexpr uint32_t S[] = {
     7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22, // Round 1
     5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20, // Round 2
     4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23, // Round 3
     6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21  // Round 4
};

} // anonymous namespace

MD5::MD5() { init(); }

/** Reset the running bit count and set registers to the defined MD5 constants. */
void MD5::init() {
    bitCount_ = 0;
    registers_[0] = 0x67452301;
    registers_[1] = 0xefcdab89;
    registers_[2] = 0x98badcfe;
    registers_[3] = 0x10325476;
    blockBuffer_.fill(0);
}

/**
 * @brief Ingest arbitrary-length data into the algorithm state.
 *
 * This accumulates bytes into a 64-byte buffer; whenever the buffer fills,
 * a 512-bit transform is executed. The total bit count is tracked to support
 * length padding during finalization.
 */
void MD5::update(const unsigned char *input, std::size_t inputLen) {
    std::size_t bufferIndex = (bitCount_ >> 3) & 0x3F; // current byte offset in 64-byte block
    bitCount_ += static_cast<uint64_t>(inputLen) << 3; // track total bits processed

    std::size_t spaceInBuffer = 64 - bufferIndex;
    std::size_t copyIndex = 0;

    // If incoming data can complete the current buffer, process it first
    if (inputLen >= spaceInBuffer) {
        std::memcpy(blockBuffer_.data() + bufferIndex, input, spaceInBuffer);
        transform(blockBuffer_.data());
        copyIndex = spaceInBuffer;

        // Process additional complete 64-byte blocks directly from the input
        while (copyIndex + 64 <= inputLen) {
            transform(reinterpret_cast<const uint8_t *>(input + copyIndex));
            copyIndex += 64;
        }
        bufferIndex = 0; // reset for remaining bytes
    }

    // Copy any leftover bytes into the buffer
    std::memcpy(blockBuffer_.data() + bufferIndex, input + copyIndex, inputLen - copyIndex);
}

/**
 * @brief Finalize the digest computation and produce a hexadecimal string.
 *
 * The finalizeDigest call performs bit padding, length appending,
 * block processing, and raw digest extraction.
 */
std::string MD5::hexdigest() {
    uint8_t digest[16] = {0};
    finalizeDigest(digest);

    static const char hexDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(32);

    for (uint8_t byte : digest) {
        out.push_back(hexDigits[byte >> 4]);
        out.push_back(hexDigits[byte & 0x0F]);
    }

    init();
    return out;
}

/**
 * @brief Apply MD5 padding to the buffered message.
 *
 * Step 1: Append a single 1 bit (0x80) followed by zero bits until the message
 * length is 64 bits shy of a multiple of 512 bits.
 * Step 2: Append the original message length in bits as a 64-bit little-endian integer.
 */
void MD5::padMessage() {
    static const uint8_t PADDING[64] = {0x80};

    const uint64_t originalBitCount = bitCount_; // preserve message length before padding
    std::size_t bufferIndex = (bitCount_ >> 3) & 0x3F;
    // If buffer has < 56 bytes, pad to 56. Otherwise, pad to fill the current
    // block and continue padding into the next block until its 56-byte mark.
    // The 120 comes from (64 - bufferIndex) + 56.
    std::size_t padLen = (bufferIndex < 56) ? (56 - bufferIndex) : (120 - bufferIndex);

    update(PADDING, padLen);

    uint8_t lengthBytes[8];
    encodeLength(lengthBytes, originalBitCount);
    update(lengthBytes, sizeof(lengthBytes));
}

/**
 * @brief Encode the total bit length into eight little-endian bytes.
 */
void MD5::encodeLength(uint8_t (&lengthBytes)[8], uint64_t bitLength) const {
    for (int i = 0; i < 8; ++i) {
        lengthBytes[i] = static_cast<uint8_t>((bitLength >> (8 * i)) & 0xFF);
    }
}

/**
 * @brief Finish hashing: pad message, process remaining blocks, serialize state.
 */
void MD5::finalizeDigest(uint8_t (&digest)[16]) {
    padMessage();

    // Serialize the 32-bit registers into a 16-byte, little-endian array
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            digest[i * 4 + j] = static_cast<uint8_t>((registers_[i] >> (j * 8)) & 0xFF);
        }
    }
}

/**
 * @brief Process a single 512-bit message block through four MD5 rounds.
 *
 * The block is split into 16 words, then four rounds of 16 operations apply the MD5
 * nonlinear functions with distinct message scheduling, constants, and left rotations.
 * Results are accumulated into the running registers.
 */
void MD5::transform(const uint8_t block[64]) {
    uint32_t a = registers_[0];
    uint32_t b = registers_[1];
    uint32_t c = registers_[2];
    uint32_t d = registers_[3];
    uint32_t x[16];

    // Break 512-bit block into sixteen 32-bit little-endian words
    for (int i = 0, j = 0; i < 16; ++i, j += 4) {
        x[i] = static_cast<uint32_t>(block[j]) | (static_cast<uint32_t>(block[j + 1]) << 8) |
               (static_cast<uint32_t>(block[j + 2]) << 16) | (static_cast<uint32_t>(block[j + 3]) << 24);
    }

    for (int i = 0; i < 64; ++i) {
        uint32_t f;
        uint32_t g;

        if (i < 16) { // Round 1
            f = F(b, c, d);
            g = i;
        } else if (i < 32) { // Round 2
            f = G(b, c, d);
            g = (5 * i + 1) % 16;
        } else if (i < 48) { // Round 3
            f = H(b, c, d);
            g = (3 * i + 5) % 16;
        } else { // Round 4
            f = I(b, c, d);
            g = (7 * i) % 16;
        }

        uint32_t temp = d;
        d = c;
        c = b;
        b = b + rotate_left(a + f + T[i] + x[g], S[i]);
        a = temp;
    }

    registers_[0] += a;
    registers_[1] += b;
    registers_[2] += c;
    registers_[3] += d;
}

} // namespace crypto
