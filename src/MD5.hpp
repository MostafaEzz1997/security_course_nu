/**
 * @file MD5.hpp
 * @brief Defines the MD5 class for computing MD5 hashes.
 */

#ifndef MD5_HPP
#define MD5_HPP

#include <array>
#include <cstdint>
#include <string>

namespace crypto {

/**
 * @class MD5
 * @brief A class to compute the MD5 hash of a data stream or string.
 *
 * This class implements the MD5 algorithm as specified in RFC 1321.
 * It can be used to generate a 128-bit hash from data provided in chunks
 * or all at once.
 */
class MD5 {
  public:
    /**
     * @brief Default constructor. Initializes the MD5 context.
     */
    MD5();

    /**
     * @brief Processes a block of data to update the hash.
     * @param data Pointer to the data to be processed.
     * @param len Length of the data in bytes.
     */
    void update(const unsigned char *data, std::size_t len);

    /**
     * @brief Finalizes the hash computation and returns the digest as a hex string.
     * @return A 32-character hexadecimal string representing the MD5 hash.
     */
    std::string hexdigest();

  private:
    /**
     * @brief Reset the internal state to the initial MD5 constants.
     */
    void init();

    /**
     * @brief Process a single 512-bit block of the message.
     * @param block The 64-byte block to transform into the internal digest state.
     */
    void transform(const uint8_t block[64]);

    /**
     * @brief Append the MD5 padding bits followed by the message length.
     */
    void padMessage();

    /**
     * @brief Encode a bit length into a little-endian 64-bit array.
     * @param lengthBytes Output buffer of eight bytes.
     * @param bitLength Total length of the original message in bits.
     */
    void encodeLength(uint8_t (&lengthBytes)[8], uint64_t bitLength) const;

    /**
     * @brief Finish the digest computation and write the raw bytes.
     * @param digest Output buffer of 16 bytes holding the final hash.
     */
    void finalizeDigest(uint8_t (&digest)[16]);

    std::array<uint32_t, 4> registers_{}; ///< Internal MD5 buffers A, B, C, D.
    uint64_t bitCount_{};                 ///< Total number of processed bits.
    std::array<uint8_t, 64> blockBuffer_{}; ///< Accumulated bytes before processing.
};

} // namespace crypto
#endif // MD5_HPP
