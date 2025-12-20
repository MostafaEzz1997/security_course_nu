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
    void init();
    void transform(const uint8_t block[64]);

    uint32_t state[4];
    uint64_t count;
    uint8_t buffer[64];
};

} // namespace crypto
#endif // MD5_HPP