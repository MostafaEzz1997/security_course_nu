#pragma once

#include <cstdint>
#include <vector>

class ToyECC {
public:
    struct KeyPair {
        std::int64_t privateKey;
        std::string publicKey;   // SEC1 compressed
    };

    // Constructor with optional curve parameters
    ToyECC(std::int64_t p  = 17,
           std::int64_t a  = 2,
           std::int64_t b  = 2,
           std::int64_t n  = 38,
           std::int64_t gx = 5,
           std::int64_t gy = 1);

    // Public API
    KeyPair generateKeyPair();

private:
    // Curve parameters
    std::int64_t P;
    std::int64_t A;
    std::int64_t B;
    std::int64_t N;

    // Base point
    std::int64_t Gx;
    std::int64_t Gy;

    struct Point {
        std::int64_t x;
        std::int64_t y;
        bool infinity;

        Point(std::int64_t x_=0, std::int64_t y_=0, bool inf=true);
    };

    // ECC internals
    Point basePoint() const;
    Point infinity() const;

    Point scalarMultiply(std::int64_t k, const Point& P0);
    Point pointAdd(const Point& P1, const Point& P2);
    Point pointDouble(const Point& P1);

    // Encoding
    std::vector<std::uint8_t> encodePointCompressed(const Point& P1);

    std::string base64Encode(const std::vector<uint8_t>& data);

    // Helpers
    std::int64_t mod(std::int64_t x, std::int64_t m) const;
    std::int64_t modInverse(std::int64_t a, std::int64_t m) const;
    std::int64_t randomScalar(std::int64_t min, std::int64_t max);
};
