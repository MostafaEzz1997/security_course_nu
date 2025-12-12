#include <random>
#include <stdexcept>
#include <iostream>

#include "ToyECCKeygen.hpp"

// ---------------- Constructor ----------------
ToyECC::ToyECC(std::int64_t p,
               std::int64_t a,
               std::int64_t b,
               std::int64_t n,
               std::int64_t gx,
               std::int64_t gy)
    : P(p), A(a), B(b), N(n), Gx(gx), Gy(gy) {}

// ---------------- Point ctor ----------------
ToyECC::Point::Point(std::int64_t x_, std::int64_t y_, bool inf)
    : x(x_), y(y_), infinity(inf) {}

// ---------------- Public API ----------------
ToyECC::KeyPair ToyECC::generateKeyPair() {
    std::int64_t d = randomScalar(1, N - 1);
    Point Q = scalarMultiply(d, basePoint());

    KeyPair kp;
    kp.privateKey = d;
    kp.publicKey  = base64Encode(encodePointCompressed(Q));
    return kp;
}

// ---------------- Base point ----------------
ToyECC::Point ToyECC::basePoint() const {
    return Point(Gx, Gy, false);
}

ToyECC::Point ToyECC::infinity() const {
    return Point(0, 0, true);
}

// ---------------- ECC arithmetic ----------------
ToyECC::Point ToyECC::scalarMultiply(std::int64_t k, const Point& P0) {
    if (k % N == 0 || P0.infinity) {
        return infinity();
    }

    Point result = infinity();
    Point addend = P0;
    std::int64_t kk = mod(k, N);

    while (kk > 0) {
        if (kk & 1) {
            result = pointAdd(result, addend);
        }
        addend = pointDouble(addend);
        kk >>= 1;
    }
    return result;
}

ToyECC::Point ToyECC::pointAdd(const Point& P1, const Point& P2) {

    // If the first point is the point at infinity (identity element),
    // return the second point:  ∞ + P2 = P2
    if (P1.infinity) 
        return P2;

    // If the second point is the point at infinity,
    // return the first point:  P1 + ∞ = P1
    if (P2.infinity) 
        return P1;

    // Check if P2 is the inverse of P1.
    // This happens when:
    //   x1 == x2  AND  y1 + y2 ≡ 0 (mod P)
    // In this case, the line between them is vertical
    // and the result is the point at infinity.
    if (P1.x == P2.x && mod(P1.y + P2.y, P) == 0) {
        return infinity();
    }

    // Slope of the line (lambda) used in point addition formula
    std::int64_t lambda;

    // If the two points are identical, we are performing point doubling:
    //   P1 + P1 = 2P1
    // This uses a different formula (tangent line),
    // so delegate to pointDouble().
    if (P1.x == P2.x && P1.y == P2.y) {
        return pointDouble(P1);
    } 
    else {
        // Compute numerator of slope:
        //   y2 - y1 (mod P)
        std::int64_t num = mod(P2.y - P1.y, P);

        // Compute denominator of slope:
        //   x2 - x1 (mod P)
        std::int64_t den = mod(P2.x - P1.x, P);

        // Compute slope:
        //   lambda = (y2 - y1) / (x2 - x1) (mod P)
        // Division modulo P is done by multiplying with the modular inverse
        lambda = mod(num * modInverse(den, P), P);
    }

    // Compute x-coordinate of the resulting point:
    //   x3 = lambda^2 - x1 - x2 (mod P)
    std::int64_t x3 = mod(lambda * lambda - P1.x - P2.x, P);

    // Compute y-coordinate of the resulting point:
    //   y3 = lambda * (x1 - x3) - y1 (mod P)
    std::int64_t y3 = mod(lambda * (P1.x - x3) - P1.y, P);

    // Return the resulting point P3 = (x3, y3)
    return Point(x3, y3, false);
}


ToyECC::Point ToyECC::pointDouble(const Point& P1) {

    // If P1 is the point at infinity, then:
    //   2 * ∞ = ∞
    //
    // If y == 0, the tangent at P1 is vertical.
    // A vertical line intersects the curve at infinity,
    // so the result of doubling is the point at infinity.
    if (P1.infinity || P1.y == 0) {
        return infinity();
    }

    // Compute the numerator of the slope (lambda) for point doubling:
    //   3*x1^2 + A   (mod P)
    //
    // This comes from the derivative of the curve equation
    // y^2 = x^3 + A*x + B
    std::int64_t num = mod(3 * P1.x * P1.x + A, P);

    // Compute the denominator of the slope:
    //   2*y1   (mod P)
    //
    // This corresponds to the derivative of y^2
    std::int64_t den = mod(2 * P1.y, P);

    // Compute the slope (lambda) of the tangent line at P1:
    //   lambda = (3*x1^2 + A) / (2*y1)  (mod P)
    //
    // Division modulo P is performed by multiplying with
    // the modular inverse of the denominator
    std::int64_t lambda = mod(num * modInverse(den, P), P);

    // Compute the x-coordinate of the doubled point:
    //   x3 = lambda^2 - 2*x1   (mod P)
    std::int64_t x3 = mod(lambda * lambda - 2 * P1.x, P);

    // Compute the y-coordinate of the doubled point:
    //   y3 = lambda * (x1 - x3) - y1   (mod P)
    std::int64_t y3 = mod(lambda * (P1.x - x3) - P1.y, P);

    // Return the resulting point:
    //   P3 = 2 * P1 = (x3, y3)
    return Point(x3, y3, false);
}


// ---------------- Encoding ----------------
std::vector<std::uint8_t> ToyECC::encodePointCompressed(const Point& P1) {
    if (P1.infinity) {
        throw std::runtime_error("Cannot encode point at infinity");
    }

    std::cout << "Encoding point (" << P1.x << ", " << P1.y << ")\n";

    std::uint8_t prefix = (P1.y % 2 == 0) ? 0x02 : 0x03;
    return {
        prefix,
        static_cast<std::uint8_t>(P1.x)
    };
}

std::string ToyECC::base64Encode(const std::vector<uint8_t>& data)
{
    static const char* table =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string out;
    size_t i = 0;

    while (i < data.size()) {
        uint32_t v = data[i++] << 16;
        if (i < data.size()) v |= data[i++] << 8;
        if (i < data.size()) v |= data[i++];

        out.push_back(table[(v >> 18) & 0x3F]);
        out.push_back(table[(v >> 12) & 0x3F]);
        out.push_back((i - 1 < data.size()) ? table[(v >> 6) & 0x3F] : '=');
        out.push_back((i < data.size())     ? table[v & 0x3F]        : '=');
    }
    return out;
}


// ---------------- Helpers ----------------
std::int64_t ToyECC::mod(std::int64_t x, std::int64_t m) const {
    std::int64_t r = x % m;
    return (r < 0) ? r + m : r;
}

std::int64_t ToyECC::modInverse(std::int64_t a, std::int64_t m) const {
    std::int64_t t = 0, newt = 1;
    std::int64_t r = m, newr = mod(a, m);

    while (newr != 0) {
        std::int64_t q = r / newr;

        std::int64_t tmp = newt;
        newt = t - q * newt;
        t = tmp;

        tmp = newr;
        newr = r - q * newr;
        r = tmp;
    }

    if (r > 1) {
        throw std::runtime_error("No modular inverse");
    }
    if (t < 0) t += m;
    return t;
}

std::int64_t ToyECC::randomScalar(std::int64_t min, std::int64_t max) {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    std::uniform_int_distribution<std::int64_t> dist(min, max);
    return dist(gen);
}
