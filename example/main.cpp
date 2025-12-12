#include <iostream>
#include <iomanip>

#include "ToyECCKeygen.hpp"

int main() {
    ToyECC ecc;
    auto kp = ecc.generateKeyPair();

    std::cout << "Private key: " << kp.privateKey << "\n";
    std::cout << "Public key (compressed): " << kp.publicKey << "\n";
    // for (auto b : kp.publicKey) {
    //     std::cout << std::hex << std::setw(2) << std::setfill('0')
    //               << static_cast<int>(b) << " ";
    // }
    std::cout << std::dec << "\n";
}
