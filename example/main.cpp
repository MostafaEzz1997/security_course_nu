
#include <iostream>
#include <iomanip>

#include "EccKeyGenerator.hpp"

static void printHex(const std::string& label,
                     const std::vector<unsigned char>& data)
{
    std::cout << label << " (" << data.size() << " bytes): ";
    for (auto b : data) {
        std::cout << std::hex << std::setfill('0') << std::setw(2)
                  << static_cast<int>(b);
    }
    std::cout << std::dec << "\n";
}

int main() {
    try {
        // Generate a P-256 keypair (NID_X9_62_prime256v1)
        EccKeyGenerator gen(NID_X9_62_prime256v1);
        EccKeyPair kp = gen.generate();

        printHex("Private key",            kp.privateKey);
        printHex("Public key (compressed)",   kp.publicKeyCompressed);
        printHex("Public key (uncompressed)", kp.publicKeyUncompressed);
    }
    catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
    return 0;
}
