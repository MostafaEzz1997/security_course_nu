#include "MD5.hpp"
#include <iostream>
#include <cstring>
#include <string>

int main() {
    // Example 1: Hashing a simple string
    crypto::MD5 md5;
    std::string text = "Hello, World!";
    md5.update(reinterpret_cast<const unsigned char*>(text.c_str()), text.length());
    std::string hash = md5.hexdigest();

    std::cout << "MD5(\"" << text << "\") = " << hash << std::endl;

    // Example 2: Hashing a file or a larger data stream in chunks
    crypto::MD5 md5_file;
    // Simulating reading a file in chunks
    const char* chunk1 = "The quick brown fox ";
    const char* chunk2 = "jumps over the lazy dog";
    
    md5_file.update(reinterpret_cast<const unsigned char*>(chunk1), strlen(chunk1));
    md5_file.update(reinterpret_cast<const unsigned char*>(chunk2), strlen(chunk2));
    
    std::string file_hash = md5_file.hexdigest();
    std::cout << "MD5 of a stream = " << file_hash << std::endl;

    return 0;
}
