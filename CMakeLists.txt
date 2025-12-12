cmake_minimum_required(VERSION 3.5)
project(ECCProject)

# Find OpenSSL at the top level. This makes it available to all subdirectories.
find_package(OpenSSL REQUIRED)

add_subdirectory(src)
add_subdirectory(example)
