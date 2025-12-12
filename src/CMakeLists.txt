set(SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/ToyECCKeygen.cpp)

# Define the library target. Let's name it 'ecc_lib' to be explicit.
add_library(ecc_lib ${SOURCE_FILES})

# Make the header files in the current source directory available to any
# target that links against this library (like your executable in 'example').
target_include_directories(ecc_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Link the ECC library against OpenSSL's crypto library.
target_link_libraries(ecc_lib PUBLIC OpenSSL::Crypto)
