set(SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp)

# Let's name the executable 'ecc_example'
add_executable(ecc_example ${SOURCE_FILES})

# Link against the ecc_lib. Because ecc_lib has a PUBLIC dependency on Boost
# and PUBLIC include directories, this one line is enough to configure everything.
target_link_libraries(ecc_example PRIVATE ecc_lib)
