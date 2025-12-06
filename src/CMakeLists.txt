cmake_minimum_required(VERSION 3.5)

project(RsaAlgo CXX)

find_package(OpenSSL REQUIRED)

set(SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/RsaAlgo.cpp)

add_library(${PROJECT_NAME} ${SOURCE_FILES})

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(${PROJECT_NAME} PUBLIC OpenSSL::Crypto)
