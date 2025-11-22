cmake_minimum_required(VERSION 3.5)

project(AesAlgo CXX)

set(SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/AesAlgo.cpp)
set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_library(${PROJECT_NAME} ${SOURCE_FILES})

target_include_directories(${PROJECT_NAME} PUBLIC ${INCLUDE_DIR})
