cmake_minimum_required(VERSION 3.5)

project(example CXX)

set(SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp)
set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../src/)

add_executable(${PROJECT_NAME} ${SOURCE_FILES})

target_include_directories(${PROJECT_NAME} PRIVATE ${INCLUDE_DIR})

target_link_libraries(${PROJECT_NAME} PRIVATE MD5)

