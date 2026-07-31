cmake_minimum_required(VERSION 3.21)

project(nsotools LANGUAGES C CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    add_compile_options(-fdiagnostics-color=always)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    add_compile_options(-fcolor-diagnostics)
endif()

set(LZ4_BUILD_CLI OFF CACHE INTERNAL "" FORCE)
set(ZSTD_BUILD_PROGRAMS OFF CACHE INTERNAL "" FORCE)
set(ZSTD_BUILD_SHARED OFF CACHE INTERNAL "" FORCE)
set(ZSTD_BUILD_STATIC ON CACHE INTERNAL "" FORCE)

add_subdirectory(lib/lz4/build/cmake/)
add_subdirectory(lib/zstd/build/cmake/)

add_executable(elf2nso elf2nso.cpp)

target_link_libraries(elf2nso PRIVATE lz4 libzstd)
target_include_directories(elf2nso PRIVATE lib/lz4/lib/ lib/zstd/lib/ lib/PicoSHA2/)