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

if (MSVC)
    set(WARNING_FLAGS /W4 /wd4244 /wd4127)
else()
    set(WARNING_FLAGS -Wall -Wextra -Werror)
endif()

set(LZ4_BUILD_CLI OFF CACHE INTERNAL "" FORCE)
set(ZSTD_BUILD_PROGRAMS OFF CACHE INTERNAL "" FORCE)
set(ZSTD_BUILD_SHARED OFF CACHE INTERNAL "" FORCE)
set(ZSTD_BUILD_STATIC ON CACHE INTERNAL "" FORCE)

add_subdirectory(lib/lz4/build/cmake/)
add_subdirectory(lib/zstd/build/cmake/)

add_library(nxo STATIC nxo.cpp nxo_elf.cpp)
target_link_libraries(nxo PRIVATE lz4 libzstd)
target_include_directories(nxo PRIVATE lib/lz4/lib/ lib/zstd/lib/ lib/PicoSHA2/)

add_executable(elf2nso elf2nso.cpp)
target_link_libraries(elf2nso PRIVATE nxo)

add_executable(nso2elf nso2elf.cpp)
target_link_libraries(nso2elf PRIVATE nxo)

add_executable(nso2nso nso2nso.cpp)
target_link_libraries(nso2nso PRIVATE nxo)

add_executable(elf2nro elf2nro.cpp)
target_link_libraries(elf2nro PRIVATE nxo)

add_executable(nro2elf nro2elf.cpp)
target_link_libraries(nro2elf PRIVATE nxo)

target_compile_options(elf2nso PRIVATE ${WARNING_FLAGS})
target_compile_options(nso2elf PRIVATE ${WARNING_FLAGS})
target_compile_options(nso2nso PRIVATE ${WARNING_FLAGS})
target_compile_options(elf2nro PRIVATE ${WARNING_FLAGS})
target_compile_options(nro2elf PRIVATE ${WARNING_FLAGS})