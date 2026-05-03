cmake_minimum_required(VERSION 3.16)

project(ss2022_client
    VERSION 0.1.0
    DESCRIPTION "Buffer-oriented Shadowsocks 2022 client core library"
    LANGUAGES C CXX ASM)

include(GNUInstallDirs)

option(BUILD_SHARED_LIBS "Build shared libraries" OFF)
option(SS2022_BUILD_TESTS "Build libss2022-client tests" ON)
option(SS2022_ENABLE_SANITIZERS "Enable ASAN/UBSAN in Debug builds" OFF)
option(SS2022_USE_SYSTEM_WOLFSSL "Require wolfSSL from pkg-config instead of vendored fallback" OFF)
set(SS2022_TARGET_CFLAGS "" CACHE STRING "Compiler flags inherited from the top-level build")
set(SS2022_TARGET_MARCH "" CACHE STRING "Target -march value inherited from the top-level build")

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(SS2022_X86_PROCESSOR OFF)
set(SS2022_AMD64_PROCESSOR OFF)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|amd64)$")
    set(SS2022_X86_PROCESSOR ON)
    set(SS2022_AMD64_PROCESSOR ON)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(i[3-6]86|x86)$")
    set(SS2022_X86_PROCESSOR ON)
endif()

include(CheckCSourceCompiles)
set(SS2022_REQUIRED_FLAGS_SAVE "${CMAKE_REQUIRED_FLAGS}")
set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} ${SS2022_TARGET_CFLAGS}")

function(ss2022_check_c_macro output_var macro_name)
    check_c_source_compiles("
#ifndef ${macro_name}
#error ${macro_name} is not enabled
#endif
int main(void) { return 0; }
" ${output_var})
endfunction()

if(SS2022_X86_PROCESSOR)
    ss2022_check_c_macro(SS2022_HAVE_SSE2 __SSE2__)
    ss2022_check_c_macro(SS2022_HAVE_SSE41 __SSE4_1__)
    ss2022_check_c_macro(SS2022_HAVE_AVX2 __AVX2__)
    ss2022_check_c_macro(SS2022_HAVE_AVX512F __AVX512F__)
    ss2022_check_c_macro(SS2022_HAVE_AVX512VL __AVX512VL__)
    ss2022_check_c_macro(SS2022_HAVE_AES __AES__)
    ss2022_check_c_macro(SS2022_HAVE_PCLMUL __PCLMUL__)
else()
    set(SS2022_HAVE_SSE2 OFF)
    set(SS2022_HAVE_SSE41 OFF)
    set(SS2022_HAVE_AVX2 OFF)
    set(SS2022_HAVE_AVX512F OFF)
    set(SS2022_HAVE_AVX512VL OFF)
    set(SS2022_HAVE_AES OFF)
    set(SS2022_HAVE_PCLMUL OFF)
endif()
set(CMAKE_REQUIRED_FLAGS "${SS2022_REQUIRED_FLAGS_SAVE}")

set(SS2022_HAVE_AVX512 OFF)
if(SS2022_HAVE_AVX512F AND SS2022_HAVE_AVX512VL)
    set(SS2022_HAVE_AVX512 ON)
endif()

set(SS2022_WOLFSSL_AESNI OFF)
set(SS2022_WOLFSSL_INTELASM OFF)
if(SS2022_AMD64_PROCESSOR AND (SS2022_HAVE_AVX2 OR SS2022_HAVE_AVX512))
    set(SS2022_WOLFSSL_INTELASM ON)
endif()
if(SS2022_AMD64_PROCESSOR AND SS2022_HAVE_AES AND SS2022_HAVE_PCLMUL)
    set(SS2022_WOLFSSL_AESNI ON)
endif()

set(SS2022_BLAKE3_DEFINITIONS)
set(SS2022_BLAKE3_AMD64_SOURCES)
if(SS2022_AMD64_PROCESSOR)
    if(MSVC)
        set(SS2022_BLAKE3_PLATFORM_SUFFIX "windows_msvc.asm")
    elseif(WIN32 OR CYGWIN)
        set(SS2022_BLAKE3_PLATFORM_SUFFIX "windows_gnu.S")
    else()
        set(SS2022_BLAKE3_PLATFORM_SUFFIX "unix.S")
    endif()

    if(SS2022_HAVE_SSE2)
        list(APPEND SS2022_BLAKE3_AMD64_SOURCES "blake3_sse2_x86-64_${SS2022_BLAKE3_PLATFORM_SUFFIX}")
    else()
        list(APPEND SS2022_BLAKE3_DEFINITIONS BLAKE3_NO_SSE2)
    endif()
    if(SS2022_HAVE_SSE41)
        list(APPEND SS2022_BLAKE3_AMD64_SOURCES "blake3_sse41_x86-64_${SS2022_BLAKE3_PLATFORM_SUFFIX}")
    else()
        list(APPEND SS2022_BLAKE3_DEFINITIONS BLAKE3_NO_SSE41)
    endif()
    if(SS2022_HAVE_AVX2)
        list(APPEND SS2022_BLAKE3_AMD64_SOURCES "blake3_avx2_x86-64_${SS2022_BLAKE3_PLATFORM_SUFFIX}")
    else()
        list(APPEND SS2022_BLAKE3_DEFINITIONS BLAKE3_NO_AVX2)
    endif()
    if(SS2022_HAVE_AVX512)
        list(APPEND SS2022_BLAKE3_AMD64_SOURCES "blake3_avx512_x86-64_${SS2022_BLAKE3_PLATFORM_SUFFIX}")
    else()
        list(APPEND SS2022_BLAKE3_DEFINITIONS BLAKE3_NO_AVX512)
    endif()

    if(SS2022_BLAKE3_AMD64_SOURCES)
        set(BLAKE3_SIMD_TYPE "amd64-asm" CACHE STRING "" FORCE)
        set(BLAKE3_AMD64_ASM_SOURCES "${SS2022_BLAKE3_AMD64_SOURCES}" CACHE STRING "" FORCE)
    else()
        set(BLAKE3_SIMD_TYPE "none" CACHE STRING "" FORCE)
    endif()
endif()

message(STATUS "ss2022 target -march: ${SS2022_TARGET_MARCH}")
message(STATUS "ss2022 x86 features: SSE2=${SS2022_HAVE_SSE2} SSE4.1=${SS2022_HAVE_SSE41} AVX2=${SS2022_HAVE_AVX2} AVX512=${SS2022_HAVE_AVX512} AES=${SS2022_HAVE_AES} PCLMUL=${SS2022_HAVE_PCLMUL}")
message(STATUS "ss2022 wolfSSL acceleration: AESNI=${SS2022_WOLFSSL_AESNI} INTELASM=${SS2022_WOLFSSL_INTELASM}")

add_subdirectory(deps/BLAKE3/c EXCLUDE_FROM_ALL)
if(SS2022_AMD64_PROCESSOR)
    get_target_property(SS2022_BLAKE3_SOURCES blake3 SOURCES)
    set(SS2022_BLAKE3_ALL_AMD64_SOURCES
        "blake3_sse2_x86-64_${SS2022_BLAKE3_PLATFORM_SUFFIX}"
        "blake3_sse41_x86-64_${SS2022_BLAKE3_PLATFORM_SUFFIX}"
        "blake3_avx2_x86-64_${SS2022_BLAKE3_PLATFORM_SUFFIX}"
        "blake3_avx512_x86-64_${SS2022_BLAKE3_PLATFORM_SUFFIX}")
    foreach(SS2022_BLAKE3_SOURCE IN LISTS SS2022_BLAKE3_ALL_AMD64_SOURCES)
        if(NOT SS2022_BLAKE3_SOURCE IN_LIST SS2022_BLAKE3_AMD64_SOURCES)
            list(REMOVE_ITEM SS2022_BLAKE3_SOURCES "${SS2022_BLAKE3_SOURCE}")
        endif()
    endforeach()
    set_target_properties(blake3 PROPERTIES SOURCES "${SS2022_BLAKE3_SOURCES}")
endif()
if(SS2022_BLAKE3_DEFINITIONS)
    target_compile_definitions(blake3 PRIVATE ${SS2022_BLAKE3_DEFINITIONS})
endif()

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(WOLFSSL QUIET IMPORTED_TARGET wolfssl)
endif()

if(WOLFSSL_FOUND)
    set(SS2022_WOLFSSL_TARGET PkgConfig::WOLFSSL)
else()
    if(SS2022_USE_SYSTEM_WOLFSSL)
        message(FATAL_ERROR "wolfSSL was not found by pkg-config")
    endif()
    set(WOLFSSL_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/deps/wolfssl" CACHE PATH "" FORCE)
    set(WOLFSSL_CRYPT_ONLY "yes" CACHE STRING "" FORCE)
    set(WOLFSSL_AESCTR "yes" CACHE STRING "" FORCE)
    set(WOLFSSL_EXAMPLES "no" CACHE STRING "" FORCE)
    set(WOLFSSL_CRYPT_TESTS "no" CACHE STRING "" FORCE)
    if(SS2022_WOLFSSL_AESNI)
        set(WOLFSSL_AESNI "yes" CACHE STRING "" FORCE)
    endif()
    if(SS2022_WOLFSSL_INTELASM)
        set(WOLFSSL_INTEL_ASM "yes" CACHE STRING "" FORCE)
    endif()
    add_subdirectory(deps/wolfssl EXCLUDE_FROM_ALL)
    target_compile_definitions(wolfssl PRIVATE _POSIX_C_SOURCE=200809L WOLFSSL_AEAD_ONLY)
    if(SS2022_WOLFSSL_AESNI)
        target_compile_definitions(wolfssl PRIVATE WOLFSSL_AESNI)
    endif()
    if(SS2022_WOLFSSL_INTELASM)
        target_compile_definitions(wolfssl PRIVATE USE_INTEL_SPEEDUP)
    endif()
    set(SS2022_WOLFSSL_TARGET wolfssl::wolfssl)
endif()

set(SS2022_SOURCES
    src/ss2022_context.c
    src/ss2022_kdf_blake3.c
    src/crypto/ss2022_wolf_aead.c
    src/crypto/ss2022_wolf_aes.c
    src/crypto/ss2022_wolf_rng.c
    src/tcp/ss2022_tcp_client.c
    src/udp/ss2022_udp_client.c
    src/udp/ss2022_replay_window.c
    src/proto/ss2022_addr.c
    src/proto/ss2022_time.c
    src/util/ss2022_endian.c)

add_library(ss2022_client ${SS2022_SOURCES})
add_library(ss2022_client::ss2022_client ALIAS ss2022_client)
target_include_directories(ss2022_client
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(ss2022_client
    PRIVATE
        BLAKE3::blake3
        ${SS2022_WOLFSSL_TARGET})
target_compile_options(ss2022_client PRIVATE
    $<$<C_COMPILER_ID:GNU,Clang,AppleClang>:-Wall -Wextra -Wpedantic -Wconversion>)

if(SS2022_ENABLE_SANITIZERS AND CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(ss2022_client PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(ss2022_client PRIVATE -fsanitize=address,undefined)
endif()

configure_file(cmake/ss2022-client.pc.in ss2022-client.pc @ONLY)

install(TARGETS ss2022_client
    EXPORT ss2022_clientTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES include/ss2022_client.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/ss2022-client.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

if(SS2022_BUILD_TESTS)
    enable_testing()
    add_executable(ss2022_tests tests/test_basic.c)
    target_include_directories(ss2022_tests PRIVATE src include)
    target_link_libraries(ss2022_tests PRIVATE ss2022_client ${SS2022_WOLFSSL_TARGET})
    target_compile_options(ss2022_tests PRIVATE
        $<$<C_COMPILER_ID:GNU,Clang,AppleClang>:-Wall -Wextra -Wpedantic -Wconversion>)
    if(SS2022_ENABLE_SANITIZERS AND CMAKE_BUILD_TYPE STREQUAL "Debug")
        target_compile_options(ss2022_tests PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(ss2022_tests PRIVATE -fsanitize=address,undefined)
    endif()
    add_test(NAME ss2022_tests COMMAND ss2022_tests)
endif()
