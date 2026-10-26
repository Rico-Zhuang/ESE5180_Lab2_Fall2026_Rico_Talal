# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(lora_encrypted_client)

# Arduino Crypto library (sources included in ../Crypto)
set(CRYPTO_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../Crypto/src" CACHE PATH "Arduino Crypto library sources")

set(crypto_sources
  ${CRYPTO_DIR}/AES128.cpp
  ${CRYPTO_DIR}/AESCommon.cpp
  ${CRYPTO_DIR}/BigNumberUtil.cpp
  ${CRYPTO_DIR}/BlockCipher.cpp
  ${CRYPTO_DIR}/Crypto.cpp
  ${CRYPTO_DIR}/Curve25519.cpp
  ${CRYPTO_DIR}/Ed25519.cpp
  ${CRYPTO_DIR}/Hash.cpp
  ${CRYPTO_DIR}/SHA256.cpp
  ${CRYPTO_DIR}/SHA512.cpp)

# The library's own RNG.h needs Arduino; shim/RNG.h replaces it (included first)
set_source_files_properties(${crypto_sources} PROPERTIES
  COMPILE_OPTIONS "-include;${CMAKE_CURRENT_SOURCE_DIR}/shim/RNG.h")

FILE(GLOB app_sources src/*.c src/*.cpp)
target_sources(app PRIVATE ${app_sources} ${crypto_sources})
target_include_directories(app PRIVATE shim ${CRYPTO_DIR})

# Shared, host-testable protocol and Zephyr radio adapter.
set(SECURITY_COMMON "${CMAKE_CURRENT_SOURCE_DIR}/../LoRa_Security_Common")
if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/identity.h")
  message(FATAL_ERROR "Run python3 ../tools/provision.py before building both boards")
endif()
target_sources(app PRIVATE ${SECURITY_COMMON}/security_protocol.c ${SECURITY_COMMON}/lora_app.c)
target_include_directories(app PRIVATE src ${SECURITY_COMMON})
