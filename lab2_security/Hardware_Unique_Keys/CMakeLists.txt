# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.28.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(Hardware_Unique_Keys)

option(LAB3_PLAINTEXT "Store the AppKey without encryption for Part 3.1" OFF)
target_compile_definitions(app PRIVATE LAB3_PLAINTEXT=$<BOOL:${LAB3_PLAINTEXT}>)

target_sources(app PRIVATE src/main.c)
