# SPDX-License-Identifier: MIT
cmake_minimum_required(VERSION 3.31...4.3)

project(wifi-analyzer
    VERSION 0.1.0
    DESCRIPTION "WiFi analysis tools: IEEE 802.11 IE decoding library, CLI and Android app"
    LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

option(WIFI_BUILD_TESTS "Build unit tests" ON)
option(WIFI_BUILD_CLI "Build the wifi-analyze-cli command line tool" ON)
option(WIFI_BUILD_FUZZERS "Build libFuzzer targets (Clang only)" OFF)
option(WIFI_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_EXTENSIONS OFF)
# No C++20 modules in use; skip dependency scanning.
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

include(WifiDependencies)
if(WIFI_BUILD_TESTS)
    enable_testing()
    wifi_fetch_catch2()
endif()

add_subdirectory(libs/wifi-analyze)

if(WIFI_BUILD_CLI)
    add_subdirectory(apps/cli)
endif()
