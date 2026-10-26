# SPDX-License-Identifier: MIT
cmake_minimum_required(VERSION 3.31...4.3)

# Usable standalone (e.g. add_subdirectory from the Android build) or as part of the repo.
if(PROJECT_IS_TOP_LEVEL OR NOT DEFINED PROJECT_NAME)
    project(wifi-analyze VERSION 0.1.0 LANGUAGES CXX)
    option(WIFI_BUILD_TESTS "Build unit tests" OFF)
    option(WIFI_BUILD_FUZZERS "Build libFuzzer targets (Clang only)" OFF)
    option(WIFI_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)
endif()

set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/../../cmake")
include(WifiWarnings)

set(WIFI_ANALYZE_VERSION "${PROJECT_VERSION}")
set(WIFI_ANALYZE_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")

configure_file(src/version.hpp.in "${WIFI_ANALYZE_GENERATED_DIR}/version_config.hpp" @ONLY)

add_library(wifi_analyze
    src/version.cpp
)
add_library(wifi_analyze::wifi_analyze ALIAS wifi_analyze)

target_compile_features(wifi_analyze PUBLIC cxx_std_23)
set_target_properties(wifi_analyze PROPERTIES
    CXX_EXTENSIONS OFF
    OUTPUT_NAME wifianalyze
    POSITION_INDEPENDENT_CODE ON)
target_include_directories(wifi_analyze
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${WIFI_ANALYZE_GENERATED_DIR})
wifi_set_warnings(wifi_analyze)

if(WIFI_BUILD_TESTS)
    add_subdirectory(tests)
endif()

if(WIFI_BUILD_FUZZERS)
    add_subdirectory(fuzz)
endif()
