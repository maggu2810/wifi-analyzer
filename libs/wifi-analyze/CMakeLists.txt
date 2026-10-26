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

# --- Generated sources (Python 3 is a build requirement) ---------------------------------
find_package(Python3 3.9 REQUIRED COMPONENTS Interpreter)
set(WIFI_ANALYZE_TOOLS_DIR "${CMAKE_CURRENT_LIST_DIR}/../../tools")

set(WIFI_ANALYZE_I18N_POT "${CMAKE_CURRENT_SOURCE_DIR}/i18n/messages.pot")
file(GLOB WIFI_ANALYZE_I18N_PO CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/i18n/*.po")
set(WIFI_ANALYZE_I18N_OUTPUTS
    "${WIFI_ANALYZE_GENERATED_DIR}/include/wifi_analyze/message_id.hpp"
    "${WIFI_ANALYZE_GENERATED_DIR}/i18n_catalog.inc")
add_custom_command(
    OUTPUT ${WIFI_ANALYZE_I18N_OUTPUTS}
    COMMAND Python3::Interpreter "${WIFI_ANALYZE_TOOLS_DIR}/gen_i18n_catalog.py"
        --pot "${WIFI_ANALYZE_I18N_POT}"
        --po ${WIFI_ANALYZE_I18N_PO}
        --out "${WIFI_ANALYZE_GENERATED_DIR}"
    DEPENDS "${WIFI_ANALYZE_TOOLS_DIR}/gen_i18n_catalog.py" "${WIFI_ANALYZE_I18N_POT}"
        ${WIFI_ANALYZE_I18N_PO}
    COMMENT "Generating i18n message catalogs"
    VERBATIM)

add_library(wifi_analyze
    src/core/tlv.cpp
    src/hex.cpp
    src/i18n/catalog.cpp
    src/version.cpp
    ${WIFI_ANALYZE_I18N_OUTPUTS}
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
        $<BUILD_INTERFACE:${WIFI_ANALYZE_GENERATED_DIR}/include>
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
