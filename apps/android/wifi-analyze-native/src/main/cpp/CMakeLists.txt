# SPDX-License-Identifier: MIT
cmake_minimum_required(VERSION 3.31...4.3)
project(wifi_analyze_jni LANGUAGES CXX)

# The shared library sources live in the repository root.
add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/../../../../../../libs/wifi-analyze" wifi-analyze)

add_library(wifi_analyze_jni SHARED jni_bridge.cpp)
target_link_libraries(wifi_analyze_jni PRIVATE wifi_analyze::wifi_analyze log)
target_compile_features(wifi_analyze_jni PRIVATE cxx_std_23)
wifi_set_warnings(wifi_analyze_jni)
# 16 KB page size support (required for new apps targeting recent Android versions).
target_link_options(wifi_analyze_jni PRIVATE "-Wl,-z,max-page-size=16384")
