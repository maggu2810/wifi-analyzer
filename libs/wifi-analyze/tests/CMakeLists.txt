# SPDX-License-Identifier: MIT
include(Catch)

add_executable(wifi_analyze_tests
    test_byte_reader.cpp
    test_version.cpp
)
target_link_libraries(wifi_analyze_tests PRIVATE wifi_analyze::wifi_analyze Catch2::Catch2WithMain)
# Tests may exercise internal headers (src/) directly.
target_include_directories(wifi_analyze_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
    ${WIFI_ANALYZE_GENERATED_DIR})
wifi_set_warnings(wifi_analyze_tests)

catch_discover_tests(wifi_analyze_tests)
