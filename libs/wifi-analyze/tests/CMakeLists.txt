# SPDX-License-Identifier: MIT
include(Catch)

add_executable(wifi_analyze_tests
    test_byte_reader.cpp
    test_elements.cpp
    test_golden.cpp
    test_hex.cpp
    test_i18n.cpp
    test_phy_channel_oui.cpp
    test_summary.cpp
    test_tlv.cpp
    test_version.cpp
)
target_link_libraries(wifi_analyze_tests PRIVATE wifi_analyze::wifi_analyze Catch2::Catch2WithMain)
# Tests may exercise internal headers (src/) directly.
target_include_directories(wifi_analyze_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
    ${WIFI_ANALYZE_GENERATED_DIR})
target_compile_definitions(wifi_analyze_tests PRIVATE
    WIFI_TESTDATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../../../testdata")
wifi_set_warnings(wifi_analyze_tests)

catch_discover_tests(wifi_analyze_tests)

add_test(NAME tools.gen_i18n_catalog
    COMMAND Python3::Interpreter -m unittest discover -s "${WIFI_ANALYZE_TOOLS_DIR}/tests" -v)

add_test(NAME golden.json_valid
    COMMAND Python3::Interpreter "${WIFI_ANALYZE_TOOLS_DIR}/check_json.py"
        "${CMAKE_CURRENT_SOURCE_DIR}/../../../testdata/golden")
