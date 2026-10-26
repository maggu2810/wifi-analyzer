# SPDX-License-Identifier: MIT
include(Catch)

add_executable(wifi_analyze_cli_tests test_cli.cpp)
target_link_libraries(wifi_analyze_cli_tests PRIVATE
    wifi_analyze_cli_core nlohmann_json::nlohmann_json Catch2::Catch2WithMain)
target_compile_definitions(wifi_analyze_cli_tests PRIVATE
    WIFI_TESTDATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../../../testdata")
wifi_set_warnings(wifi_analyze_cli_tests)
catch_discover_tests(wifi_analyze_cli_tests)

# Smoke test of the real binary.
add_test(NAME cli.version COMMAND wifi-analyze-cli --version)
set_tests_properties(cli.version PROPERTIES PASS_REGULAR_EXPRESSION "^[0-9]+\\.[0-9]+\\.[0-9]+")
