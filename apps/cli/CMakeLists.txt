# SPDX-License-Identifier: MIT
wifi_fetch_cli11()
wifi_fetch_nlohmann_json()

find_package(CURL QUIET)
option(WIFI_CLI_WITH_CURL "Enable 'oui update' (download via libcurl)" ${CURL_FOUND})

add_library(wifi_analyze_cli_core STATIC
    src/app.cpp
    src/input.cpp
    src/oui_cache.cpp
    src/render.cpp
)
target_compile_features(wifi_analyze_cli_core PUBLIC cxx_std_23)
target_include_directories(wifi_analyze_cli_core PUBLIC src)
target_link_libraries(wifi_analyze_cli_core
    PUBLIC wifi_analyze::wifi_analyze
    PRIVATE CLI11::CLI11 nlohmann_json::nlohmann_json)
if(WIFI_CLI_WITH_CURL)
    find_package(CURL REQUIRED)
    target_compile_definitions(wifi_analyze_cli_core PRIVATE WIFI_CLI_WITH_CURL)
    target_link_libraries(wifi_analyze_cli_core PRIVATE CURL::libcurl)
endif()
wifi_set_warnings(wifi_analyze_cli_core)

add_executable(wifi-analyze-cli src/main.cpp)
target_link_libraries(wifi-analyze-cli PRIVATE wifi_analyze_cli_core)
wifi_set_warnings(wifi-analyze-cli)
install(TARGETS wifi-analyze-cli RUNTIME DESTINATION bin)

if(WIFI_BUILD_TESTS)
    add_subdirectory(tests)
endif()
