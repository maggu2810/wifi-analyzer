# SPDX-License-Identifier: MIT
wifi_fetch_cli11()
wifi_fetch_nlohmann_json()

find_package(CURL QUIET)
option(WIFI_CLI_WITH_CURL "Enable 'oui update' (download via libcurl)" ${CURL_FOUND})

# Version of wifi-analyze-cli (SemVer, set at release / start of a development round; see
# AGENTS.md "Versioning"). Builds report it with their git identity (tools/git_version.py).
set(WIFI_CLI_VERSION "0.2.0")

add_library(wifi_analyze_cli_core STATIC
    src/app.cpp
    src/input.cpp
    src/oui_cache.cpp
    src/render.cpp
)
target_compile_features(wifi_analyze_cli_core PUBLIC cxx_std_23)
target_include_directories(wifi_analyze_cli_core PUBLIC src PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
include(WifiVersionStamp)
wifi_version_stamp(wifi_analyze_cli_core PREFIX cli-v VERSION "${WIFI_CLI_VERSION}"
    NAME wifi_analyze_cli::config::version_stamp OUT "${CMAKE_CURRENT_BINARY_DIR}/generated/cli_version_stamp.hpp")
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
