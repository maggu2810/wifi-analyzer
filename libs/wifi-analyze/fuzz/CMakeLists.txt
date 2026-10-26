# SPDX-License-Identifier: MIT
# libFuzzer targets. Configure with the "fuzz" preset (Clang); run via tools/run_fuzzers.sh.
if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "WIFI_BUILD_FUZZERS requires Clang (libFuzzer)")
endif()

foreach(name IN ITEMS split_elements parse_hex format_message)
    add_executable(fuzz_${name} fuzz_${name}.cpp)
    target_link_libraries(fuzz_${name} PRIVATE wifi_analyze::wifi_analyze)
    target_link_options(fuzz_${name} PRIVATE -fsanitize=fuzzer)
    wifi_set_warnings(fuzz_${name})
endforeach()
