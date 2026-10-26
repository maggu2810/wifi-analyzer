# SPDX-License-Identifier: MIT
#
# Third-party dependencies for tests and apps. Never linked into libwifianalyze itself.
# A system package is preferred when available (FIND_PACKAGE_ARGS), otherwise the pinned
# version is fetched.

include_guard(GLOBAL)
include(FetchContent)

function(wifi_fetch_catch2)
    if(TARGET Catch2::Catch2WithMain)
        return()
    endif()
    FetchContent_Declare(Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v3.9.1
        GIT_SHALLOW TRUE
        SYSTEM
        FIND_PACKAGE_ARGS 3)
    FetchContent_MakeAvailable(Catch2)
    if(DEFINED catch2_SOURCE_DIR)
        list(APPEND CMAKE_MODULE_PATH "${catch2_SOURCE_DIR}/extras")
        set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH}" PARENT_SCOPE)
    endif()
endfunction()
