# SPDX-License-Identifier: MIT

include_guard(GLOBAL)

# Applies the project warning set to a target (PRIVATE, so consumers are not affected).
function(wifi_set_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4)
        if(WIFI_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE /WX)
        endif()
        return()
    endif()

    target_compile_options(${target} PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
        -Wshadow
        -Wnon-virtual-dtor
        -Wold-style-cast
        -Wcast-align
        -Woverloaded-virtual
        -Wnull-dereference
        -Wdouble-promotion
        -Wformat=2
        -Wimplicit-fallthrough
        -Wundef)
    if(WIFI_WARNINGS_AS_ERRORS)
        target_compile_options(${target} PRIVATE -Werror)
    endif()
endfunction()
