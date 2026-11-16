# SPDX-License-Identifier: MIT
# Build identity from git (docs/decisions/0008-versioning-from-git.md).
#
# wifi_version_stamp(<target> PREFIX <tag prefix> VERSION <x.y.z> NAME <ns::constant> OUT <header>)
# Adds a custom target that runs tools/git_version.py on every build and writes <header>
# (inline constexpr std::string_view <ns::constant>) only when the stamp changed; <target>
# depends on it.
include_guard(GLOBAL)

function(wifi_version_stamp target)
    cmake_parse_arguments(PARSE_ARGV 1 arg "" "PREFIX;VERSION;NAME;OUT" "")
    set(tool "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../tools/git_version.py")
    find_package(Python3 3.9 REQUIRED COMPONENTS Interpreter)
    add_custom_target(${target}_version_stamp
        COMMAND Python3::Interpreter "${tool}"
            --prefix "${arg_PREFIX}" --version "${arg_VERSION}"
            --out "${arg_OUT}" --name "${arg_NAME}"
        BYPRODUCTS "${arg_OUT}"
        COMMENT "Version stamp ${arg_PREFIX}${arg_VERSION}"
        VERBATIM)
    add_dependencies(${target} ${target}_version_stamp)
endfunction()
