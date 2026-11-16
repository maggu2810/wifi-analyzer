// SPDX-License-Identifier: MIT
#include <algorithm>
#include <catch2/catch_test_macros.hpp>

#include <wifi_analyze/version.hpp>

TEST_CASE("version starts with a dotted triple", "[version]") {
    // "X.Y.Z" (release), "X.Y.Z-dev.N+gHASH[.dirty]", "X.Y.Z-dev+gHASH[.dirty]", "X.Y.Z+nogit"
    const auto v = wifi_analyze::version();
    const auto core = v.substr(0, v.find_first_of("-+"));
    REQUIRE_FALSE(core.empty());
    CHECK(std::ranges::count(core, '.') == 2);
    CHECK(std::ranges::all_of(core, [](char c) { return c == '.' || (c >= '0' && c <= '9'); }));
}
