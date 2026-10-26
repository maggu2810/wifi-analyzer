// SPDX-License-Identifier: MIT
#include <algorithm>
#include <catch2/catch_test_macros.hpp>

#include <wifi_analyze/version.hpp>

TEST_CASE("version is a dotted triple", "[version]") {
    const auto v = wifi_analyze::version();
    REQUIRE_FALSE(v.empty());
    CHECK(std::ranges::count(v, '.') == 2);
}
