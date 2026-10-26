// SPDX-License-Identifier: MIT
// Golden JSON tests: decoded output of each capture must match testdata/golden/<name>.json.
// After an intentional change, regenerate with: WIFI_UPDATE_GOLDEN=1 ctest -R golden
// and review the diff.

#include <catch2/catch_test_macros.hpp>
#include <cstdlib>
#include <fstream>

#include <wifi_analyze/json.hpp>

#include "test_support.hpp"

using namespace wifi_analyze;

TEST_CASE("golden JSON output", "[golden]") {
    const bool update = std::getenv("WIFI_UPDATE_GOLDEN") != nullptr;
    for (const std::string name : {"wpa2-wpa3-5ghz-ax", "wpa3-6ghz-be-mlo",
                                   "wpa-wpa2-tkip-2ghz-wps", "open-hotspot-owe-mbssid"}) {
        INFO(name);
        const auto ies = decode(test_support::capture(name));
        const auto json =
            to_json(ies, summarize(ies), Localizer{}, JsonOptions{.pretty = true}) + "\n";
        const auto path = test_support::testdata("golden/" + name + ".json");
        if (update) {
            std::ofstream{path, std::ios::binary} << json;
            continue;
        }
        const auto expected = test_support::read_file(path);
        CHECK(json == expected);
    }
}
