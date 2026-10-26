// SPDX-License-Identifier: MIT
#include <catch2/catch_test_macros.hpp>

#include <wifi_analyze/capture.hpp>
#include <wifi_analyze/summary.hpp>

#include "test_support.hpp"

using namespace wifi_analyze;

TEST_CASE("anonymization removes identifying data and keeps structure", "[anonymize]") {
    const AnonymizeOptions options{.salt = 42, .keep_oui = true};
    for (const auto* name : {"wpa2-wpa3-5ghz-ax", "wpa3-6ghz-be-mlo", "wpa-wpa2-tkip-2ghz-wps",
                             "open-hotspot-owe-mbssid"}) {
        INFO(name);
        const auto original = test_support::capture(name);
        const auto anonymized = anonymize_ies(original, options);
        const auto a = decode(anonymized);
        const auto o = decode(original);
        REQUIRE(a.elements.size() == o.elements.size());
        for (std::size_t i = 0; i < a.elements.size(); ++i) {
            CHECK(a.elements[i].type == o.elements[i].type);
            CHECK(a.elements[i].status == o.elements[i].status);
        }
        const auto sa = summarize(a);
        const auto so = summarize(o);
        CHECK(sa.ssid != so.ssid);
        CHECK(sa.ssid.starts_with("ssid-"));
        CHECK(sa.security.type == so.security.type);
        CHECK(sa.phy.channel_width_mhz == so.phy.channel_width_mhz);
        CHECK(sa.device.manufacturer == so.device.manufacturer);
        if (!so.device.serial_number.empty()) {
            CHECK(sa.device.serial_number == "0");
            CHECK(sa.device.device_name != so.device.device_name);
        }
        // Deterministic for the same salt, different for another salt.
        CHECK(anonymize_ies(original, options) == anonymized);
        CHECK(anonymize_ies(original, {.salt = 43, .keep_oui = true}) != anonymized);
    }
}

TEST_CASE("anonymized MLD, RNR and OWE addresses", "[anonymize]") {
    const AnonymizeOptions options{.salt = 1, .keep_oui = false};
    const auto s =
        summarize(decode(anonymize_ies(test_support::capture("wpa3-6ghz-be-mlo"), options)));
    REQUIRE(s.mlo);
    CHECK(s.mlo->mld_mac != MacAddress{0x00, 0x11, 0x22, 0xaa, 0xbb, 0xcc});
    CHECK(((*s.mlo->mld_mac)[0] & 0x02U) != 0); // locally administered
    REQUIRE(s.neighbors.size() == 1);
    CHECK(s.neighbors[0].bssid != MacAddress{0x00, 0x11, 0x22, 0xaa, 0xbb, 0xcd});

    const auto ies =
        decode(anonymize_ies(test_support::capture("open-hotspot-owe-mbssid"), options));
    const auto* owe = ies.first<OweTransition>();
    REQUIRE(owe != nullptr);
    CHECK(owe->bssid != MacAddress{0x00, 0x11, 0x22, 0x33, 0x44, 0x66});
    CHECK(std::string(owe->ssid.begin(), owe->ssid.end()).starts_with("ssid-"));
}

TEST_CASE("hidden SSIDs and keep_oui", "[anonymize]") {
    CHECK(anonymize_ssid(std::vector<std::uint8_t>{}, {}).empty());
    CHECK(anonymize_ssid(std::vector<std::uint8_t>{0, 0, 0}, {}) ==
          std::vector<std::uint8_t>{0, 0, 0});
    const MacAddress mac{0x00, 0x50, 0xf2, 1, 2, 3};
    const auto kept = anonymize_mac(mac, {.salt = 7, .keep_oui = true});
    CHECK(kept[0] == 0x00);
    CHECK(kept[1] == 0x50);
    CHECK(kept[2] == 0xf2);
    CHECK(kept != mac);
}
