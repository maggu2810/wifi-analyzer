// SPDX-License-Identifier: MIT
// Element-level decoding edge cases.

#include <catch2/catch_test_macros.hpp>
#include <functional>

#include <wifi_analyze/i18n.hpp>
#include <wifi_analyze/ie.hpp>

#include "test_support.hpp"

using namespace wifi_analyze;
using test_support::hex;

namespace {

DecodedElement single(std::string_view ies_hex, const DecodeContext& ctx = {}) {
    auto ies = decode(hex(ies_hex), ctx);
    REQUIRE(ies.elements.size() == 1);
    return std::move(ies.elements.front());
}

} // namespace

TEST_CASE("SSID variants", "[elements]") {
    const auto hidden = single("0000");
    CHECK(std::get<Ssid>(hidden.value).hidden);
    const auto zeros = single("0003 000000");
    CHECK(std::get<Ssid>(zeros.value).hidden);
    const auto utf8 = single("0006 c3a46e64c3a4"); // "ändä"
    CHECK(std::get<std::string>(utf8.tree.children[0].value) == "ändä");
    const auto binary = single("0003 41ff5c");
    CHECK(std::get<std::string>(binary.tree.children[0].value) == "A\\xff\\\\");
    std::vector<std::uint8_t> long_ssid{0, 33};
    long_ssid.insert(long_ssid.end(), 33, 0x41);
    const auto too_long = decode(long_ssid);
    CHECK(test_support::has_diagnostic(too_long.elements[0].diagnostics, MessageId::ssid_too_long));
}

TEST_CASE("rates and BSS membership selectors", "[elements]") {
    const auto e = single("0104 82 0c ff fb");
    const auto& rates = std::get<SupportedRates>(e.value);
    REQUIRE(rates.rates.size() == 2);
    CHECK(rates.rates[0].basic);
    CHECK(rates.rates[0].units_500kbps == 2);
    CHECK(rates.membership_selectors == std::vector<std::uint8_t>{127, 123});
    CHECK(format_value(e.tree.children[0], Localizer{}) == "1 Mbit/s");
}

TEST_CASE("truncated RSN keeps the decoded part", "[elements]") {
    // AKM count says 2, only one suite present.
    const auto e = single("300e 0100 000fac04 0100 000fac04 0200");
    CHECK(e.status == DecodeStatus::malformed);
    const auto& rsn = std::get<Rsn>(e.value);
    CHECK(rsn.group_cipher->type == 4);
    CHECK(rsn.pairwise_ciphers.size() == 1);
    CHECK(rsn.akms.empty());
    CHECK(test_support::has_diagnostic(e.diagnostics, MessageId::decode_too_short));
}

TEST_CASE("unknown and named-only elements keep their data", "[elements]") {
    const auto unknown = single("fe02 aabb");
    CHECK(unknown.status == DecodeStatus::unknown);
    CHECK(unknown.type == "unknown");
    REQUIRE(unknown.tree.children.size() == 1);
    CHECK(std::get<std::vector<std::uint8_t>>(unknown.tree.children[0].value) ==
          std::vector<std::uint8_t>{0xaa, 0xbb});

    const auto named = single("3402 aabb"); // Neighbor Report: named, not decoded
    CHECK(named.status == DecodeStatus::unknown);
    CHECK(named.type == "neighbor_report");
    CHECK(named.name == MessageId::element_neighbor_report);

    const auto ext = single("ff03 7f 0102");
    CHECK(ext.type == "extension");
    CHECK(ext.key.ext_id == 0x7f);

    const auto vendor = single("dd05 001122 0102");
    CHECK(vendor.type == "vendor");
    CHECK(vendor.key.oui == Oui{0x00, 0x11, 0x22});
    CHECK(vendor.key.vendor_type == 0x01);
}

TEST_CASE("extra octets after known fields are reported", "[elements]") {
    const auto e = single("0302 24 ff");
    CHECK(e.status == DecodeStatus::ok);
    CHECK(test_support::has_diagnostic(e.diagnostics, MessageId::decode_trailing_data));
    CHECK(test_support::node(e.tree, MessageId::common_unparsed) != nullptr);
    // Decoder diagnostics carry stream-relative byte ranges.
    const auto& diag = e.diagnostics.back();
    REQUIRE(diag.bytes);
    CHECK(diag.bytes->offset == 3);
}

TEST_CASE("country with operating triplet", "[elements]") {
    const auto e = single("0706 555304 c98000");
    const auto& c = std::get<Country>(e.value);
    CHECK(c.code == "US");
    CHECK(c.environment == 4);
    CHECK(test_support::node(e.tree, MessageId::country_operating_triplet) != nullptr);
}

TEST_CASE("extended capabilities with unknown bits", "[elements]") {
    const auto e = single("7f0c 0000080000000000000000 80"); // bit 19 and bit 95
    const auto& caps = std::get<ExtendedCapabilities>(e.value);
    CHECK(caps.bss_transition());
    CHECK(caps.bit(95));
    CHECK(test_support::node(e.tree, MessageId::extcap_unknown_bit) != nullptr);
}

TEST_CASE("HT capabilities spatial streams", "[elements]") {
    const auto e = single("2d1a 6f00 17 ffffff00000000000000000000000000 0000 00000000 00");
    const auto& ht = std::get<HtCapabilities>(e.value);
    CHECK(ht.rx_spatial_streams() == 3);
    CHECK(ht.short_gi_20());
    CHECK(ht.short_gi_40());
    CHECK(ht.supports_40mhz());
}

TEST_CASE("nesting depth is limited", "[elements]") {
    // Multiple BSSID containing a profile that contains a Multiple BSSID ... (5 levels).
    std::vector<std::uint8_t> inner{0x00, 0x01, 0x41}; // SSID "A"
    for (int i = 0; i < 5; ++i) {
        std::vector<std::uint8_t> profile{0x00, static_cast<std::uint8_t>(inner.size())};
        profile.insert(profile.end(), inner.begin(), inner.end());
        std::vector<std::uint8_t> mbssid{71, static_cast<std::uint8_t>(profile.size() + 1), 0x01};
        mbssid.insert(mbssid.end(), profile.begin(), profile.end());
        inner = mbssid;
    }
    const auto ies = decode(inner);
    REQUIRE(ies.elements.size() == 1);
    CHECK(test_support::has_diagnostic(ies.elements[0].diagnostics, MessageId::decode_max_depth));
}

TEST_CASE("every element label and value can be rendered", "[elements]") {
    for (const auto* name : {"wpa2-wpa3-5ghz-ax", "wpa3-6ghz-be-mlo", "wpa-wpa2-tkip-2ghz-wps",
                             "open-hotspot-owe-mbssid"}) {
        const auto ies = decode(test_support::capture(name));
        for (const auto locale : available_locales()) {
            const auto loc = localizer(locale);
            std::function<void(const TreeNode&)> visit = [&](const TreeNode& n) {
                CHECK_FALSE(loc.text(n.label).empty());
                static_cast<void>(format_value(n, loc));
                for (const auto& c : n.children) {
                    visit(c);
                }
            };
            for (const auto& e : ies.elements) {
                visit(e.tree);
            }
        }
    }
}

TEST_CASE("known element registry", "[elements]") {
    const auto all = known_elements();
    CHECK(all.size() > 80);
    CHECK(std::ranges::count_if(all, &ElementInfo::decoded) > 50);
    for (const auto& info : all) {
        CHECK_FALSE(info.type.empty());
        CHECK_FALSE(info.spec_reference.empty());
    }
}
