// SPDX-License-Identifier: MIT
// Summary tests on the synthetic captures (testdata/captures/synthetic/README.md).

#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>

#include <wifi_analyze/i18n.hpp>
#include <wifi_analyze/summary.hpp>

#include "test_support.hpp"

using namespace wifi_analyze;
using test_support::capture;

TEST_CASE("5 GHz WPA2/WPA3 transition, Wi-Fi 6", "[summary]") {
    const auto ies = decode(capture("wpa2-wpa3-5ghz-ax"));
    for (const auto& e : ies.elements) {
        INFO(e.type);
        CHECK(e.status == DecodeStatus::ok);
        CHECK(e.diagnostics.empty());
    }
    const auto s = summarize(ies);
    CHECK(s.ssid == "HomeNet");
    CHECK_FALSE(s.hidden);
    CHECK(s.security.type == SecurityType::wpa2_wpa3_personal);
    CHECK(s.security.pmf == Pmf::capable);
    CHECK(s.security.sae_hash_to_element);
    CHECK_FALSE(s.security.weak);
    CHECK(s.phy.generation == 6);
    CHECK(generation_name(s.phy) == "Wi-Fi 6");
    CHECK(s.phy.band == Band::ghz_5);
    CHECK(s.phy.primary_channel == 36);
    CHECK(s.phy.primary_frequency_mhz == 5180);
    CHECK(s.phy.channel_width_mhz == 80);
    CHECK(s.phy.center_frequencies_mhz == std::vector<std::uint32_t>{5210});
    CHECK(s.phy.max_spatial_streams == 2);
    REQUIRE(s.phy.max_rate_mbps);
    CHECK(*s.phy.max_rate_mbps == Catch::Approx(1201.0));
    CHECK(s.phy.standards ==
          std::vector{PhyStandard::a, PhyStandard::n, PhyStandard::ac, PhyStandard::ax});
    REQUIRE(s.bss_load);
    CHECK(s.bss_load->station_count == 3);
    CHECK(s.country == "DE");
    CHECK(s.roaming.k);
    CHECK(s.roaming.v);
    CHECK_FALSE(s.roaming.r);
    CHECK(s.wmm);
    CHECK(s.uapsd);
    CHECK(s.bss_color == 42);
    CHECK(s.problem_count == 0);
}

TEST_CASE("frequency from context takes precedence", "[summary]") {
    DecodeContext ctx;
    ctx.frequency_mhz = 5180;
    const auto s = summarize(decode(capture("wpa2-wpa3-5ghz-ax"), ctx), ctx);
    CHECK(s.phy.primary_channel == 36);
    CHECK(s.phy.band == Band::ghz_5);
}

TEST_CASE("6 GHz Wi-Fi 7 with MLO, puncturing and RNR", "[summary]") {
    const auto ies = decode(capture("wpa3-6ghz-be-mlo"));
    for (const auto& e : ies.elements) {
        INFO(e.type);
        CHECK(e.status == DecodeStatus::ok);
    }
    const auto s = summarize(ies);
    CHECK(s.security.type == SecurityType::wpa3_personal);
    CHECK(s.security.pmf == Pmf::required);
    REQUIRE(s.security.group_management_cipher);
    CHECK(s.security.group_management_cipher->type == 6);
    CHECK(s.phy.generation == 7);
    CHECK(s.phy.band == Band::ghz_6);
    CHECK(s.phy.primary_channel == 5);
    CHECK(s.phy.primary_frequency_mhz == 5975);
    CHECK(s.phy.channel_width_mhz == 320);
    CHECK(s.phy.center_frequencies_mhz == std::vector<std::uint32_t>{6105});
    CHECK(s.phy.punctured_subchannels == 0x0010);
    CHECK(s.phy.max_spatial_streams == 2);
    CHECK(*s.phy.max_rate_mbps == Catch::Approx(5764.7));
    REQUIRE(s.mlo);
    CHECK(s.mlo->mld_mac == MacAddress{0x00, 0x11, 0x22, 0xaa, 0xbb, 0xcc});
    CHECK(s.mlo->link_id == 1);
    CHECK(s.mlo->max_simultaneous_links == 1); // as transmitted: 2 links
    REQUIRE(s.neighbors.size() == 1);
    CHECK(s.neighbors[0].band == Band::ghz_5);
    CHECK(s.neighbors[0].channel == 36);
    CHECK(s.neighbors[0].same_ssid);
    CHECK(s.neighbors[0].co_located);
    CHECK(s.twt_responder);
    CHECK(s.bss_color == 21);
}

TEST_CASE("2.4 GHz WPA/WPA2 mixed with TKIP and WPS", "[summary]") {
    const auto ies = decode(capture("wpa-wpa2-tkip-2ghz-wps"));
    const auto s = summarize(ies);
    CHECK(s.security.type == SecurityType::wpa_wpa2_personal);
    CHECK(s.security.wpa1);
    CHECK(s.security.weak);
    CHECK(s.security.pmf == Pmf::disabled);
    CHECK(s.phy.generation == 4);
    CHECK(s.phy.band == Band::ghz_2_4);
    CHECK(s.phy.primary_channel == 6);
    CHECK(s.phy.channel_width_mhz == 20);
    CHECK(s.phy.standards == std::vector{PhyStandard::b, PhyStandard::g, PhyStandard::n});
    CHECK(*s.phy.max_rate_mbps == Catch::Approx(72.2));
    CHECK(s.device.manufacturer == "ACME Inc");
    CHECK(s.device.model_name == "Router1");
    CHECK(s.device.model_number == "R-1");
    CHECK(s.device.device_name == "ACME-R100");
    CHECK(s.device.serial_number == "1234");

    const auto* wps = ies.first<Wps>();
    REQUIRE(wps != nullptr);
    CHECK(wps->state == 2);
    CHECK(wps->version2 == 0x20);
    CHECK(wps->config_methods == 0x2008);
    CHECK(wps->primary_device_category == 6);
    const auto* rsn = test_support::find(ies, "rsn");
    REQUIRE(rsn != nullptr);
    CHECK(test_support::has_diagnostic(rsn->diagnostics, MessageId::rsn_weak_cipher));
}

TEST_CASE("open hotspot with OWE transition and Multiple BSSID", "[summary]") {
    const auto ies = decode(capture("open-hotspot-owe-mbssid"));
    const auto s = summarize(ies);
    CHECK(s.security.type == SecurityType::enhanced_open_transition);
    CHECK(s.nontransmitted_bssids == 1);
    CHECK(s.access_network_type == 3);
    CHECK(s.internet == true);
    CHECK(s.hotspot20_release == 3);
    CHECK(generation_name(s.phy) == "802.11g");

    const auto* owe = ies.first<OweTransition>();
    REQUIRE(owe != nullptr);
    CHECK(std::string(owe->ssid.begin(), owe->ssid.end()) == "CityOWE1");
    CHECK(owe->operating_class == 81);
    CHECK(owe->channel == 11);

    // The nontransmitted profile is decoded recursively.
    const auto* mbssid = test_support::find(ies, "multiple_bssid");
    REQUIRE(mbssid != nullptr);
    const auto* profile = test_support::node(mbssid->tree, MessageId::mbssid_profile);
    REQUIRE(profile != nullptr);
    CHECK(test_support::node(*profile, MessageId::element_rsn) != nullptr);
    const auto* nested_ssid = test_support::node(*profile, MessageId::ssid_name);
    REQUIRE(nested_ssid != nullptr);
    CHECK(std::get<std::string>(nested_ssid->value) == "Guest2");
    // Nested byte ranges are relative to the outer element content.
    REQUIRE(nested_ssid->bytes);
    const auto& content = mbssid->content();
    CHECK(std::string(content.begin() + static_cast<std::ptrdiff_t>(nested_ssid->bytes->offset),
                      content.begin() + static_cast<std::ptrdiff_t>(nested_ssid->bytes->end())) ==
          "Guest2");
}

TEST_CASE("security classification without RSN", "[summary]") {
    const auto ssid_only = test_support::hex("0004 74657374");
    CHECK(summarize(decode(ssid_only)).security.type == SecurityType::open_or_wep);
    DecodeContext privacy;
    privacy.privacy = true;
    CHECK(summarize(decode(ssid_only), privacy).security.type == SecurityType::wep);
    privacy.privacy = false;
    CHECK(summarize(decode(ssid_only), privacy).security.type == SecurityType::open);
}

TEST_CASE("security classification of RSN variants", "[summary]") {
    auto classify = [](std::string_view rsn_body) {
        const auto body = test_support::hex(rsn_body);
        std::vector<std::uint8_t> ies{48, static_cast<std::uint8_t>(body.size())};
        ies.insert(ies.end(), body.begin(), body.end());
        return summarize(decode(ies)).security.type;
    };
    // OWE
    CHECK(classify("0100 000fac04 0100 000fac04 0100 000fac12 c000") ==
          SecurityType::enhanced_open);
    // 802.1X, no PMF
    CHECK(classify("0100 000fac04 0100 000fac04 0100 000fac01 0000") ==
          SecurityType::wpa2_enterprise);
    // 802.1X + 802.1X-SHA-256, PMF capable
    CHECK(classify("0100 000fac04 0100 000fac04 0200 000fac01 000fac05 8000") ==
          SecurityType::wpa2_wpa3_enterprise);
    // 802.1X-SHA-256 with PMF required
    CHECK(classify("0100 000fac04 0100 000fac04 0100 000fac05 c000") ==
          SecurityType::wpa3_enterprise);
    // Suite B 192
    CHECK(classify("0100 000fac09 0100 000fac09 0100 000fac0c c000") ==
          SecurityType::wpa3_enterprise_192);
    // Only version: defaults to CCMP/802.1X
    CHECK(classify("0100") == SecurityType::wpa2_enterprise);
    // DPP only
    CHECK(classify("0100 000fac04 0100 000fac04 0100 506f9a02 c000") == SecurityType::other);
}

TEST_CASE("summary overview renders in every locale", "[summary]") {
    const auto s = summarize(decode(capture("wpa2-wpa3-5ghz-ax")));
    const auto overview = describe(s);
    REQUIRE_FALSE(overview.children.empty());
    const auto* security = test_support::node(overview, MessageId::summary_security);
    REQUIRE(security != nullptr);
    CHECK(format_value(*security, Localizer{}) == "WPA2/WPA3-Personal");
    for (const auto locale : available_locales()) {
        CHECK_FALSE(format_value(*security, localizer(locale)).empty());
    }
}

TEST_CASE("real capture: Android emulator AP", "[summary][real]") {
    const auto bytes = parse_hex(test_support::read_file(test_support::testdata(
                                     "captures/android/emulator-androidwifi.hex")))
                           .value();
    DecodeContext ctx;
    ctx.frequency_mhz = 2437;
    ctx.privacy = false;
    const auto ies = decode(bytes, ctx);
    REQUIRE(ies.elements.size() == 7);
    for (const auto& e : ies.elements) {
        INFO(e.type);
        CHECK(e.status == DecodeStatus::ok);
    }
    const auto s = summarize(ies, ctx);
    CHECK(s.ssid == "AndroidWifi");
    CHECK(s.security.type == SecurityType::open);
    CHECK(s.phy.generation == 0);
    CHECK(s.phy.standards == std::vector{PhyStandard::b, PhyStandard::g});
    CHECK(s.phy.primary_channel == 6);
    CHECK(s.country == "US");
    CHECK(s.wmm);
}
