// SPDX-License-Identifier: MIT
#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>

#include <wifi_analyze/channel.hpp>
#include <wifi_analyze/oui.hpp>
#include <wifi_analyze/summary.hpp>

using namespace wifi_analyze;
using Catch::Approx;

TEST_CASE("PHY rates match the standard tables", "[phy]") {
    // HT (802.11n): MCS 7, 1 SS
    CHECK(*phy_rate_mbps(4, 20, 7, 1, false) == Approx(65.0));
    CHECK(*phy_rate_mbps(4, 20, 7, 1, true) == Approx(72.2));
    CHECK(*phy_rate_mbps(4, 40, 7, 2, true) == Approx(300.0));
    // VHT (802.11ac)
    CHECK(*phy_rate_mbps(5, 80, 9, 1, true) == Approx(433.3));
    CHECK(*phy_rate_mbps(5, 160, 9, 2, true) == Approx(1733.3));
    CHECK_FALSE(phy_rate_mbps(5, 20, 9, 1, false).has_value()); // invalid combination
    CHECK(*phy_rate_mbps(5, 20, 9, 3, false) == Approx(260.0));
    // HE (802.11ax), 0.8 µs GI
    CHECK(*phy_rate_mbps(6, 20, 11, 1, false) == Approx(143.4));
    CHECK(*phy_rate_mbps(6, 80, 11, 1, false) == Approx(600.5));
    CHECK(*phy_rate_mbps(6, 160, 11, 2, false) == Approx(2402.0));
    // EHT (802.11be)
    CHECK(*phy_rate_mbps(7, 320, 13, 1, false) == Approx(2882.4));
    // Invalid input
    CHECK_FALSE(phy_rate_mbps(4, 80, 7, 1, false).has_value());
    CHECK_FALSE(phy_rate_mbps(6, 320, 11, 1, false).has_value());
    CHECK_FALSE(phy_rate_mbps(7, 20, 14, 1, false).has_value());
    CHECK_FALSE(phy_rate_mbps(6, 20, 0, 0, false).has_value());
}

TEST_CASE("channel and frequency conversion", "[channel]") {
    CHECK(channel_from_frequency(2412) == ChannelInfo{Band::ghz_2_4, 1});
    CHECK(channel_from_frequency(2484) == ChannelInfo{Band::ghz_2_4, 14});
    CHECK(channel_from_frequency(5180) == ChannelInfo{Band::ghz_5, 36});
    CHECK(channel_from_frequency(5825) == ChannelInfo{Band::ghz_5, 165});
    CHECK(channel_from_frequency(5935) == ChannelInfo{Band::ghz_6, 2});
    CHECK(channel_from_frequency(5955) == ChannelInfo{Band::ghz_6, 1});
    CHECK(channel_from_frequency(7115) == ChannelInfo{Band::ghz_6, 233});
    CHECK(channel_from_frequency(60480) == ChannelInfo{Band::ghz_60, 2});
    CHECK_FALSE(channel_from_frequency(2400).has_value());
    for (const auto mhz : {2412U, 2472U, 2484U, 5180U, 5500U, 5955U, 6415U}) {
        const auto ch = channel_from_frequency(mhz);
        REQUIRE(ch);
        CHECK(frequency_from_channel(ch->band, ch->channel) == mhz);
    }
    CHECK(band_from_operating_class(81) == Band::ghz_2_4);
    CHECK(band_from_operating_class(128) == Band::ghz_5);
    CHECK(band_from_operating_class(131) == Band::ghz_6);
    CHECK(band_from_operating_class(1) == Band::unknown);
}

TEST_CASE("built-in OUI table", "[oui]") {
    CHECK(builtin_oui_name(Oui{0x00, 0x50, 0xf2}) == "Microsoft");
    CHECK(builtin_oui_name(Oui{0x50, 0x6f, 0x9a}) == "Wi-Fi Alliance");
    CHECK_FALSE(builtin_oui_name(Oui{0x12, 0x34, 0x56}).has_value());
}

TEST_CASE("IEEE OUI CSV parsing", "[oui]") {
    const std::string_view csv = "Registry,Assignment,Organization Name,Organization Address\r\n"
                                 "MA-L,123456,\"Example, Inc.\",\"Street 1\r\nCity\"\r\n"
                                 "MA-L,ABCDEF,Other Corp,Somewhere\n"
                                 "MA-L,ABCDEF,Duplicate Corp,Somewhere\n"
                                 "MA-M,ABCDEF1,Not 24 bit,x\n";
    const auto db = OuiDatabase::parse_ieee_csv(csv);
    REQUIRE(db.has_value());
    CHECK(db->size() == 2);
    CHECK(db->find(Oui{0x12, 0x34, 0x56}) == "Example, Inc.");
    CHECK(db->find(Oui{0xab, 0xcd, 0xef}) == "Other Corp");
    CHECK(oui_name(Oui{0x12, 0x34, 0x56}, &*db) == "Example, Inc.");
    CHECK(oui_name(Oui{0x00, 0x50, 0xf2}, &*db) == "Microsoft"); // falls back to built-in
    CHECK_FALSE(OuiDatabase::parse_ieee_csv("garbage\n").has_value());
}

TEST_CASE("OUI of a MAC address", "[oui]") {
    CHECK(oui_of_mac(MacAddress{0x00, 0x50, 0xf2, 1, 2, 3}) == Oui{0x00, 0x50, 0xf2});
    CHECK_FALSE(oui_of_mac(MacAddress{0x02, 0x50, 0xf2, 1, 2, 3}).has_value()); // local
    CHECK_FALSE(oui_of_mac(MacAddress{0x01, 0x00, 0x5e, 1, 2, 3}).has_value()); // group
}
