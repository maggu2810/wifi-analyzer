// SPDX-License-Identifier: MIT
// Vendor-specific elements (vendor_misc.cpp, vendor_wfa.cpp, WPS extensions). Vectors follow the
// layouts of the Wireshark 4.6.9 dissectors; the Atheros element is a real capture.

#include <catch2/catch_test_macros.hpp>
#include <functional>

#include <wifi_analyze/i18n.hpp>
#include <wifi_analyze/ie.hpp>

#include "test_support.hpp"

using namespace wifi_analyze;
using test_support::hex;
using test_support::node;

namespace {

DecodedElement single(std::string_view ies_hex) {
    auto ies = decode(hex(ies_hex));
    REQUIRE(ies.elements.size() == 1);
    return std::move(ies.elements.front());
}

std::string text_of(const DecodedElement& e, MessageId label) {
    const auto* n = node(e.tree, label);
    REQUIRE(n != nullptr);
    return std::get<std::string>(n->value);
}

} // namespace

TEST_CASE("vendor elements decode without leftovers", "[vendor]") {
    struct Case {
        const char* hex;
        std::string_view type;
    };
    const std::array cases{
        Case{"dd09 00037f 01 01 00 00 ff7f", "vendor.atheros"}, // real capture
        Case{"dd0a 004096 2f 41502d310000", "vendor.cisco"},
        Case{"dd05 004096 03 05", "vendor.cisco"},
        Case{"dd09 004096 0e 0500 40 10 08", "vendor.cisco"},
        Case{"dd05 004096 14 01", "vendor.cisco"},
        Case{"dd16 004096 04 00 01 03a40000 27a40000 42435e00 62322f00", "vendor.cisco"},
        Case{"851e 00000000000000000000 41502d4b69746368656e000000000000 05 000000", "cisco_ccx1"},
        Case{"dd0a 000b86 01 03 00 41502d32", "vendor.aruba"},
        Case{"dd39 000b86 0109003101004048118e432441ff402726f9b994e1a440240000000000004014000000"
             "00000040568000000000004004000000000000",
             "vendor.aruba"},
        Case{"dd08 001392 03 41502d33", "vendor.ruckus.ap_name"},
        Case{"dd08 5c5b35 01 4d495354", "vendor.mist.ap_name"},
        Case{"dd08 dc0856 01 41502d37", "vendor.alcatel_lucent.ap_name"},
        Case{"dd0b 001977 21 01 00 04 41502d34", "vendor.aerohive"},
        Case{"dd0a 001174 01 06 00 41502d36", "vendor.arista"},
        Case{"dd0c 00090f 0a00 0105 4641502d31", "vendor.fortinet"},
        Case{"dd07 000ce6 01 02 aabb", "vendor.meru"},
        Case{"dd10 00a0f8 01 00000000000000 04 41502d35", "vendor.extreme"},
        Case{"ad0f 00a0f8 0300 6400 0a00 1100 00000000", "symbol_proprietary"},
        Case{"dd14 000512 01 03 02 1000 001122334455 66778899aabb", "vendor.extreme_mesh"},
        Case{
            "dd26 000c42 00 0000 011e 00000000000000000000 4d696b726f54696b000000000000000000000000",
            "vendor.mikrotik"},
        Case{"dd09 005043 04 00 01 01 01 00", "vendor.marvell"},
        Case{"dd0f 001f32 01 11 05 0102030405 f0 02 aabb", "vendor.nintendo"},
        Case{"dd0c 0017f2 06 0100 05 0102030405", "vendor.apple"},
        Case{"dd1e 00904c 33 ef09 1b ffff0000000000000000000000000000 0000 00000000 00",
             "vendor.broadcom.ht"},
        Case{"dd18 6a5c35 01 010101 040493734900 06026400 0a0105 0b02b400",
             "vendor.sgdsn.drone_id"},
        Case{"dd18 506f9a 29 0100 000fac04 0100 000fac04 0100 000fac08 cc00",
             "vendor.wfa.rsn_override"},
        Case{"dd05 506f9a 2b 20", "vendor.wfa.rsnx_override"},
        Case{"dd0a 506f9a 1b 060120 070102", "vendor.wfa.multi_ap"},
        Case{"dd0d 506f9a 0a 00 0006 0011 1c44 0032", "vendor.wfa.wfd"},
        Case{"dd0d 506f9a 13 00 0200 8001 dd 0100 aa", "vendor.wfa.nan"},
        Case{"dd16 506f9a 14 000fac07 0100 000fac04 0100 506f9a01 0000", "vendor.wfa.osen"},
        Case{"dd0a 506f9a 22 01 04 00500060", "vendor.wfa.qos_mgmt"},
        Case{"dd16 0050f2 04 104a 0001 10 1049 0009 00372a 000120 060120", "vendor.microsoft.wps"},
    };
    for (const auto& c : cases) {
        INFO(c.hex);
        const auto e = single(c.hex);
        CHECK(e.type == c.type);
        CHECK(e.status == DecodeStatus::ok);
        CHECK(e.diagnostics.empty());
        for (const auto locale : available_locales()) {
            const auto loc = localizer(locale);
            std::function<void(const TreeNode&)> visit = [&](const TreeNode& n) {
                CHECK_FALSE(loc.text(n.label).empty());
                static_cast<void>(format_value(n, loc));
                for (const auto& child : n.children) {
                    visit(child);
                }
            };
            visit(e.tree);
        }
    }
}

TEST_CASE("AP names of infrastructure vendors", "[vendor]") {
    CHECK(text_of(single("dd0a 004096 2f 41502d310000"), MessageId::vendor_ap_name) == "AP-1");
    CHECK(text_of(single("851e 00000000000000000000 41502d4b69746368656e000000000000 05 000000"),
                  MessageId::vendor_ap_name) == "AP-Kitchen");
    CHECK(text_of(single("dd0a 000b86 01 03 00 41502d32"), MessageId::vendor_ap_name) == "AP-2");
    CHECK(text_of(single("dd08 001392 03 41502d33"), MessageId::vendor_ap_name) == "AP-3");
    CHECK(text_of(single("dd0b 001977 21 01 00 04 41502d34"), MessageId::aerohive_host_name) ==
          "AP-4");
    CHECK(text_of(single("dd0c 00090f 0a00 0105 4641502d31"), MessageId::vendor_ap_name) ==
          "FAP-1");
    CHECK(text_of(single("dd10 00a0f8 01 00000000000000 04 41502d35"), MessageId::vendor_ap_name) ==
          "AP-5");
    CHECK(text_of(single("dd26 000c42 00 0000 011e 00000000000000000000 "
                         "4d696b726f54696b000000000000000000000000"),
                  MessageId::mikrotik_identity) == "MikroTik");
    // Other Ruckus types are not decoded (only named by OUI).
    CHECK(single("dd06 001392 01 aabb").status == DecodeStatus::unknown);
}

TEST_CASE("Atheros advanced capability (real capture)", "[vendor]") {
    const auto e = single("dd09 00037f 01 01 00 00 ff7f");
    CHECK(std::get<std::uint64_t>(node(e.tree, MessageId::atheros_default_key)->value) == 0x7fff);
    CHECK_FALSE(std::get<bool>(node(e.tree, MessageId::atheros_turbo_prime)->value));
}

TEST_CASE("Aruba GPS and French drone ID", "[vendor]") {
    const auto gps = single("dd39 000b86 0109003101004048118e432441ff402726f9b994e1a4402400000000"
                            "0000401400000000000040568000000000004004000000000000");
    CHECK(std::get<double>(node(gps.tree, MessageId::aruba_gps_latitude)->value) == 48.137154);
    CHECK(std::get<double>(node(gps.tree, MessageId::aruba_gps_distance)->value) == 2.5);

    const auto drone = single("dd18 6a5c35 01 010101 040493734900 06026400 0a0105 0b02b400");
    CHECK(std::get<double>(node(drone.tree, MessageId::drone_latitude)->value) == 48.13715);
    CHECK(std::get<std::int64_t>(node(drone.tree, MessageId::drone_altitude_amsl)->value) == 100);
    CHECK(std::get<std::uint64_t>(node(drone.tree, MessageId::drone_heading)->value) == 180);
}

TEST_CASE("Wi-Fi Alliance RSN override, Multi-AP and Wi-Fi Display", "[vendor]") {
    const auto rsno = single("dd18 506f9a 29 0100 000fac04 0100 000fac04 0100 000fac08 cc00");
    // Decoded with the RSN decoder, but not exposed as typed RSN value (summary uses RSN only).
    CHECK(std::holds_alternative<std::monostate>(rsno.value));
    const auto* akm = node(rsno.tree, MessageId::rsn_akm_list);
    REQUIRE(akm != nullptr);
    CHECK(akm->bytes->offset == 16);

    const auto map = single("dd0a 506f9a 1b 060120 070102");
    CHECK(std::get<bool>(node(map.tree, MessageId::multi_ap_fronthaul_bss)->value));
    CHECK_FALSE(std::get<bool>(node(map.tree, MessageId::multi_ap_backhaul_bss)->value));
    CHECK(std::get<std::uint64_t>(node(map.tree, MessageId::multi_ap_profile)->value) == 2);

    const auto wps = single("dd16 0050f2 04 104a 0001 10 1049 0009 00372a 000120 060120");
    CHECK(std::get<bool>(node(wps.tree, MessageId::multi_ap_fronthaul_bss)->value));

    const auto wfd = single("dd0d 506f9a 0a 00 0006 0011 1c44 0032");
    CHECK(std::get<EnumValue>(node(wfd.tree, MessageId::wfd_device_type)->value).raw == 1);
    CHECK(std::get<bool>(node(wfd.tree, MessageId::wfd_session_available)->value));
    CHECK(std::get<std::uint64_t>(node(wfd.tree, MessageId::wfd_control_port)->value) == 7236);

    const auto bad = single("dd09 506f9a 0a 00 0006 0011"); // subelement longer than element
    CHECK(bad.status == DecodeStatus::malformed);
}
