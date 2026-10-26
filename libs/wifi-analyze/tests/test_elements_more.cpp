// SPDX-License-Identifier: MIT
// Decoders in src/ie/standard_more.cpp. Byte vectors are built from the element formats of
// IEEE 802.11-2020 / 802.11ax-2021 / 802.11be-2024 (no real captures available for most).

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

std::size_t count(const TreeNode& root, MessageId label) {
    std::size_t n = root.label == label ? 1 : 0;
    for (const auto& c : root.children) {
        n += count(c, label);
    }
    return n;
}

} // namespace

TEST_CASE("new standard elements decode without leftovers", "[elements][more]") {
    struct Case {
        const char* hex;
        std::string_view type;
    };
    const std::array cases{
        Case{"0205 6400 01 02 03", "fh_parameter_set"},
        Case{"0406 01 02 0000 0000", "cf_parameter_set"},
        Case{"0c12 01 00 03a40000 27a40000 42435e00 62322f00", "edca_parameter_set"},
        Case{"2909 020000000001 05 24 08", "ibss_dfs"},
        Case{"2e01 0f", "qos_capability"},
        Case{"3422 001122334455 07580000 80 24 0e 0301ff 0104 1000 6400 3e0101 0603012a00 6302aabb",
             "neighbor_report"},
        Case{"3e01 03", "secondary_channel_offset"},
        Case{"3f01 10", "bss_average_access_delay"},
        Case{"4204 20 0101ff", "measurement_pilot_transmission"},
        Case{"4306 0108 1000 2000", "bss_available_admission_capacity"},
        Case{"4511 02 e807 0a 1a 0c 1e 00 0000 00 0000000000 05", "time_advertisement"},
        Case{"4903 51 01 06", "bss_intolerant_channel_report"},
        Case{"5a03 0a00 01", "bss_max_idle_period"},
        Case{"6209 4345542d3143455354", "time_zone"},
        Case{"6e12 2e06 0007 0815 ffff 1817 2027 282f 3037 383f", "qos_map"},
        Case{"c106 0300 40 10 20 30", "extended_bss_load"},
        Case{"c203 01 2a 00", "wide_bandwidth_channel_switch"},
        Case{"c405 c2 03 01 2a 00", "channel_switch_wrapper"},
        Case{"d80f 00 3328 0010000000000000 40 0002 00", "twt"},
        Case{"d816 28 1000 0001 10 0a00 1805 2000 0000 08 0100 0100 03 ff 0f", "twt"},
        Case{"f012 d10b 3412 020000000001 aaaa bbbb 0102cafe", "fils_indication"},
        Case{"f002 0002", "fils_indication"},
        Case{"ff02 25 1b", "uora_parameter_set"},
        Case{"ff02 29 07", "ndp_feedback_report_parameter_set"},
        Case{"ff02 2d 49", "ess_report"},
        Case{"ff02 2e 0a", "ops"},
        Case{"ff06 2f 0500 80 10 20", "he_bss_load"},
        Case{"ff04 34 102700", "max_channel_switch_time"},
        Case{"ff0a 6d 3a 05 3412 010000 03 01", "tid_to_link_mapping"},
        Case{"ff02 6d 04", "tid_to_link_mapping"},
        Case{"ff07 87 02 03 32 2a 0300", "bandwidth_indication"},
    };
    for (const auto& c : cases) {
        INFO(c.hex);
        const auto e = single(c.hex);
        CHECK(e.type == c.type);
        CHECK(e.status == DecodeStatus::ok);
        CHECK(e.diagnostics.empty());
        // Every node renders in every locale.
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

TEST_CASE("FILS Indication", "[elements][more]") {
    const auto e = single("f012 d10b 3412 020000000001 aaaa bbbb 0102cafe");
    CHECK(std::get<std::uint64_t>(node(e.tree, MessageId::fils_public_key_count)->value) == 1);
    CHECK(std::get<std::uint64_t>(node(e.tree, MessageId::fils_realm_count)->value) == 2);
    CHECK(std::get<bool>(node(e.tree, MessageId::fils_sk_without_pfs)->value));
    CHECK_FALSE(std::get<bool>(node(e.tree, MessageId::fils_sk_with_pfs)->value));
    CHECK(std::get<bool>(node(e.tree, MessageId::fils_public_key_auth)->value));
    CHECK(std::get<std::string>(node(e.tree, MessageId::interworking_hessid)->value) ==
          "02:00:00:00:00:01");
    CHECK(count(e.tree, MessageId::fils_realm_id) == 2);
    const auto* key = node(e.tree, MessageId::fils_key_indicator);
    REQUIRE(key != nullptr);
    CHECK(key->bytes->offset == 16);

    const auto truncated = single("f003 8100 34"); // cache id announced, one octet only
    CHECK(truncated.status == DecodeStatus::malformed);
}

TEST_CASE("TWT individual and broadcast", "[elements][more]") {
    const auto ind = single("d80f 00 3328 0010000000000000 40 0002 00");
    CHECK(std::get<std::uint64_t>(node(ind.tree, MessageId::twt_target_wake_time)->value) == 4096);
    CHECK(std::get<std::uint64_t>(node(ind.tree, MessageId::twt_wake_interval)->value) ==
          512U << 10U);
    CHECK(std::get<EnumValue>(node(ind.tree, MessageId::twt_setup_command)->value).raw == 1);

    const auto bc = single("d816 28 1000 0001 10 0a00 1805 2000 0000 08 0100 0100 03 ff 0f");
    CHECK(count(bc.tree, MessageId::twt_broadcast_parameter_set) == 2);
    CHECK(std::get<std::uint64_t>(node(bc.tree, MessageId::twt_broadcast_id)->value) == 3);
    CHECK(std::get<std::uint64_t>(node(bc.tree, MessageId::twt_broadcast_persistence)->value) == 5);
    CHECK(node(bc.tree, MessageId::twt_ul_tid_bitmap) != nullptr);
}

TEST_CASE("Neighbor Report with subelements", "[elements][more]") {
    const auto e = single(
        "3422 001122334455 07580000 80 24 0e 0301ff 0104 1000 6400 3e0101 0603012a00 6302aabb");
    CHECK(std::get<EnumValue>(node(e.tree, MessageId::nr_reachability)->value).raw == 3);
    CHECK(std::get<bool>(node(e.tree, MessageId::nr_he)->value));
    CHECK_FALSE(std::get<bool>(node(e.tree, MessageId::nr_eht)->value));
    CHECK(std::get<EnumValue>(node(e.tree, MessageId::nr_phy_type)->value).raw == 14);
    CHECK(node(e.tree, MessageId::nr_sub_preference) != nullptr);
    // Subelement with element format, decoded by the element decoder at the right offset.
    const auto* sco = node(e.tree, MessageId::ht_secondary_channel_offset);
    REQUIRE(sco != nullptr);
    CHECK(std::get<EnumValue>(sco->value).raw == 1);
    CHECK(sco->bytes->offset == 24);
    CHECK(node(e.tree, MessageId::wide_bw_new_width) != nullptr);
    CHECK(node(e.tree, MessageId::common_subelement) != nullptr); // unknown id 0x63 kept raw

    const auto bad = single("340e 001122334455 07580000 80 24 0e 05"); // subelement cut off
    CHECK(bad.status == DecodeStatus::malformed);
}

TEST_CASE("EDCA, QoS Map and Channel Switch Wrapper", "[elements][more]") {
    const auto edca = single("0c12 01 00 03a40000 27a40000 42435e00 62322f00");
    CHECK(count(edca.tree, MessageId::edca_ac_record) == 4);
    CHECK(std::get<std::uint64_t>(node(edca.tree, MessageId::qos_edca_update_count)->value) == 1);

    const auto map = single("6e12 2e06 0007 0815 ffff 1817 2027 282f 3037 383f");
    CHECK(count(map.tree, MessageId::qos_map_dscp_exception) == 1);
    CHECK(count(map.tree, MessageId::qos_map_dscp_range) == 8);
    CHECK(count(map.tree, MessageId::qos_map_unused) == 1);
    const auto odd = single("6e03 2e0600");
    CHECK(test_support::has_diagnostic(odd.diagnostics, MessageId::qos_map_bad_length));

    const auto wrapper = single("c405 c2 03 01 2a 00");
    CHECK(node(wrapper.tree, MessageId::element_wide_bw_cs) != nullptr);
}

TEST_CASE("HE / EHT extension elements", "[elements][more]") {
    const auto ess = single("ff02 2d 49");
    CHECK(std::get<std::int64_t>(node(ess.tree, MessageId::ess_transition_threshold)->value) ==
          -82);
    const auto ess_none = single("ff02 2d fc");
    CHECK(
        std::get<EnumValue>(node(ess_none.tree, MessageId::ess_transition_threshold)->value).raw ==
        63);

    const auto t2lm = single("ff0a 6d 3a 05 3412 010000 03 01");
    CHECK(count(t2lm.tree, MessageId::t2lm_tid_mapping) == 2);
    CHECK(std::get<EnumValue>(node(t2lm.tree, MessageId::t2lm_direction)->value).name ==
          Text{MessageId::t2lm_bidirectional});
    const auto t2lm_default = single("ff02 6d 04");
    CHECK(node(t2lm_default.tree, MessageId::t2lm_presence) == nullptr);

    const auto cs_time = single("ff04 34 102700");
    CHECK(std::get<std::uint64_t>(node(cs_time.tree, MessageId::max_cs_time)->value) == 10000);

    const auto bwi = single("ff07 87 02 03 32 2a 0300");
    CHECK(std::get<EnumValue>(node(bwi.tree, MessageId::eht_channel_width)->value).raw == 3);
    CHECK(node(bwi.tree, MessageId::eht_disabled_subchannels) != nullptr);
}
