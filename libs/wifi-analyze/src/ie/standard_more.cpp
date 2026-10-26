// SPDX-License-Identifier: MIT
// Further standard and extension elements seen in beacons / probe responses.
// Reference: IEEE Std 802.11-2020 clause 9.4.2 (element formats), IEEE Std 802.11ax-2021 and
// IEEE Std 802.11be-2024. Cross-checked against Wireshark 4.6.9 packet-ieee80211.c; the
// dissector function is named at each decoder (see docs/decoder-sources.md).

#include <array>
#include <string>

#include "ie/decoders.hpp"

namespace wifi_analyze::ie {
namespace {

using core::table_name;

/// QoS Info field, AP form (IEEE 802.11-2020 §9.4.1, QoS Info field).
void qos_info_ap(Decoder& d, TreeNode& parent) {
    if (auto q = d.bits(WA_TR(qos_info, "QoS Info"), 1)) {
        q->number(0, 4, WA_TR(qos_edca_update_count, "EDCA Parameter Set Update Count"));
        q->flag(4, WA_TR(qos_q_ack, "Q-Ack"));
        q->flag(5, WA_TR(qos_queue_request, "Queue Request"));
        q->flag(6, WA_TR(qos_txop_request, "TXOP Request"));
        q->flag(7, WA_TR(qos_more_data_ack, "More Data Ack"));
        parent.children.push_back(q->take());
    }
}

/// Generic subelement list (id u8, length u8, data) as raw nodes.
void raw_subelements(Decoder& d, TreeNode& parent) {
    while (d.remaining() >= 2) {
        const auto start = d.offset();
        auto sub = d.group(WA_TR(common_subelement, "Subelement"));
        d.u8(sub, WA_TR(common_subelement_id, "Subelement ID"));
        const auto len = d.u8(sub, msg::length);
        if (!len || !d.bytes(sub, msg::data, *len)) {
            parent.children.push_back(std::move(sub));
            return;
        }
        d.close(sub, start);
        parent.children.push_back(std::move(sub));
    }
    if (!d.reader().empty()) {
        d.malformed();
    }
}

Text sco_name(std::uint64_t v) {
    constexpr std::array<Text, 4> names{WA_TR(sco_none, "No secondary channel"),
                                        WA_TR(sco_above, "Above"), msg::reserved,
                                        WA_TR(sco_below, "Below")};
    return table_name(names, v);
}

Text wide_bw_name(std::uint64_t v) {
    constexpr std::array<Text, 4> names{"20/40 MHz", "80/160/80+80 MHz",
                                        WA_TR(wide_bw_160_deprecated, "160 MHz (deprecated)"),
                                        WA_TR(wide_bw_80p80_deprecated, "80+80 MHz (deprecated)")};
    return table_name(names, v);
}

Text eht_bandwidth_name(std::uint64_t v) {
    constexpr std::array<Text, 5> names{"20 MHz", "40 MHz", "80 MHz", "160 MHz", "320 MHz"};
    return table_name(names, v);
}

/// Time Advertisement time value, timing capabilities 2 (802.11-2020 Table 9-207).
void utc_time_value(Decoder& d, TreeNode& parent) {
    const auto start = d.offset();
    auto t = d.group(WA_TR(time_adv_time_value, "Time Value"));
    d.u16(t, WA_TR(time_year, "Year"));
    d.u8(t, WA_TR(time_month, "Month"));
    d.u8(t, WA_TR(time_day, "Day"));
    d.u8(t, WA_TR(time_hours, "Hours"));
    d.u8(t, WA_TR(time_minutes, "Minutes"));
    d.u8(t, WA_TR(time_seconds, "Seconds"));
    d.u16(t, WA_TR(time_milliseconds, "Milliseconds"));
    d.u8(t, msg::reserved);
    d.close(t, start);
    parent.children.push_back(std::move(t));
}

Text twt_setup_command_name(std::uint64_t v) {
    constexpr std::array<Text, 8> names{
        WA_TR(twt_cmd_request, "Request TWT"), WA_TR(twt_cmd_suggest, "Suggest TWT"),
        WA_TR(twt_cmd_demand, "Demand TWT"),   WA_TR(twt_cmd_grouping, "TWT Grouping"),
        WA_TR(twt_cmd_accept, "Accept TWT"),   WA_TR(twt_cmd_alternate, "Alternate TWT"),
        WA_TR(twt_cmd_dictate, "Dictate TWT"), WA_TR(twt_cmd_reject, "Reject TWT")};
    return table_name(names, v);
}

/// TWT wake interval = mantissa * 2^exponent µs (802.11ax-2021 §9.4.2).
void twt_wake_interval(Decoder& d, TreeNode& parent, std::uint64_t exponent) {
    const auto start = d.offset();
    const auto mantissa = d.reader().u16le();
    if (!mantissa) {
        d.malformed();
        return;
    }
    auto n = Decoder::node(WA_TR(twt_wake_interval_mantissa, "TWT Wake Interval Mantissa"),
                           std::uint64_t{*mantissa}, d.range_from(start));
    if (exponent < 40) {
        n.children.push_back(Decoder::node(WA_TR(twt_wake_interval, "TWT Wake Interval"),
                                           std::uint64_t{*mantissa} << exponent,
                                           d.range_from(start), Unit::microseconds));
    }
    parent.children.push_back(std::move(n));
}

void twt_broadcast_set(Decoder& d, bool wake_unit_tu, bool& last) {
    const auto start = d.offset();
    auto set = d.group(WA_TR(twt_broadcast_parameter_set, "Broadcast TWT Parameter Set"));
    auto req = d.bits(WA_TR(twt_request_type, "Request Type"), 2);
    if (!req) {
        last = true;
        return;
    }
    req->flag(0, WA_TR(twt_requester, "TWT Request"));
    req->enumeration(1, 3, WA_TR(twt_setup_command, "TWT Setup Command"), twt_setup_command_name);
    req->flag(4, WA_TR(twt_trigger, "Trigger"));
    last = req->flag(5, WA_TR(twt_last_broadcast_set, "Last Broadcast Parameter Set"));
    req->flag(6, WA_TR(twt_flow_type_unannounced, "Flow Type (Unannounced)"));
    req->number(7, 3, WA_TR(twt_broadcast_recommendation, "Broadcast TWT Recommendation"));
    const auto exponent =
        req->number(10, 5, WA_TR(twt_wake_interval_exponent, "TWT Wake Interval Exponent"));
    req->flag(15, WA_TR(twt_aligned, "Aligned"));
    set.children.push_back(req->take());
    d.u16(set, WA_TR(twt_target_wake_time_short, "Target Wake Time (TSF bits 10-25)"));
    d.u8(set, wake_unit_tu
                  ? WA_TR(twt_min_wake_duration_tu, "Nominal Minimum Wake Duration (TU)")
                  : WA_TR(twt_min_wake_duration_256us, "Nominal Minimum Wake Duration (256 µs)"));
    twt_wake_interval(d, set, exponent);
    if (auto info = d.bits(WA_TR(twt_broadcast_info, "Broadcast TWT Info"), 2)) {
        const bool restricted = info->flag(
            0, WA_TR(twt_rtwt_traffic_info_present, "Restricted TWT Traffic Info Present"));
        info->number(1, 2, WA_TR(twt_rtwt_schedule_info, "Restricted TWT Schedule Info"));
        info->number(3, 5, WA_TR(twt_broadcast_id, "Broadcast TWT ID"));
        info->number(8, 8, WA_TR(twt_broadcast_persistence, "Broadcast TWT Persistence"));
        set.children.push_back(info->take());
        if (restricted) {
            if (auto ctrl = d.bits(WA_TR(twt_traffic_info_control, "Traffic Info Control"), 1)) {
                ctrl->flag(0, WA_TR(twt_dl_tid_bitmap_valid, "DL TID Bitmap Valid"));
                ctrl->flag(1, WA_TR(twt_ul_tid_bitmap_valid, "UL TID Bitmap Valid"));
                set.children.push_back(ctrl->take());
            }
            d.u8(set, WA_TR(twt_dl_tid_bitmap, "Restricted TWT DL TID Bitmap"), Unit::none,
                 Display::hex);
            d.u8(set, WA_TR(twt_ul_tid_bitmap, "Restricted TWT UL TID Bitmap"), Unit::none,
                 Display::hex);
        }
    } else {
        last = true;
    }
    d.close(set, start);
    d.add(std::move(set));
}

void twt_individual(Decoder& d, std::uint64_t control) {
    const bool wake_unit_tu = ((control >> 5U) & 1U) != 0;
    auto req = d.bits(WA_TR(twt_request_type, "Request Type"), 2);
    if (!req) {
        return;
    }
    req->flag(0, WA_TR(twt_requester, "TWT Request"));
    const auto command = req->enumeration(1, 3, WA_TR(twt_setup_command, "TWT Setup Command"),
                                          twt_setup_command_name);
    req->flag(4, WA_TR(twt_trigger, "Trigger"));
    req->flag(5, WA_TR(twt_implicit, "Implicit"));
    req->flag(6, WA_TR(twt_flow_type_unannounced, "Flow Type (Unannounced)"));
    req->number(7, 3, WA_TR(twt_flow_id, "TWT Flow Identifier"));
    const auto exponent =
        req->number(10, 5, WA_TR(twt_wake_interval_exponent, "TWT Wake Interval Exponent"));
    req->flag(15, WA_TR(twt_protection, "TWT Protection"));
    d.add(req->take());
    const auto start = d.offset();
    const auto twt = d.reader().u64le();
    if (!twt) {
        d.malformed();
        return;
    }
    d.add(Decoder::node(WA_TR(twt_target_wake_time, "Target Wake Time"), std::uint64_t{*twt},
                        d.range_from(start), Unit::microseconds));
    if (command == 3) {
        // TWT Grouping: a variable TWT Group Assignment field follows; not interpreted.
        d.rest(d.root(), msg::data);
        return;
    }
    d.u8(d.root(),
         wake_unit_tu
             ? WA_TR(twt_min_wake_duration_tu, "Nominal Minimum Wake Duration (TU)")
             : WA_TR(twt_min_wake_duration_256us, "Nominal Minimum Wake Duration (256 µs)"));
    twt_wake_interval(d, d.root(), exponent);
    d.u8(d.root(), WA_TR(twt_channel, "TWT Channel"), Unit::none, Display::hex);
    if ((control & 0x01U) != 0) {
        d.u32(d.root(), WA_TR(twt_ndp_paging, "NDP Paging"), Unit::none, Display::hex);
    }
    if ((control & 0x40U) != 0) {
        d.u16(d.root(), WA_TR(twt_link_id_bitmap, "Link ID Bitmap"), Unit::none, Display::hex);
    }
    if ((control & 0x80U) != 0) {
        d.u16(d.root(), WA_TR(twt_aligned_link_bitmap, "Aligned TWT Link Bitmap"), Unit::none,
              Display::hex);
    }
}

using SubFn = ElementValue (*)(Decoder&);

/// Neighbor Report subelements whose format is that of an element (802.11-2020 Table 9-173,
/// 802.11ax-2021, 802.11be-2024). Wireshark: dissect_neighbor_report.
struct NeighborSubelement {
    std::uint8_t id;
    MessageId name;
    SubFn fn;
};

ElementValue nr_tsf(Decoder& d) {
    d.u16(d.root(), WA_TR(nr_tsf_offset, "TSF Offset"), Unit::tu);
    d.u16(d.root(), WA_TR(nr_beacon_interval, "Beacon Interval"), Unit::tu);
    return {};
}

ElementValue nr_country(Decoder& d) {
    d.text(d.root(), WA_TR(country_code, "Country Code"), 2);
    return {};
}

ElementValue nr_preference(Decoder& d) {
    d.u8(d.root(), WA_TR(nr_preference, "Preference"));
    return {};
}

ElementValue nr_termination(Decoder& d) {
    d.bytes(d.root(), WA_TR(nr_termination_tsf, "BSS Termination TSF"), 8);
    d.u16(d.root(), WA_TR(nr_duration_minutes, "Duration (minutes)"));
    return {};
}

ElementValue nr_vendor(Decoder& d) {
    d.oui(d.root(), WA_TR(vendor_oui, "OUI"));
    d.rest(d.root(), msg::data);
    return {};
}

const std::array neighbor_subelements{
    NeighborSubelement{1, WA_TR(nr_sub_tsf, "TSF Information"), nr_tsf},
    NeighborSubelement{2, WA_TR(nr_sub_country, "Condensed Country String"), nr_country},
    NeighborSubelement{3, WA_TR(nr_sub_preference, "BSS Transition Candidate Preference"),
                       nr_preference},
    NeighborSubelement{4, WA_TR(nr_sub_termination, "BSS Termination Duration"), nr_termination},
    NeighborSubelement{5, WA_TR(nr_sub_bearing, "Bearing"), nullptr},
    NeighborSubelement{6, WA_TR(nr_sub_wide_bw, "Wide Bandwidth Channel"),
                       decode_wide_bandwidth_channel_switch},
    NeighborSubelement{39, WA_TR(nr_sub_measurement_report, "Measurement Report"), nullptr},
    NeighborSubelement{45, WA_TR(element_ht_capabilities, "HT Capabilities"),
                       decode_ht_capabilities},
    NeighborSubelement{61, WA_TR(element_ht_operation, "HT Operation"), decode_ht_operation},
    NeighborSubelement{62, WA_TR(element_secondary_channel_offset, "Secondary Channel Offset"),
                       decode_secondary_channel_offset},
    NeighborSubelement{66, WA_TR(element_measurement_pilot, "Measurement Pilot Transmission"),
                       decode_measurement_pilot_transmission},
    NeighborSubelement{70, WA_TR(element_rm_capabilities, "RM Enabled Capabilities"),
                       decode_rm_enabled_capabilities},
    NeighborSubelement{71, WA_TR(element_multiple_bssid, "Multiple BSSID"), decode_multiple_bssid},
    NeighborSubelement{191, WA_TR(element_vht_capabilities, "VHT Capabilities"),
                       decode_vht_capabilities},
    NeighborSubelement{192, WA_TR(element_vht_operation, "VHT Operation"), decode_vht_operation},
    NeighborSubelement{193, WA_TR(element_he_capabilities, "HE Capabilities"),
                       decode_he_capabilities},
    NeighborSubelement{194, WA_TR(element_he_operation, "HE Operation"), decode_he_operation},
    NeighborSubelement{199, WA_TR(element_eht_capabilities, "EHT Capabilities"),
                       decode_eht_capabilities},
    NeighborSubelement{200, WA_TR(element_eht_operation, "EHT Operation"), decode_eht_operation},
    NeighborSubelement{201, WA_TR(nr_sub_basic_multi_link, "Basic Multi-Link"), decode_multi_link},
    NeighborSubelement{221, WA_TR(element_vendor_specific, "Vendor Specific"), nr_vendor},
};

Text phy_type_name(std::uint64_t v) {
    // 802.11-2020 Annex C dot11PHYType (Wireshark: phy_type_vals).
    switch (v) {
    case 2:
        return "DSSS";
    case 4:
        return "OFDM";
    case 5:
        return "HR/DSSS";
    case 6:
        return "ERP";
    case 7:
        return "HT";
    case 8:
        return "DMG";
    case 9:
        return "VHT";
    case 10:
        return "TVHT";
    case 11:
        return "S1G";
    case 12:
        return "CDMG";
    case 13:
        return "CMMG";
    case 14:
        return "HE";
    case 15:
        return "EDMG";
    case 17:
        return "NGV";
    case 18:
        return "EHT";
    default:
        return msg::unknown;
    }
}

} // namespace

// FH Parameter Set, 802.11-2020 §9.4.2 (obsolete PHY). Wireshark: ieee80211_tag_fh_parameter.
ElementValue decode_fh_parameter_set(Decoder& d) {
    d.u16(d.root(), WA_TR(fh_dwell_time, "Dwell Time"), Unit::tu);
    d.u8(d.root(), WA_TR(fh_hop_set, "Hop Set"));
    d.u8(d.root(), WA_TR(fh_hop_pattern, "Hop Pattern"));
    d.u8(d.root(), WA_TR(fh_hop_index, "Hop Index"));
    return {};
}

// CF Parameter Set, 802.11-2020 §9.4.2. Wireshark: ieee80211_tag_cf_parameter.
ElementValue decode_cf_parameter_set(Decoder& d) {
    d.u8(d.root(), WA_TR(cf_count, "CFP Count"));
    d.u8(d.root(), WA_TR(cf_period, "CFP Period"));
    d.u16(d.root(), WA_TR(cf_max_duration, "CFP Max Duration"), Unit::tu);
    d.u16(d.root(), WA_TR(cf_duration_remaining, "CFP Duration Remaining"), Unit::tu);
    return {};
}

// EDCA Parameter Set, 802.11-2020 §9.4.2. Wireshark: ieee80211_tag_edca_param_set.
// The AC parameter records have the same format as in the WMM Parameter element.
ElementValue decode_edca_parameter_set(Decoder& d) {
    qos_info_ap(d, d.root());
    d.u8(d.root(), WA_TR(edca_update_edca_info, "Update EDCA Info"), Unit::none, Display::hex);
    decode_edca_records(d, d.root());
    return {};
}

// IBSS DFS, 802.11-2020 §9.4.2. Wireshark: ieee80211_tag_ibss_dfs.
ElementValue decode_ibss_dfs(Decoder& d) {
    d.mac(d.root(), WA_TR(ibss_dfs_owner, "DFS Owner"));
    d.u8(d.root(), WA_TR(ibss_dfs_recovery_interval, "DFS Recovery Interval"));
    while (d.remaining() >= 2) {
        const auto start = d.offset();
        auto entry = d.group(WA_TR(ibss_dfs_channel_map, "Channel Map"));
        d.u8(entry, WA_TR(common_channel, "Channel"));
        if (auto map = d.bits(WA_TR(ibss_dfs_map, "Map"), 1)) {
            map->flag(0, WA_TR(ibss_dfs_bss, "BSS"));
            map->flag(1, WA_TR(ibss_dfs_ofdm_preamble, "OFDM Preamble"));
            map->flag(2, WA_TR(ibss_dfs_unidentified, "Unidentified Signal"));
            map->flag(3, WA_TR(ibss_dfs_radar, "Radar"));
            map->flag(4, WA_TR(ibss_dfs_unmeasured, "Unmeasured"));
            entry.children.push_back(map->take());
        }
        d.close(entry, start);
        d.add(std::move(entry));
    }
    return {};
}

// QoS Capability, 802.11-2020 §9.4.2 (AP form). Wireshark: ieee80211_tag_qos_capability.
ElementValue decode_qos_capability(Decoder& d) {
    qos_info_ap(d, d.root());
    return {};
}

// Secondary Channel Offset, 802.11-2020 §9.4.2. Wireshark: dissect_secondary_channel_offset_ie.
ElementValue decode_secondary_channel_offset(Decoder& d) {
    d.enumeration(d.root(), WA_TR(ht_secondary_channel_offset, "Secondary Channel Offset"), 1,
                  sco_name);
    return {};
}

// BSS Average Access Delay, 802.11-2020 §9.4.2. Wireshark: dissect_bss_avg_access_delay_ie.
ElementValue decode_bss_average_access_delay(Decoder& d) {
    d.u8(d.root(), WA_TR(bss_ap_avg_access_delay, "AP Average Access Delay"));
    return {};
}

// Measurement Pilot Transmission, 802.11-2020 §9.4.2.
// Wireshark: dissect_measurement_pilot_trans_ie.
ElementValue decode_measurement_pilot_transmission(Decoder& d) {
    d.u8(d.root(), WA_TR(measurement_pilot_interval, "Measurement Pilot Interval"), Unit::tu);
    raw_subelements(d, d.root());
    return {};
}

// BSS Available Admission Capacity, 802.11-2020 §9.4.2.
// Wireshark: dissect_bss_available_admission_capacity_ie.
ElementValue decode_bss_available_admission_capacity(Decoder& d) {
    auto mask =
        d.bits(WA_TR(admission_capacity_bitmask, "Available Admission Capacity Bitmask"), 2);
    if (!mask) {
        return {};
    }
    const auto bits = mask->get(0, 12);
    d.add(mask->take());
    constexpr std::array<Text, 12> names{"UP 0", "UP 1", "UP 2",  "UP 3",  "UP 4",  "UP 5",
                                         "UP 6", "UP 7", "AC_BE", "AC_BK", "AC_VI", "AC_VO"};
    for (unsigned i = 0; i < names.size(); ++i) {
        if (((bits >> i) & 1U) == 0) {
            continue;
        }
        const auto start = d.offset();
        const auto v = d.reader().u16le();
        if (!v) {
            d.malformed();
            break;
        }
        auto n =
            Decoder::node(WA_TR(admission_capacity_entry, "Available Admission Capacity (32 µs/s)"),
                          std::uint64_t{*v}, d.range_from(start));
        auto target = Decoder::node(WA_TR(admission_capacity_for, "Applies To"),
                                    EnumValue{.raw = i, .name = names[i]}, d.range_from(start));
        target.display = Display::name_only;
        n.children.push_back(std::move(target));
        d.add(std::move(n));
    }
    return {};
}

// Time Advertisement, 802.11-2020 §9.4.2. Wireshark: dissect_time_adv.
ElementValue decode_time_advertisement(Decoder& d) {
    const auto caps =
        d.enumeration(d.root(), WA_TR(time_adv_timing_capabilities, "Timing Capabilities"), 1,
                      [](std::uint64_t v) -> Text {
                          constexpr std::array<Text, 3> names{
                              WA_TR(time_adv_no_source, "No standardized external time source"),
                              WA_TR(time_adv_tsf_offset, "Timestamp offset based on UTC"),
                              WA_TR(time_adv_utc, "UTC time at which the TSF timer is 0")};
                          return table_name(names, v);
                      });
    if (caps == 1) {
        d.bytes(d.root(), WA_TR(time_adv_time_value, "Time Value"), 10);
        d.bytes(d.root(), WA_TR(time_adv_time_error, "Time Error"), 5);
    } else if (caps == 2) {
        utc_time_value(d, d.root());
        d.bytes(d.root(), WA_TR(time_adv_time_error, "Time Error"), 5);
        d.u8(d.root(), WA_TR(time_adv_update_counter, "Time Update Counter"));
    }
    return {};
}

// 20/40 BSS Intolerant Channel Report, 802.11-2020 §9.4.2.
// Wireshark: dissect_20_40_bss_intolerant.
ElementValue decode_bss_intolerant_channel_report(Decoder& d) {
    d.u8(d.root(), WA_TR(common_operating_class, "Operating Class"));
    auto channels = d.group(WA_TR(intolerant_channels, "Channel List"));
    const auto start = d.offset();
    while (!d.reader().empty()) {
        d.u8(channels, WA_TR(common_channel, "Channel"));
    }
    d.close(channels, start);
    d.add(std::move(channels));
    return {};
}

// BSS Max Idle Period, 802.11-2020 §9.4.2. Wireshark: dissect_bss_max_idle_period.
ElementValue decode_bss_max_idle_period(Decoder& d) {
    d.u16(d.root(), WA_TR(bss_max_idle_period, "Max Idle Period (1000 TU)"));
    if (auto o = d.bits(WA_TR(bss_max_idle_options, "Idle Options"), 1)) {
        o->flag(0, WA_TR(bss_max_idle_protected_keepalive, "Protected Keep-Alive Required"));
        d.add(o->take());
    }
    return {};
}

// Time Zone, 802.11-2020 §9.4.2 (POSIX TZ string). Wireshark: dissect_time_zone.
ElementValue decode_time_zone(Decoder& d) {
    d.text(d.root(), WA_TR(time_zone, "Time Zone"), d.remaining());
    return {};
}

// QoS Map, 802.11-2020 §9.4.2. Wireshark: dissect_qos_map_set.
ElementValue decode_qos_map(Decoder& d) {
    const auto size = d.content().size();
    if (size < 16 || size % 2 != 0) {
        d.diagnostic(
            Severity::warning,
            WA_TR(qos_map_bad_length, "QoS Map length {0} is invalid (expected 16 + 2n octets)"),
            {std::to_string(size)});
    }
    const auto exceptions = size >= 16 ? (size - 16) / 2 : 0;
    for (std::size_t i = 0; i < exceptions; ++i) {
        const auto start = d.offset();
        auto e = d.group(WA_TR(qos_map_dscp_exception, "DSCP Exception"));
        d.u8(e, WA_TR(qos_map_dscp, "DSCP"));
        d.u8(e, WA_TR(qos_map_user_priority, "User Priority"));
        d.close(e, start);
        d.add(std::move(e));
    }
    for (unsigned up = 0; up < 8 && d.remaining() >= 2; ++up) {
        const auto start = d.offset();
        const auto pair = d.reader().array<2>();
        if (!pair) {
            break;
        }
        const auto [low, high] = *pair;
        auto r = Decoder::node(WA_TR(qos_map_dscp_range, "DSCP Range"), std::uint64_t{up},
                               d.range_from(start));
        if (low == 255 && high == 255) {
            r.children.push_back(
                Decoder::node(WA_TR(qos_map_unused, "Not used"), true, d.range_from(start)));
        } else {
            r.children.push_back(Decoder::node(WA_TR(qos_map_dscp_low, "DSCP Low"),
                                               std::uint64_t{low},
                                               ByteRange{.offset = start, .length = 1}));
            r.children.push_back(Decoder::node(WA_TR(qos_map_dscp_high, "DSCP High"),
                                               std::uint64_t{high},
                                               ByteRange{.offset = start + 1, .length = 1}));
        }
        d.add(std::move(r));
    }
    return {};
}

// Extended BSS Load, 802.11-2020 §9.4.2. Wireshark: dissect_ext_bss_load.
ElementValue decode_extended_bss_load(Decoder& d) {
    d.u16(d.root(), WA_TR(ext_bss_load_mu_mimo_count, "MU-MIMO Capable STA Count"));
    d.u8(d.root(),
         WA_TR(ext_bss_load_ss_underutilization, "Spatial Stream Underutilization (x/255)"));
    d.u8(d.root(), WA_TR(ext_bss_load_util_20, "Observable Secondary 20 MHz Utilization (x/255)"));
    d.u8(d.root(), WA_TR(ext_bss_load_util_40, "Observable Secondary 40 MHz Utilization (x/255)"));
    d.u8(d.root(), WA_TR(ext_bss_load_util_80, "Observable Secondary 80 MHz Utilization (x/255)"));
    return {};
}

// Wide Bandwidth Channel Switch, 802.11-2020 §9.4.2 (also the Neighbor Report Wide
// Bandwidth Channel subelement). Wireshark: dissect_wide_bw_channel_switch.
ElementValue decode_wide_bandwidth_channel_switch(Decoder& d) {
    d.enumeration(d.root(), WA_TR(wide_bw_new_width, "New Channel Width"), 1, wide_bw_name);
    d.u8(d.root(), WA_TR(vht_ccfs0, "Channel Center Frequency Segment 0"));
    d.u8(d.root(), WA_TR(vht_ccfs1, "Channel Center Frequency Segment 1"));
    return {};
}

// Channel Switch Wrapper, 802.11-2020 §9.4.2: nested elements.
// Wireshark: dissect_channel_switch_wrapper.
ElementValue decode_channel_switch_wrapper(Decoder& d) {
    const auto start = d.offset();
    const auto data = d.reader().rest();
    d.nested_elements(d.root(), data, start);
    return {};
}

// Neighbor Report, 802.11-2020 §9.4.2 with 802.11ax/be BSSID Information bits.
// Wireshark: dissect_neighbor_report.
ElementValue decode_neighbor_report(Decoder& d) {
    d.mac(d.root(), WA_TR(nr_bssid, "BSSID"));
    if (auto info = d.bits(WA_TR(nr_bssid_info, "BSSID Information"), 4)) {
        info->enumeration(
            0, 2, WA_TR(nr_reachability, "AP Reachability"), [](std::uint64_t v) -> Text {
                constexpr std::array<Text, 4> names{msg::reserved,
                                                    WA_TR(nr_not_reachable, "Not reachable"),
                                                    msg::unknown, WA_TR(nr_reachable, "Reachable")};
                return table_name(names, v);
            });
        info->flag(2, WA_TR(nr_security, "Security"));
        info->flag(3, WA_TR(nr_key_scope, "Key Scope"));
        info->flag(4, WA_TR(nr_spectrum_management, "Spectrum Management"));
        info->flag(5, WA_TR(nr_qos, "QoS"));
        info->flag(6, WA_TR(nr_apsd, "APSD"));
        info->flag(7, WA_TR(nr_radio_measurement, "Radio Measurement"));
        info->flag(10, WA_TR(nr_mobility_domain, "Mobility Domain"));
        info->flag(11, WA_TR(nr_ht, "High Throughput"));
        info->flag(12, WA_TR(nr_vht, "Very High Throughput"));
        info->flag(13, WA_TR(nr_ftm, "Fine Timing Measurement"));
        info->flag(14, WA_TR(nr_he, "High Efficiency"));
        info->flag(15, WA_TR(nr_er_bss, "Extended Range BSS"));
        info->flag(16, WA_TR(nr_colocated_ap, "Co-Located AP"));
        info->flag(17, WA_TR(nr_unsolicited_probe, "Unsolicited Probe Responses Active"));
        info->flag(18, WA_TR(nr_ess_colocated, "Member of ESS with 2.4/5 GHz Co-Located AP"));
        info->flag(19, WA_TR(nr_oct, "OCT Supported with Reporting AP"));
        info->flag(20, WA_TR(nr_colocated_6ghz, "Co-Located with 6 GHz AP"));
        info->flag(21, WA_TR(nr_eht, "Extremely High Throughput"));
        info->flag(22, WA_TR(nr_dmg_positioning, "DMG Positioning"));
        d.add(info->take());
    }
    d.u8(d.root(), WA_TR(common_operating_class, "Operating Class"));
    d.u8(d.root(), WA_TR(common_channel, "Channel"));
    d.enumeration(d.root(), WA_TR(nr_phy_type, "PHY Type"), 1, phy_type_name);

    while (d.remaining() >= 2) {
        const auto start = d.offset();
        const auto id = *d.reader().u8();
        const auto len = *d.reader().u8();
        const auto body = d.reader().bytes(len);
        if (!body) {
            d.reader().rest();
            d.malformed();
            break;
        }
        const NeighborSubelement* known = nullptr;
        for (const auto& s : neighbor_subelements) {
            if (s.id == id) {
                known = &s;
            }
        }
        auto sub =
            Decoder::node(known != nullptr ? known->name : WA_TR(common_subelement, "Subelement"),
                          std::uint64_t{id}, d.range_from(start));
        if (known != nullptr && known->fn != nullptr) {
            d.sub_decode(sub, known->fn, *body, start + 2);
        } else if (!body->empty()) {
            sub.children.push_back(
                Decoder::node(msg::data, std::vector<std::uint8_t>(body->begin(), body->end()),
                              ByteRange{.offset = start + 2, .length = body->size()}));
        }
        d.add(std::move(sub));
    }
    if (!d.reader().empty()) {
        d.malformed();
    }
    return {};
}

// Target Wake Time, 802.11ax-2021 §9.4.2 (+ 802.11be link bitmaps). Wireshark:
// ieee80211_tag_twt.
ElementValue decode_twt(Decoder& d) {
    auto ctrl = d.bits(WA_TR(twt_control, "Control"), 1);
    if (!ctrl) {
        return {};
    }
    const auto control = ctrl->get(0, 8);
    ctrl->flag(0, WA_TR(twt_ndp_paging_indicator, "NDP Paging Indicator"));
    ctrl->flag(1, WA_TR(twt_responder_pm_mode, "Responder PM Mode"));
    const auto negotiation = ctrl->enumeration(
        2, 2, WA_TR(twt_negotiation_type, "Negotiation Type"), [](std::uint64_t v) -> Text {
            constexpr std::array<Text, 4> names{
                WA_TR(twt_neg_individual, "Individual TWT"),
                WA_TR(twt_neg_wake_tbtt, "Wake TBTT and wake interval"),
                WA_TR(twt_neg_broadcast, "Broadcast TWT (in broadcast frames)"),
                WA_TR(twt_neg_broadcast_unicast,
                      "Broadcast TWT (in individually addressed frames)")};
            return table_name(names, v);
        });
    ctrl->flag(4, WA_TR(twt_info_frame_disabled, "TWT Information Frame Disabled"));
    const bool wake_unit_tu =
        ctrl->flag(5, WA_TR(twt_wake_duration_unit_tu, "Wake Duration Unit is 1 TU"));
    ctrl->flag(6, WA_TR(twt_link_id_bitmap_present, "Link ID Bitmap Present"));
    ctrl->flag(7, WA_TR(twt_aligned_twt_link_bitmap, "Aligned TWT Link Bitmap Present"));
    d.add(ctrl->take());

    if ((negotiation & 0x2U) != 0) {
        bool last = false;
        while (!last && d.remaining() >= 2 && !d.is_malformed()) {
            twt_broadcast_set(d, wake_unit_tu, last);
        }
    } else {
        twt_individual(d, control);
    }
    return {};
}

// FILS Indication, 802.11-2020 §9.4.2. Wireshark: ieee80211_tag_fils_indication.
ElementValue decode_fils_indication(Decoder& d) {
    auto info = d.bits(WA_TR(fils_information, "FILS Information"), 2);
    if (!info) {
        return {};
    }
    const auto keys =
        info->number(0, 3, WA_TR(fils_public_key_count, "Number of Public Key Identifiers"));
    const auto realms = info->number(3, 3, WA_TR(fils_realm_count, "Number of Realm Identifiers"));
    info->flag(6, WA_TR(fils_ip_config, "FILS IP Address Configuration"));
    const bool cache = info->flag(7, WA_TR(fils_cache_id_included, "Cache Identifier Included"));
    const bool hessid = info->flag(8, WA_TR(fils_hessid_included, "HESSID Included"));
    info->flag(9, WA_TR(fils_sk_without_pfs, "FILS Shared Key Authentication without PFS"));
    info->flag(10, WA_TR(fils_sk_with_pfs, "FILS Shared Key Authentication with PFS"));
    info->flag(11, WA_TR(fils_public_key_auth, "FILS Public Key Authentication"));
    d.add(info->take());

    if (cache) {
        d.u16(d.root(), WA_TR(fils_cache_id, "Cache Identifier"), Unit::none, Display::hex);
    }
    if (hessid) {
        d.mac(d.root(), WA_TR(interworking_hessid, "HESSID"));
    }
    for (std::uint64_t i = 0; i < realms; ++i) {
        d.u16(d.root(), WA_TR(fils_realm_id, "Realm Identifier"), Unit::none, Display::hex);
    }
    for (std::uint64_t i = 0; i < keys && !d.is_malformed(); ++i) {
        const auto start = d.offset();
        auto key = d.group(WA_TR(fils_public_key_id, "Public Key Identifier"));
        d.u8(key, WA_TR(fils_key_type, "Key Type"));
        const auto len = d.u8(key, msg::length);
        if (len) {
            d.bytes(key, WA_TR(fils_key_indicator, "Public Key Indicator"), *len);
        }
        d.close(key, start);
        d.add(std::move(key));
    }
    return {};
}

// UORA Parameter Set, 802.11ax-2021 §9.4.2. Wireshark: dissect_uora_parameter_set.
ElementValue decode_uora_parameter_set(Decoder& d) {
    if (auto o = d.bits(WA_TR(uora_ocw_range, "OCW Range"), 1)) {
        o->number(0, 3, WA_TR(uora_eocw_min, "EOCWmin"));
        o->number(3, 3, WA_TR(uora_eocw_max, "EOCWmax"));
        d.add(o->take());
    }
    return {};
}

// NDP Feedback Report Parameter Set, 802.11ax-2021 §9.4.2.
// Wireshark: dissect_ndp_feedback_report_set.
ElementValue decode_ndp_feedback_report_parameter_set(Decoder& d) {
    d.u8(d.root(),
         WA_TR(ndp_resource_request_threshold, "Resource Request Buffer Threshold Exponent"));
    return {};
}

// ESS Report, 802.11ax-2021 §9.4.2. Wireshark: dissect_ess_report.
ElementValue decode_ess_report(Decoder& d) {
    auto e = d.bits(WA_TR(ess_information, "ESS Information"), 1);
    if (!e) {
        return {};
    }
    e->flag(0, WA_TR(ess_planned, "Planned ESS"));
    e->flag(1, WA_TR(ess_edge, "Edge of ESS"));
    const auto threshold = e->get(2, 6);
    if (threshold == 63) {
        e->computed(
            2, 6, WA_TR(ess_transition_threshold, "Recommended BSS Transition RSSI Threshold"),
            EnumValue{.raw = threshold, .name = WA_TR(ess_no_recommendation, "No recommendation")});
    } else {
        e->computed(2, 6,
                    WA_TR(ess_transition_threshold, "Recommended BSS Transition RSSI Threshold"),
                    std::int64_t{-100} + static_cast<std::int64_t>(threshold), Unit::dbm);
    }
    d.add(e->take());
    return {};
}

// OPS, 802.11ax-2021 §9.4.2. Wireshark: dissect_ops.
ElementValue decode_ops(Decoder& d) {
    d.u8(d.root(), WA_TR(ops_duration, "OPS Duration"), Unit::milliseconds);
    return {};
}

// HE BSS Load, 802.11ax-2021 §9.4.2. Wireshark 4.6.9 names the element only.
ElementValue decode_he_bss_load(Decoder& d) {
    d.u16(d.root(), WA_TR(he_bss_load_sta_count, "HE STA Count"));
    d.u8(d.root(), WA_TR(he_bss_load_utilization, "Utilization (x/255)"));
    d.u8(d.root(), WA_TR(he_bss_load_freq_underutilization, "Frequency Underutilization (x/255)"));
    d.u8(d.root(),
         WA_TR(ext_bss_load_ss_underutilization, "Spatial Stream Underutilization (x/255)"));
    return {};
}

// Max Channel Switch Time, 802.11ax-2021 §9.4.2. Wireshark: dissect_max_channel_switch_time.
ElementValue decode_max_channel_switch_time(Decoder& d) {
    const auto start = d.offset();
    if (const auto v = d.reader().u24le()) {
        d.add(Decoder::node(WA_TR(max_cs_time, "Switch Time"), std::uint64_t{*v},
                            d.range_from(start), Unit::tu));
    } else {
        d.malformed();
    }
    return {};
}

// TID-to-Link Mapping, 802.11be-2024 §9.4.2. Wireshark: dissect_tid_to_link_mapping.
// Direction values and the absence of the presence indicator with Default Link Mapping follow
// the standard and Linux include/linux/ieee80211.h (Wireshark 4.6.9 names 0/1 the other way).
ElementValue decode_tid_to_link_mapping(Decoder& d) {
    auto ctrl = d.bits(WA_TR(t2lm_control, "TID-to-Link Mapping Control"), 1);
    if (!ctrl) {
        return {};
    }
    ctrl->enumeration(0, 2, WA_TR(t2lm_direction, "Direction"), [](std::uint64_t v) -> Text {
        constexpr std::array<Text, 3> names{WA_TR(t2lm_downlink, "Downlink"),
                                            WA_TR(t2lm_uplink, "Uplink"),
                                            WA_TR(t2lm_bidirectional, "Bidirectional")};
        return table_name(names, v);
    });
    const bool default_mapping = ctrl->flag(2, WA_TR(t2lm_default, "Default Link Mapping"));
    const bool switch_time =
        ctrl->flag(3, WA_TR(t2lm_switch_time_present, "Mapping Switch Time Present"));
    const bool duration = ctrl->flag(4, WA_TR(t2lm_duration_present, "Expected Duration Present"));
    const bool one_octet = ctrl->flag(5, WA_TR(t2lm_map_size_1, "Link Mapping Size is 1 Octet"));
    d.add(ctrl->take());
    std::uint8_t presence = 0;
    if (!default_mapping) {
        presence = d.u8(d.root(), WA_TR(t2lm_presence, "Link Mapping Presence Indicator"),
                        Unit::none, Display::hex)
                       .value_or(0);
    }
    if (switch_time) {
        d.u16(d.root(), WA_TR(t2lm_switch_time, "Mapping Switch Time"));
    }
    if (duration) {
        const auto start = d.offset();
        if (const auto v = d.reader().u24le()) {
            d.add(Decoder::node(WA_TR(t2lm_expected_duration, "Expected Duration"),
                                std::uint64_t{*v}, d.range_from(start), Unit::tu));
        } else {
            d.malformed();
        }
    }
    for (unsigned tid = 0; tid < 8; ++tid) {
        if (((presence >> tid) & 1U) == 0) {
            continue;
        }
        const auto start = d.offset();
        const auto map = one_octet
                             ? d.reader().u8().transform([](auto v) { return std::uint16_t{v}; })
                             : d.reader().u16le();
        if (!map) {
            d.malformed();
            break;
        }
        auto n = Decoder::node(WA_TR(t2lm_tid_mapping, "Link Mapping of TID"), std::uint64_t{tid},
                               d.range_from(start));
        n.children.push_back(
            Decoder::node(WA_TR(t2lm_links, "Links"), std::uint64_t{*map}, d.range_from(start)));
        n.children.back().display = Display::hex;
        d.add(std::move(n));
    }
    return {};
}

// Bandwidth Indication, 802.11be-2024 §9.4.2. Wireshark: dissect_bandwidth_indication.
ElementValue decode_bandwidth_indication(Decoder& d) {
    auto params = d.bits(WA_TR(bwi_parameters, "Bandwidth Indication Parameters"), 1);
    if (!params) {
        return {};
    }
    const bool bitmap =
        params->flag(1, WA_TR(bwi_disabled_bitmap_present, "Disabled Subchannel Bitmap Present"));
    d.add(params->take());
    if (auto control = d.bits(WA_TR(eht_control, "Control"), 1)) {
        control->enumeration(0, 3, WA_TR(eht_channel_width, "Channel Width"), eht_bandwidth_name);
        d.add(control->take());
    }
    d.u8(d.root(), WA_TR(vht_ccfs0, "Channel Center Frequency Segment 0"));
    d.u8(d.root(), WA_TR(vht_ccfs1, "Channel Center Frequency Segment 1"));
    if (bitmap) {
        d.u16(d.root(), WA_TR(eht_disabled_subchannels, "Disabled Subchannel Bitmap"), Unit::none,
              Display::hex);
    }
    return {};
}

} // namespace wifi_analyze::ie
