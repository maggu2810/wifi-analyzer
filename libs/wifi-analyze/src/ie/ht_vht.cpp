// SPDX-License-Identifier: MIT
// HT (802.11n) and VHT (802.11ac) elements. Reference: IEEE Std 802.11-2020, HT Capabilities,
// HT Operation, VHT Capabilities and VHT Operation elements.
// Cross-checked with Wireshark 4.6.9 packet-ieee80211.c; the dissector per element is listed in
// docs/decoder-sources.md.

#include <algorithm>
#include <array>
#include <string>

#include "ie/decoders.hpp"

namespace wifi_analyze::ie {
namespace {

using core::BitField;
using core::table_name;

Text sm_power_save_name(std::uint64_t v) {
    constexpr std::array<Text, 4> names{WA_TR(sm_ps_static, "Static"),
                                        WA_TR(sm_ps_dynamic, "Dynamic"), msg::reserved,
                                        WA_TR(sm_ps_disabled, "Disabled")};
    return table_name(names, v);
}

/// Adds the "2^(13+e) - 1 octets" interpretation of an A-MPDU length exponent.
void ampdu_length(BitField& b, unsigned first, unsigned count, MessageId label) {
    const auto e = b.get(first, count);
    b.computed(first, count, label, (std::uint64_t{1} << (13 + e)) - 1, Unit::octets);
}

Text min_mpdu_spacing_name(std::uint64_t v) {
    constexpr std::array<Text, 8> names{WA_TR(mpdu_spacing_none, "No restriction"),
                                        "1/4 µs",
                                        "1/2 µs",
                                        "1 µs",
                                        "2 µs",
                                        "4 µs",
                                        "8 µs",
                                        "16 µs"};
    return table_name(names, v);
}

Text vht_mcs_name(std::uint64_t v) {
    constexpr std::array<Text, 4> names{"MCS 0-7", "MCS 0-8", "MCS 0-9", msg::not_supported};
    return table_name(names, v);
}

} // namespace

void add_mcs_map(Decoder& d, TreeNode& parent, MessageId label, core::NameFn names) {
    constexpr std::array<MessageId, 8> streams{
        WA_TR(nss_1, "1 Spatial Stream"),  WA_TR(nss_2, "2 Spatial Streams"),
        WA_TR(nss_3, "3 Spatial Streams"), WA_TR(nss_4, "4 Spatial Streams"),
        WA_TR(nss_5, "5 Spatial Streams"), WA_TR(nss_6, "6 Spatial Streams"),
        WA_TR(nss_7, "7 Spatial Streams"), WA_TR(nss_8, "8 Spatial Streams")};
    if (auto map = d.bits(label, 2)) {
        for (unsigned ss = 0; ss < 8; ++ss) {
            map->enumeration(ss * 2, 2, streams[ss], names);
        }
        parent.children.push_back(map->take());
    }
}

ElementValue decode_ht_capabilities(Decoder& d) {
    HtCapabilities ht;

    auto info = d.bits(WA_TR(ht_capability_info, "HT Capability Information"), 2);
    if (!info) {
        return {};
    }
    ht.info = static_cast<std::uint16_t>(info->get(0, 16));
    info->flag(0, WA_TR(ht_ldpc, "LDPC Coding Capability"));
    info->enumeration(1, 1, WA_TR(ht_channel_width_set, "Supported Channel Width Set"),
                      [](std::uint64_t v) -> Text {
                          return v != 0 ? WA_TR(ht_width_20_40, "20 MHz and 40 MHz")
                                        : WA_TR(ht_width_20, "20 MHz only");
                      });
    info->enumeration(2, 2, WA_TR(ht_sm_power_save, "SM Power Save"), sm_power_save_name);
    info->flag(4, WA_TR(ht_greenfield, "HT-Greenfield"));
    info->flag(5, WA_TR(ht_short_gi_20, "Short GI for 20 MHz"));
    info->flag(6, WA_TR(ht_short_gi_40, "Short GI for 40 MHz"));
    info->flag(7, WA_TR(ht_tx_stbc, "Tx STBC"));
    info->enumeration(8, 2, WA_TR(ht_rx_stbc, "Rx STBC"), [](std::uint64_t v) -> Text {
        constexpr std::array<Text, 4> names{msg::not_supported, WA_TR(stbc_1, "One spatial stream"),
                                            WA_TR(stbc_2, "One and two spatial streams"),
                                            WA_TR(stbc_3, "One, two and three spatial streams")};
        return table_name(names, v);
    });
    info->flag(10, WA_TR(ht_delayed_block_ack, "HT-Delayed Block Ack"));
    info->enumeration(11, 1, WA_TR(ht_max_amsdu, "Maximum A-MSDU Length"),
                      [](std::uint64_t v) -> Text { return v != 0 ? "7935" : "3839"; });
    info->flag(12, WA_TR(ht_dsss_cck_40, "DSSS/CCK Mode in 40 MHz"));
    info->flag(14, WA_TR(ht_40_intolerant, "Forty MHz Intolerant"));
    info->flag(15, WA_TR(ht_lsig_txop, "L-SIG TXOP Protection Support"));
    d.add(info->take());

    auto ampdu = d.bits(WA_TR(ht_ampdu_parameters, "A-MPDU Parameters"), 1);
    if (!ampdu) {
        return ht;
    }
    ht.ampdu_parameters = static_cast<std::uint8_t>(ampdu->get(0, 8));
    ampdu_length(*ampdu, 0, 2, WA_TR(ht_max_ampdu_length, "Maximum A-MPDU Length"));
    ampdu->enumeration(2, 3, WA_TR(ht_min_mpdu_spacing, "Minimum MPDU Start Spacing"),
                       min_mpdu_spacing_name);
    d.add(ampdu->take());

    auto mcs = d.bits(WA_TR(ht_mcs_set, "Supported MCS Set"), 16);
    if (!mcs) {
        return ht;
    }
    std::ranges::copy(mcs->data(), ht.mcs_set.begin());
    {
        // Rx MCS bitmask: list supported MCS indices compactly.
        std::string supported;
        int run_start = -1;
        for (int i = 0; i <= 77; ++i) {
            const bool set = i < 77 && mcs->test(static_cast<unsigned>(i));
            if (set && run_start < 0) {
                run_start = i;
            } else if (!set && run_start >= 0) {
                if (!supported.empty()) {
                    supported += ", ";
                }
                supported += std::to_string(run_start);
                if (i - 1 != run_start) {
                    supported += "-" + std::to_string(i - 1);
                }
                run_start = -1;
            }
        }
        mcs->computed(0, 77, WA_TR(ht_rx_mcs, "Rx MCS"), supported);
    }
    mcs->number(80, 10, WA_TR(ht_rx_highest_rate, "Rx Highest Supported Data Rate"), Unit::mbps);
    mcs->flag(96, WA_TR(ht_tx_mcs_defined, "Tx MCS Set Defined"));
    mcs->flag(97, WA_TR(ht_tx_rx_not_equal, "Tx Rx MCS Set Not Equal"));
    mcs->number(98, 2, WA_TR(ht_tx_max_nss, "Tx Maximum Number Spatial Streams Supported"),
                Unit::none, 1);
    mcs->flag(100, WA_TR(ht_tx_unequal_modulation, "Tx Unequal Modulation Supported"));
    d.add(mcs->take());

    if (auto ext = d.bits(WA_TR(ht_extended_capabilities, "HT Extended Capabilities"), 2)) {
        ext->enumeration(8, 2, WA_TR(ht_mcs_feedback, "MCS Feedback"), [](std::uint64_t v) -> Text {
            constexpr std::array<Text, 4> names{WA_TR(feedback_none, "No feedback"), msg::reserved,
                                                WA_TR(feedback_unsolicited, "Unsolicited"),
                                                WA_TR(feedback_both, "Both")};
            return table_name(names, v);
        });
        ext->flag(10, WA_TR(ht_htc, "+HTC Support"));
        ext->flag(11, WA_TR(ht_rd_responder, "RD Responder"));
        d.add(ext->take());
    }
    d.u32(d.root(), WA_TR(ht_txbf_capabilities, "Transmit Beamforming Capabilities"), Unit::none,
          Display::hex);
    d.u8(d.root(), WA_TR(ht_asel_capabilities, "ASEL Capabilities"), Unit::none, Display::hex);
    return ht;
}

ElementValue decode_ht_operation(Decoder& d) {
    HtOperation op;
    const auto primary = d.u8(d.root(), WA_TR(ht_primary_channel, "Primary Channel"));
    auto info = d.bits(WA_TR(ht_operation_info, "HT Operation Information"), 5);
    if (!primary || !info) {
        return {};
    }
    op.primary_channel = *primary;
    op.secondary_channel_offset = static_cast<std::uint8_t>(info->enumeration(
        0, 2, WA_TR(ht_secondary_channel_offset, "Secondary Channel Offset"),
        [](std::uint64_t v) -> Text {
            constexpr std::array<Text, 4> names{WA_TR(sco_none, "No secondary channel"),
                                                WA_TR(sco_above, "Above"), msg::reserved,
                                                WA_TR(sco_below, "Below")};
            return table_name(names, v);
        }));
    op.any_channel_width =
        info->flag(2, WA_TR(ht_sta_channel_width, "STA Channel Width (any width allowed)"));
    info->flag(3, WA_TR(ht_rifs, "RIFS Mode"));
    info->enumeration(8, 2, WA_TR(ht_protection, "HT Protection"), [](std::uint64_t v) -> Text {
        constexpr std::array<Text, 4> names{WA_TR(ht_protection_none, "No protection"),
                                            WA_TR(ht_protection_nonmember, "Nonmember protection"),
                                            WA_TR(ht_protection_20, "20 MHz protection"),
                                            WA_TR(ht_protection_mixed, "Non-HT mixed")};
        return table_name(names, v);
    });
    info->flag(10, WA_TR(ht_nongreenfield_present, "Nongreenfield HT STAs Present"));
    info->flag(12, WA_TR(ht_obss_non_ht_present, "OBSS Non-HT STAs Present"));
    op.ccfs2 = static_cast<std::uint8_t>(
        info->number(13, 8, WA_TR(ht_ccfs2, "Channel Center Frequency Segment 2")));
    info->flag(30, WA_TR(ht_dual_beacon, "Dual Beacon"));
    info->flag(31, WA_TR(ht_dual_cts, "Dual CTS Protection"));
    info->flag(32, WA_TR(ht_stbc_beacon, "STBC Beacon"));
    d.add(info->take());
    d.bytes(d.root(), WA_TR(ht_basic_mcs_set, "Basic HT-MCS Set"), 16);
    return op;
}

ElementValue decode_vht_capabilities(Decoder& d) {
    VhtCapabilities vht;
    auto info = d.bits(WA_TR(vht_capability_info, "VHT Capabilities Information"), 4);
    if (!info) {
        return {};
    }
    vht.info = static_cast<std::uint32_t>(info->get(0, 32));
    info->enumeration(
        0, 2, WA_TR(vht_max_mpdu_length, "Maximum MPDU Length"), [](std::uint64_t v) -> Text {
            constexpr std::array<Text, 4> names{"3895", "7991", "11454", msg::reserved};
            return table_name(names, v);
        });
    info->enumeration(2, 2, WA_TR(vht_channel_width_set, "Supported Channel Width Set"),
                      [](std::uint64_t v) -> Text {
                          constexpr std::array<Text, 4> names{
                              WA_TR(vht_width_80, "No 160 MHz or 80+80 MHz"),
                              WA_TR(vht_width_160, "160 MHz"),
                              WA_TR(vht_width_160_80p80, "160 MHz and 80+80 MHz"), msg::reserved};
                          return table_name(names, v);
                      });
    info->flag(4, WA_TR(vht_rx_ldpc, "Rx LDPC"));
    info->flag(5, WA_TR(vht_short_gi_80, "Short GI for 80 MHz"));
    info->flag(6, WA_TR(vht_short_gi_160, "Short GI for 160 and 80+80 MHz"));
    info->flag(7, WA_TR(vht_tx_stbc, "Tx STBC"));
    info->number(8, 3, WA_TR(vht_rx_stbc, "Rx STBC (spatial streams)"));
    info->flag(11, WA_TR(vht_su_beamformer, "SU Beamformer Capable"));
    info->flag(12, WA_TR(vht_su_beamformee, "SU Beamformee Capable"));
    info->number(13, 3, WA_TR(vht_beamformee_sts, "Beamformee STS Capability"), Unit::none, 1);
    info->number(16, 3, WA_TR(vht_sounding_dimensions, "Number of Sounding Dimensions"), Unit::none,
                 1);
    info->flag(19, WA_TR(vht_mu_beamformer, "MU Beamformer Capable"));
    info->flag(20, WA_TR(vht_mu_beamformee, "MU Beamformee Capable"));
    info->flag(21, WA_TR(vht_txop_ps, "TXOP PS"));
    info->flag(22, WA_TR(vht_htc, "+HTC-VHT Capable"));
    ampdu_length(*info, 23, 3, WA_TR(vht_max_ampdu_length, "Maximum A-MPDU Length"));
    info->enumeration(26, 2, WA_TR(vht_link_adaptation, "VHT Link Adaptation Capable"),
                      [](std::uint64_t v) -> Text {
                          constexpr std::array<Text, 4> names{
                              WA_TR(feedback_none, "No feedback"), msg::reserved,
                              WA_TR(feedback_unsolicited, "Unsolicited"),
                              WA_TR(feedback_both, "Both")};
                          return table_name(names, v);
                      });
    info->flag(28, WA_TR(vht_rx_antenna_consistency, "Rx Antenna Pattern Consistency"));
    info->flag(29, WA_TR(vht_tx_antenna_consistency, "Tx Antenna Pattern Consistency"));
    info->number(30, 2, WA_TR(vht_extended_nss_bw, "Extended NSS BW Support"));
    d.add(info->take());

    auto set = d.group(WA_TR(vht_mcs_nss_set, "Supported VHT-MCS and NSS Set"));
    const auto start = d.offset();
    if (d.remaining() >= 8) {
        vht.rx_mcs_map = static_cast<std::uint16_t>(d.content()[d.offset()] |
                                                    (d.content()[d.offset() + 1] << 8U));
        add_mcs_map(d, set, WA_TR(vht_rx_mcs_map, "Rx VHT-MCS Map"), vht_mcs_name);
        if (auto rx =
                d.bits(WA_TR(vht_rx_highest_rate, "Rx Highest Supported Long GI Data Rate"), 2)) {
            rx->number(0, 13, WA_TR(vht_highest_rate, "Data Rate"), Unit::mbps);
            rx->number(13, 3, WA_TR(vht_max_nsts_total, "Maximum NSTS Total"));
            set.children.push_back(rx->take());
        }
        vht.tx_mcs_map = static_cast<std::uint16_t>(d.content()[d.offset()] |
                                                    (d.content()[d.offset() + 1] << 8U));
        add_mcs_map(d, set, WA_TR(vht_tx_mcs_map, "Tx VHT-MCS Map"), vht_mcs_name);
        if (auto tx =
                d.bits(WA_TR(vht_tx_highest_rate, "Tx Highest Supported Long GI Data Rate"), 2)) {
            tx->number(0, 13, WA_TR(vht_highest_rate, "Data Rate"), Unit::mbps);
            tx->flag(13, WA_TR(vht_ext_nss_bw_capable, "VHT Extended NSS BW Capable"));
            set.children.push_back(tx->take());
        }
    } else {
        d.malformed();
    }
    d.close(set, start);
    d.add(std::move(set));
    return vht;
}

ElementValue decode_vht_operation(Decoder& d) {
    VhtOperation op;
    const auto width = d.enumeration(
        d.root(), WA_TR(vht_operation_width, "Channel Width"), 1, [](std::uint64_t v) -> Text {
            constexpr std::array<Text, 4> names{
                "20/40 MHz", "80/160/80+80 MHz",
                WA_TR(vht_op_160_deprecated, "160 MHz (deprecated)"),
                WA_TR(vht_op_80p80_deprecated, "80+80 MHz (deprecated)")};
            return table_name(names, v);
        });
    const auto ccfs0 = d.u8(d.root(), WA_TR(vht_ccfs0, "Channel Center Frequency Segment 0"));
    const auto ccfs1 = d.u8(d.root(), WA_TR(vht_ccfs1, "Channel Center Frequency Segment 1"));
    if (!width || !ccfs0 || !ccfs1) {
        return {};
    }
    op.channel_width = static_cast<std::uint8_t>(*width);
    op.ccfs0 = *ccfs0;
    op.ccfs1 = *ccfs1;
    if (d.remaining() >= 2) {
        op.basic_mcs_map = static_cast<std::uint16_t>(d.content()[d.offset()] |
                                                      (d.content()[d.offset() + 1] << 8U));
    }
    add_mcs_map(d, d.root(), WA_TR(vht_basic_mcs_map, "Basic VHT-MCS and NSS Set"), vht_mcs_name);
    return op;
}

} // namespace wifi_analyze::ie
