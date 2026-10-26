// SPDX-License-Identifier: MIT
// HE (802.11ax) extension elements. Reference: IEEE Std 802.11ax-2021, HE Capabilities (ext 35),
// HE Operation (36), MU EDCA Parameter Set (38), Spatial Reuse Parameter Set (39), BSS Color
// Change Announcement (42), HE 6 GHz Band Capabilities (59); IEEE Std 802.11-2020 Multiple BSSID
// Configuration (55), Non-Inheritance (56), Short SSID List (58).
// Cross-checked with Wireshark 4.6.9 packet-ieee80211.c; the dissector per element is listed in
// docs/decoder-sources.md.

#include <array>
#include <string>

#include "ie/decoders.hpp"

namespace wifi_analyze::ie {
namespace {

using core::BitField;
using core::table_name;

Text he_mcs_name(std::uint64_t v) {
    constexpr std::array<Text, 4> names{"MCS 0-7", "MCS 0-9", "MCS 0-11", msg::not_supported};
    return table_name(names, v);
}

struct Flag {
    std::uint16_t bit;
    MessageId label;
};

void he_mac_capabilities(BitField& b) {
    b.flag(0, WA_TR(he_htc, "+HTC HE Support"));
    b.flag(1, WA_TR(he_twt_requester, "TWT Requester Support"));
    b.flag(2, WA_TR(he_twt_responder, "TWT Responder Support"));
    b.number(3, 2, WA_TR(he_dynamic_fragmentation, "Dynamic Fragmentation Support"));
    b.number(5, 3,
             WA_TR(he_max_fragmented_msdus, "Maximum Number of Fragmented MSDUs/A-MSDUs Exponent"));
    b.number(8, 2, WA_TR(he_min_fragment_size, "Minimum Fragment Size"));
    b.number(10, 2, WA_TR(he_trigger_mac_padding, "Trigger Frame MAC Padding Duration"));
    b.number(12, 3, WA_TR(he_multi_tid_rx, "Multi-TID Aggregation Rx Support"));
    b.number(15, 2, WA_TR(he_link_adaptation, "HE Link Adaptation Support"));
    constexpr std::array flags{
        Flag{17, WA_TR(he_all_ack, "All Ack Support")},
        Flag{18, WA_TR(he_trs, "TRS Support")},
        Flag{19, WA_TR(he_bsr, "BSR Support")},
        Flag{20, WA_TR(he_broadcast_twt, "Broadcast TWT Support")},
        Flag{21, WA_TR(he_32bit_ba, "32-bit BA Bitmap Support")},
        Flag{22, WA_TR(he_mu_cascading, "MU Cascading Support")},
        Flag{23, WA_TR(he_ack_enabled_aggregation, "Ack-Enabled Aggregation Support")},
        Flag{25, WA_TR(he_om_control, "OM Control Support")},
        Flag{26, WA_TR(he_ofdma_ra, "OFDMA RA Support")},
    };
    for (const auto& f : flags) {
        b.flag(f.bit, f.label);
    }
    b.number(27, 2, WA_TR(he_max_ampdu_exponent_ext, "Maximum A-MPDU Length Exponent Extension"));
    constexpr std::array flags2{
        Flag{29, WA_TR(he_amsdu_fragmentation, "A-MSDU Fragmentation Support")},
        Flag{30, WA_TR(he_flexible_twt, "Flexible TWT Schedule Support")},
        Flag{31, WA_TR(he_rx_control_multibss, "Rx Control Frame to MultiBSS")},
        Flag{32, WA_TR(he_bsrp_bqrp_ampdu, "BSRP BQRP A-MPDU Aggregation")},
        Flag{33, WA_TR(he_qtp, "QTP Support")},
        Flag{34, WA_TR(he_bqr, "BQR Support")},
        Flag{35, WA_TR(he_psr_responder, "PSR Responder")},
        Flag{36, WA_TR(he_ndp_feedback_report, "NDP Feedback Report Support")},
        Flag{37, WA_TR(he_ops, "OPS Support")},
        Flag{38, WA_TR(he_amsdu_not_under_ba, "A-MSDU Not Under BA in Ack-Enabled A-MPDU Support")},
    };
    for (const auto& f : flags2) {
        b.flag(f.bit, f.label);
    }
    b.number(39, 3, WA_TR(he_multi_tid_tx, "Multi-TID Aggregation Tx Support"));
    constexpr std::array flags3{
        Flag{42, WA_TR(he_subchannel_selective, "HE Subchannel Selective Transmission Support")},
        Flag{43, WA_TR(he_ul_2x996, "UL 2x996-tone RU Support")},
        Flag{44, WA_TR(he_om_ul_mu_disable, "OM Control UL MU Data Disable Rx Support")},
        Flag{45, WA_TR(he_dynamic_sm_ps, "HE Dynamic SM Power Save")},
        Flag{46, WA_TR(he_punctured_sounding, "Punctured Sounding Support")},
        Flag{47, WA_TR(he_ht_vht_trigger_rx, "HT and VHT Trigger Frame Rx Support")},
    };
    for (const auto& f : flags3) {
        b.flag(f.bit, f.label);
    }
}

void he_phy_capabilities(BitField& b) {
    b.flag(1, WA_TR(he_width_40_24, "40 MHz in 2.4 GHz"));
    b.flag(2, WA_TR(he_width_40_80_5, "40 and 80 MHz in 5/6 GHz"));
    b.flag(3, WA_TR(he_width_160_5, "160 MHz in 5/6 GHz"));
    b.flag(4, WA_TR(he_width_80p80_5, "160/80+80 MHz in 5/6 GHz"));
    b.flag(5, WA_TR(he_width_242_24, "242-tone RUs in 2.4 GHz"));
    b.flag(6, WA_TR(he_width_242_5, "242-tone RUs in 5/6 GHz"));
    b.number(8, 4, WA_TR(he_punctured_preamble_rx, "Punctured Preamble Rx"));
    b.flag(12, WA_TR(he_device_class, "Device Class A"));
    b.flag(13, WA_TR(he_ldpc, "LDPC Coding in Payload"));
    b.flag(14, WA_TR(he_su_1x_ltf, "HE SU PPDU with 1x HE-LTF and 0.8 µs GI"));
    b.number(15, 2, WA_TR(he_midamble_nsts, "Midamble Tx/Rx Max NSTS"));
    b.flag(17, WA_TR(he_ndp_4x_ltf, "NDP with 4x HE-LTF and 3.2 µs GI"));
    b.flag(18, WA_TR(he_stbc_tx_80, "STBC Tx <= 80 MHz"));
    b.flag(19, WA_TR(he_stbc_rx_80, "STBC Rx <= 80 MHz"));
    b.flag(20, WA_TR(he_doppler_tx, "Doppler Tx"));
    b.flag(21, WA_TR(he_doppler_rx, "Doppler Rx"));
    b.flag(22, WA_TR(he_full_bw_ul_mu_mimo, "Full Bandwidth UL MU-MIMO"));
    b.flag(23, WA_TR(he_partial_bw_ul_mu_mimo, "Partial Bandwidth UL MU-MIMO"));
    b.number(24, 2, WA_TR(he_dcm_tx_constellation, "DCM Max Constellation Tx"));
    b.flag(26, WA_TR(he_dcm_tx_nss, "DCM Max NSS Tx"));
    b.number(27, 2, WA_TR(he_dcm_rx_constellation, "DCM Max Constellation Rx"));
    b.flag(29, WA_TR(he_dcm_rx_nss, "DCM Max NSS Rx"));
    b.flag(30, WA_TR(he_rx_partial_bw_su, "Rx Partial BW SU in 20 MHz HE MU PPDU"));
    b.flag(31, WA_TR(he_su_beamformer, "SU Beamformer"));
    b.flag(32, WA_TR(he_su_beamformee, "SU Beamformee"));
    b.flag(33, WA_TR(he_mu_beamformer, "MU Beamformer"));
    b.number(34, 3, WA_TR(he_beamformee_sts_80, "Beamformee STS <= 80 MHz"), Unit::none, 1);
    b.number(37, 3, WA_TR(he_beamformee_sts_160, "Beamformee STS > 80 MHz"), Unit::none, 1);
    b.number(40, 3, WA_TR(he_sounding_dim_80, "Number of Sounding Dimensions <= 80 MHz"),
             Unit::none, 1);
    b.number(43, 3, WA_TR(he_sounding_dim_160, "Number of Sounding Dimensions > 80 MHz"),
             Unit::none, 1);
    b.flag(46, WA_TR(he_ng16_su, "Ng = 16 SU Feedback"));
    b.flag(47, WA_TR(he_ng16_mu, "Ng = 16 MU Feedback"));
    b.flag(48, WA_TR(he_codebook_42_su, "Codebook Size {4, 2} SU Feedback"));
    b.flag(49, WA_TR(he_codebook_75_mu, "Codebook Size {7, 5} MU Feedback"));
    b.flag(50, WA_TR(he_triggered_su_bf, "Triggered SU Beamforming Feedback"));
    b.flag(51, WA_TR(he_triggered_mu_bf, "Triggered MU Beamforming Partial BW Feedback"));
    b.flag(52, WA_TR(he_triggered_cqi, "Triggered CQI Feedback"));
    b.flag(53, WA_TR(he_partial_bw_er, "Partial Bandwidth Extended Range"));
    b.flag(54, WA_TR(he_partial_bw_dl_mu_mimo, "Partial Bandwidth DL MU-MIMO"));
    b.flag(55, WA_TR(he_ppe_present, "PPE Thresholds Present"));
    b.flag(56, WA_TR(he_psr_sr, "PSR-Based SR Support"));
    b.flag(57, WA_TR(he_power_boost, "Power Boost Factor Support"));
    b.flag(58, WA_TR(he_su_mu_4x_ltf, "HE SU/MU PPDU with 4x HE-LTF and 0.8 µs GI"));
    b.number(59, 3, WA_TR(he_max_nc, "Max Nc"));
    b.flag(62, WA_TR(he_stbc_tx_160, "STBC Tx > 80 MHz"));
    b.flag(63, WA_TR(he_stbc_rx_160, "STBC Rx > 80 MHz"));
    b.flag(64, WA_TR(he_er_su_4x_ltf, "HE ER SU PPDU with 4x HE-LTF and 0.8 µs GI"));
    b.flag(65, WA_TR(he_20_in_40_24, "20 MHz in 40 MHz HE PPDU in 2.4 GHz"));
    b.flag(66, WA_TR(he_20_in_160, "20 MHz in 160/80+80 MHz HE PPDU"));
    b.flag(67, WA_TR(he_80_in_160, "80 MHz in 160/80+80 MHz HE PPDU"));
    b.flag(68, WA_TR(he_er_su_1x_ltf, "HE ER SU PPDU with 1x HE-LTF and 0.8 µs GI"));
    b.flag(69, WA_TR(he_midamble_2x_1x, "Midamble Tx/Rx 2x and 1x HE-LTF"));
    b.number(70, 2, WA_TR(he_dcm_max_ru, "DCM Max RU"));
    b.flag(72, WA_TR(he_long_sigb, "Longer Than 16 HE SIG-B OFDM Symbols Support"));
    b.flag(73, WA_TR(he_non_triggered_cqi, "Non-Triggered CQI Feedback"));
    b.flag(74, WA_TR(he_tx_1024qam_small_ru, "Tx 1024-QAM Support < 242-tone RU"));
    b.flag(75, WA_TR(he_rx_1024qam_small_ru, "Rx 1024-QAM Support < 242-tone RU"));
    b.flag(76,
           WA_TR(he_rx_full_bw_compressed, "Rx Full BW SU Using HE MU PPDU with Compressed SIGB"));
    b.flag(77, WA_TR(he_rx_full_bw_noncompressed,
                     "Rx Full BW SU Using HE MU PPDU with Non-Compressed SIGB"));
    b.number(78, 2, WA_TR(he_nominal_padding, "Nominal Packet Padding"));
    b.flag(80, WA_TR(he_mu_m1ru_max_ltf, "HE MU PPDU with More Than One RU Rx Max N_HE-LTF"));
}

std::optional<std::uint16_t> peek_u16(const Decoder& d) {
    if (d.remaining() < 2) {
        return std::nullopt;
    }
    return static_cast<std::uint16_t>(d.content()[d.offset()] |
                                      (d.content()[d.offset() + 1] << 8U));
}

void add_he_mcs(Decoder& d, TreeNode& parent, MessageId label, std::uint16_t& target) {
    if (const auto v = peek_u16(d)) {
        target = *v;
    }
    add_mcs_map(d, parent, label, he_mcs_name);
}

void add_he_mcs_opt(Decoder& d, TreeNode& parent, MessageId label,
                    std::optional<std::uint16_t>& target) {
    target = peek_u16(d);
    add_mcs_map(d, parent, label, he_mcs_name);
}

void edca_ac_record(Decoder& d, TreeNode& parent, bool mu, WmmAc* out) {
    const auto start = d.offset();
    auto record = d.group(WA_TR(edca_ac_record, "Access Category Parameters"));
    auto aci = d.bits(WA_TR(edca_aci_aifsn, "ACI/AIFSN"), 1);
    auto ecw = d.bits(WA_TR(edca_ecw, "ECWmin/ECWmax"), 1);
    if (!aci || !ecw) {
        return;
    }
    const auto aifsn = aci->number(0, 4, WA_TR(edca_aifsn, "AIFSN"));
    const bool acm = aci->flag(4, WA_TR(edca_acm, "ACM (Admission Control Mandatory)"));
    const auto ac = aci->enumeration(5, 2, WA_TR(edca_aci, "ACI"), access_category_name);
    record.children.push_back(aci->take());
    const auto ecw_min = ecw->get(0, 4);
    const auto ecw_max = ecw->get(4, 4);
    ecw->computed(0, 4, WA_TR(edca_cw_min, "CWmin"), (std::uint64_t{1} << ecw_min) - 1);
    ecw->computed(4, 4, WA_TR(edca_cw_max, "CWmax"), (std::uint64_t{1} << ecw_max) - 1);
    record.children.push_back(ecw->take());
    std::uint16_t txop = 0;
    if (mu) {
        const auto timer = d.u8(record, WA_TR(edca_mu_timer, "MU EDCA Timer (8 TU units)"));
        static_cast<void>(timer);
    } else {
        const auto txop_start = d.offset();
        const auto raw = d.reader().u16le();
        if (!raw) {
            d.malformed();
        } else {
            txop = *raw;
            record.children.push_back(Decoder::node(WA_TR(edca_txop_limit, "TXOP Limit"),
                                                    std::uint64_t{*raw} * 32,
                                                    d.range_from(txop_start), Unit::microseconds));
        }
    }
    d.close(record, start);
    parent.children.push_back(std::move(record));
    if (out != nullptr) {
        *out = WmmAc{.aci = static_cast<std::uint8_t>(ac),
                     .aifsn = static_cast<std::uint8_t>(aifsn),
                     .acm = acm,
                     .ecw_min = static_cast<std::uint8_t>(ecw_min),
                     .ecw_max = static_cast<std::uint8_t>(ecw_max),
                     .txop_limit = txop};
    }
}

} // namespace

Text access_category_name(std::uint64_t aci) {
    constexpr std::array<Text, 4> names{WA_TR(ac_be, "Best Effort (BE)"),
                                        WA_TR(ac_bk, "Background (BK)"), WA_TR(ac_vi, "Video (VI)"),
                                        WA_TR(ac_vo, "Voice (VO)")};
    return table_name(names, aci);
}

/// Decodes 4 EDCA access category records (WMM Parameter element: with TXOP limit).
std::vector<WmmAc> decode_edca_records(Decoder& d, TreeNode& parent) {
    std::vector<WmmAc> acs;
    for (int i = 0; i < 4 && d.remaining() >= 4; ++i) {
        WmmAc ac;
        edca_ac_record(d, parent, false, &ac);
        acs.push_back(ac);
    }
    return acs;
}

ElementValue decode_he_capabilities(Decoder& d) {
    HeCapabilities he;
    auto mac = d.bits(WA_TR(he_mac_capabilities, "HE MAC Capabilities Information"), 6);
    if (!mac) {
        return {};
    }
    std::ranges::copy(mac->data(), he.mac.begin());
    he_mac_capabilities(*mac);
    d.add(mac->take());

    auto phy = d.bits(WA_TR(he_phy_capabilities, "HE PHY Capabilities Information"), 11);
    if (!phy) {
        return he;
    }
    std::ranges::copy(phy->data(), he.phy.begin());
    he_phy_capabilities(*phy);
    d.add(phy->take());

    auto set = d.group(WA_TR(he_mcs_nss_set, "Supported HE-MCS and NSS Set"));
    const auto start = d.offset();
    add_he_mcs(d, set, WA_TR(he_rx_mcs_80, "Rx HE-MCS Map <= 80 MHz"), he.rx_mcs_80);
    add_he_mcs(d, set, WA_TR(he_tx_mcs_80, "Tx HE-MCS Map <= 80 MHz"), he.tx_mcs_80);
    if (he.supports_160mhz()) {
        add_he_mcs_opt(d, set, WA_TR(he_rx_mcs_160, "Rx HE-MCS Map 160 MHz"), he.rx_mcs_160);
        add_he_mcs_opt(d, set, WA_TR(he_tx_mcs_160, "Tx HE-MCS Map 160 MHz"), he.tx_mcs_160);
    }
    if (he.supports_80p80mhz()) {
        add_he_mcs_opt(d, set, WA_TR(he_rx_mcs_80p80, "Rx HE-MCS Map 80+80 MHz"), he.rx_mcs_80p80);
        add_he_mcs_opt(d, set, WA_TR(he_tx_mcs_80p80, "Tx HE-MCS Map 80+80 MHz"), he.tx_mcs_80p80);
    }
    d.close(set, start);
    d.add(std::move(set));
    if (he.phy_bit(55)) {
        d.rest(d.root(), WA_TR(he_ppe_thresholds, "PPE Thresholds"));
    }
    return he;
}

ElementValue decode_he_operation(Decoder& d) {
    HeOperation op;
    auto params = d.bits(WA_TR(he_operation_parameters, "HE Operation Parameters"), 3);
    if (!params) {
        return {};
    }
    op.parameters = static_cast<std::uint32_t>(params->get(0, 24));
    params->number(0, 3, WA_TR(he_default_pe, "Default PE Duration"));
    params->flag(3, WA_TR(he_twt_required, "TWT Required"));
    params->number(4, 10, WA_TR(he_txop_rts_threshold, "TXOP Duration RTS Threshold"));
    const bool vht_present =
        params->flag(14, WA_TR(he_vht_info_present, "VHT Operation Information Present"));
    const bool cohosted = params->flag(15, WA_TR(he_cohosted_bss, "Co-Hosted BSS"));
    params->flag(16, WA_TR(he_er_su_disable, "ER SU Disable"));
    const bool six_ghz =
        params->flag(17, WA_TR(he_6ghz_info_present, "6 GHz Operation Information Present"));
    d.add(params->take());

    auto color = d.bits(WA_TR(he_bss_color_info, "BSS Color Information"), 1);
    if (!color) {
        return op;
    }
    op.bss_color = static_cast<std::uint8_t>(color->number(0, 6, WA_TR(he_bss_color, "BSS Color")));
    op.partial_bss_color = color->flag(6, WA_TR(he_partial_bss_color, "Partial BSS Color"));
    op.bss_color_disabled = color->flag(7, WA_TR(he_bss_color_disabled, "BSS Color Disabled"));
    d.add(color->take());

    if (const auto v = peek_u16(d)) {
        op.basic_mcs_map = *v;
    }
    add_mcs_map(d, d.root(), WA_TR(he_basic_mcs, "Basic HE-MCS and NSS Set"), he_mcs_name);

    if (vht_present) {
        const auto start = d.offset();
        auto vht = d.group(WA_TR(he_vht_operation_info, "VHT Operation Information"));
        const auto width = d.u8(vht, WA_TR(vht_operation_width, "Channel Width"));
        const auto ccfs0 = d.u8(vht, WA_TR(vht_ccfs0, "Channel Center Frequency Segment 0"));
        const auto ccfs1 = d.u8(vht, WA_TR(vht_ccfs1, "Channel Center Frequency Segment 1"));
        if (width && ccfs0 && ccfs1) {
            op.vht_operation = VhtOperation{
                .channel_width = *width, .ccfs0 = *ccfs0, .ccfs1 = *ccfs1, .basic_mcs_map = 0};
        }
        d.close(vht, start);
        d.add(std::move(vht));
    }
    if (cohosted) {
        op.max_cohosted_bssid_indicator =
            d.u8(d.root(), WA_TR(he_max_cohosted, "Max Co-Hosted BSSID Indicator"));
    }
    if (six_ghz) {
        const auto start = d.offset();
        auto info = d.group(WA_TR(he_6ghz_operation, "6 GHz Operation Information"));
        He6GhzOperation six;
        const auto primary = d.u8(info, WA_TR(he_6ghz_primary, "Primary Channel"));
        auto control = d.bits(WA_TR(he_6ghz_control, "Control"), 1);
        if (primary && control) {
            six.primary_channel = *primary;
            six.channel_width = static_cast<std::uint8_t>(control->enumeration(
                0, 2, WA_TR(he_6ghz_width, "Channel Width"), [](std::uint64_t v) -> Text {
                    constexpr std::array<Text, 4> names{"20 MHz", "40 MHz", "80 MHz",
                                                        "160/80+80 MHz"};
                    return table_name(names, v);
                }));
            six.duplicate_beacon = control->flag(2, WA_TR(he_6ghz_dup_beacon, "Duplicate Beacon"));
            // Regulatory Info is B3-B6 (4 bits); values 3, 7 and 8 from IEEE 802.11-2024,
            // cross-checked with Wireshark master a9349d7b (he_regulatory_info_rvals).
            six.regulatory_info = static_cast<std::uint8_t>(control->enumeration(
                3, 4, WA_TR(he_6ghz_regulatory, "Regulatory Info"), [](std::uint64_t v) -> Text {
                    constexpr std::array<Text, 9> names{
                        WA_TR(he_6ghz_indoor, "Indoor AP"),
                        WA_TR(he_6ghz_standard_power, "Standard Power AP"),
                        WA_TR(he_6ghz_very_low_power, "Very Low Power AP"),
                        WA_TR(he_6ghz_indoor_enabled, "Indoor Enabled AP"),
                        Text{},
                        Text{},
                        Text{},
                        WA_TR(he_6ghz_role_not_relevant, "AP Role Not Relevant"),
                        WA_TR(he_6ghz_indoor_standard_power, "Indoor Standard Power AP")};
                    return table_name(names, v);
                }));
            info.children.push_back(control->take());
            const auto c0 = d.u8(info, WA_TR(vht_ccfs0, "Channel Center Frequency Segment 0"));
            const auto c1 = d.u8(info, WA_TR(vht_ccfs1, "Channel Center Frequency Segment 1"));
            const auto min_rate = d.u8(info, WA_TR(he_6ghz_min_rate, "Minimum Rate"), Unit::mbps);
            if (c0 && c1 && min_rate) {
                six.ccfs0 = *c0;
                six.ccfs1 = *c1;
                six.minimum_rate = *min_rate;
                op.six_ghz = six;
            }
        }
        d.close(info, start);
        d.add(std::move(info));
    }
    return op;
}

ElementValue decode_mu_edca_parameter_set(Decoder& d) {
    d.u8(d.root(), WA_TR(wmm_qos_info, "QoS Info"), Unit::none, Display::hex);
    for (int i = 0; i < 4 && !d.reader().empty(); ++i) {
        edca_ac_record(d, d.root(), true, nullptr);
    }
    return {};
}

ElementValue decode_spatial_reuse(Decoder& d) {
    auto control = d.bits(WA_TR(sr_control, "SR Control"), 1);
    if (!control) {
        return {};
    }
    control->flag(0, WA_TR(sr_psr_disallowed, "PSR Disallowed"));
    control->flag(1, WA_TR(sr_non_srg_disallowed, "Non-SRG OBSS PD SR Disallowed"));
    const bool non_srg_offset =
        control->flag(2, WA_TR(sr_non_srg_offset_present, "Non-SRG Offset Present"));
    const bool srg = control->flag(3, WA_TR(sr_srg_info_present, "SRG Information Present"));
    control->flag(4, WA_TR(sr_value15_allowed, "HESIGA Spatial Reuse Value15 Allowed"));
    d.add(control->take());
    if (non_srg_offset) {
        d.u8(d.root(), WA_TR(sr_non_srg_max_offset, "Non-SRG OBSS PD Max Offset"), Unit::db);
    }
    if (srg) {
        d.u8(d.root(), WA_TR(sr_srg_min_offset, "SRG OBSS PD Min Offset"), Unit::db);
        d.u8(d.root(), WA_TR(sr_srg_max_offset, "SRG OBSS PD Max Offset"), Unit::db);
        d.bytes(d.root(), WA_TR(sr_srg_color_bitmap, "SRG BSS Color Bitmap"), 8);
        d.bytes(d.root(), WA_TR(sr_srg_bssid_bitmap, "SRG Partial BSSID Bitmap"), 8);
    }
    return {};
}

ElementValue decode_bss_color_change(Decoder& d) {
    d.u8(d.root(), WA_TR(bss_color_countdown, "Color Switch Countdown"));
    if (auto info = d.bits(WA_TR(bss_color_new_info, "New BSS Color Information"), 1)) {
        info->number(0, 6, WA_TR(bss_color_new, "New BSS Color"));
        d.add(info->take());
    }
    return {};
}

ElementValue decode_multiple_bssid_configuration(Decoder& d) {
    d.u8(d.root(), WA_TR(mbssid_config_count, "BSSID Count"));
    d.u8(d.root(), WA_TR(mbssid_config_periodicity, "Full Set Rx Periodicity"));
    return {};
}

ElementValue decode_non_inheritance(Decoder& d) {
    const auto start = d.offset();
    auto ids = d.group(WA_TR(non_inheritance_ids, "Element IDs"));
    const auto n = d.u8(ids, msg::length);
    for (std::uint8_t i = 0; n && i < *n; ++i) {
        if (!d.u8(ids, WA_TR(non_inheritance_id, "Element ID"))) {
            break;
        }
    }
    d.close(ids, start);
    d.add(std::move(ids));
    const auto ext_start = d.offset();
    auto ext = d.group(WA_TR(non_inheritance_ext_ids, "Element ID Extensions"));
    const auto m = d.u8(ext, msg::length);
    for (std::uint8_t i = 0; m && i < *m; ++i) {
        if (!d.u8(ext, WA_TR(non_inheritance_ext_id, "Element ID Extension"))) {
            break;
        }
    }
    d.close(ext, ext_start);
    d.add(std::move(ext));
    return {};
}

ElementValue decode_short_ssid_list(Decoder& d) {
    while (d.remaining() >= 4) {
        d.u32(d.root(), WA_TR(rnr_short_ssid, "Short SSID"), Unit::none, Display::hex);
    }
    return {};
}

ElementValue decode_he_6ghz_band_capabilities(Decoder& d) {
    if (auto caps = d.bits(WA_TR(he_6ghz_capabilities, "Capabilities Information"), 2)) {
        caps->number(0, 3, WA_TR(he_6ghz_min_mpdu_spacing, "Minimum MPDU Start Spacing"));
        const auto e = caps->get(3, 3);
        caps->computed(3, 3, WA_TR(he_6ghz_max_ampdu, "Maximum A-MPDU Length"),
                       (std::uint64_t{1} << (13 + e)) - 1, Unit::octets);
        caps->enumeration(
            6, 2, WA_TR(vht_max_mpdu_length, "Maximum MPDU Length"), [](std::uint64_t v) -> Text {
                constexpr std::array<Text, 4> names{"3895", "7991", "11454", msg::reserved};
                return table_name(names, v);
            });
        caps->number(9, 2, WA_TR(he_6ghz_sm_ps, "SM Power Save"));
        caps->flag(11, WA_TR(ht_rd_responder, "RD Responder"));
        caps->flag(12, WA_TR(vht_rx_antenna_consistency, "Rx Antenna Pattern Consistency"));
        caps->flag(13, WA_TR(vht_tx_antenna_consistency, "Tx Antenna Pattern Consistency"));
        d.add(caps->take());
    }
    return {};
}

} // namespace wifi_analyze::ie
