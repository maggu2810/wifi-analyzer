// SPDX-License-Identifier: MIT
// EHT (802.11be, Wi-Fi 7) extension elements. Reference: IEEE Std 802.11be-2024, EHT Operation
// (ext 106), Multi-Link (ext 107), EHT Capabilities (ext 108).

#include <array>
#include <string>

#include "ie/decoders.hpp"

namespace wifi_analyze::ie {
namespace {

using core::BitField;
using core::table_name;

Text eht_width_name(std::uint64_t v) {
    constexpr std::array<Text, 5> names{"20 MHz", "40 MHz", "80 MHz", "160 MHz", "320 MHz"};
    return table_name(names, v);
}

/// One EHT-MCS map for a bandwidth: 3 octets (MCS 0-9, 10-11, 12-13), Rx nibble then Tx nibble.
std::optional<EhtMcsMap> eht_mcs_map(Decoder& d, TreeNode& parent, MessageId label) {
    auto b = d.bits(label, 3);
    if (!b) {
        return std::nullopt;
    }
    EhtMcsMap map;
    constexpr std::array<MessageId, 3> rx{WA_TR(eht_rx_nss_0_9, "Rx Max NSS for MCS 0-9"),
                                          WA_TR(eht_rx_nss_10_11, "Rx Max NSS for MCS 10-11"),
                                          WA_TR(eht_rx_nss_12_13, "Rx Max NSS for MCS 12-13")};
    constexpr std::array<MessageId, 3> tx{WA_TR(eht_tx_nss_0_9, "Tx Max NSS for MCS 0-9"),
                                          WA_TR(eht_tx_nss_10_11, "Tx Max NSS for MCS 10-11"),
                                          WA_TR(eht_tx_nss_12_13, "Tx Max NSS for MCS 12-13")};
    for (unsigned i = 0; i < 3; ++i) {
        map.rx_max_nss[i] = static_cast<std::uint8_t>(b->number(i * 8, 4, rx[i]));
        map.tx_max_nss[i] = static_cast<std::uint8_t>(b->number((i * 8) + 4, 4, tx[i]));
    }
    parent.children.push_back(b->take());
    return map;
}

void eht_phy_capabilities(BitField& b) {
    b.flag(1, WA_TR(eht_320_6ghz, "Support for 320 MHz in 6 GHz"));
    b.flag(2, WA_TR(eht_242_ru_wide, "Support for 242-tone RU in BW Wider Than 20 MHz"));
    b.flag(3, WA_TR(eht_ndp_4x_ltf, "NDP with 4x EHT-LTF and 3.2 µs GI"));
    b.flag(4, WA_TR(eht_partial_bw_ul_mu_mimo, "Partial Bandwidth UL MU-MIMO"));
    b.flag(5, WA_TR(eht_su_beamformer, "SU Beamformer"));
    b.flag(6, WA_TR(eht_su_beamformee, "SU Beamformee"));
    b.number(7, 3, WA_TR(eht_beamformee_ss_80, "Beamformee SS (<= 80 MHz)"), Unit::none, 1);
    b.number(10, 3, WA_TR(eht_beamformee_ss_160, "Beamformee SS (160 MHz)"), Unit::none, 1);
    b.number(13, 3, WA_TR(eht_beamformee_ss_320, "Beamformee SS (320 MHz)"), Unit::none, 1);
    b.number(16, 3, WA_TR(eht_sounding_80, "Number of Sounding Dimensions (<= 80 MHz)"), Unit::none,
             1);
    b.number(19, 3, WA_TR(eht_sounding_160, "Number of Sounding Dimensions (160 MHz)"), Unit::none,
             1);
    b.number(22, 3, WA_TR(eht_sounding_320, "Number of Sounding Dimensions (320 MHz)"), Unit::none,
             1);
    b.flag(25, WA_TR(eht_ng16_su, "Ng = 16 SU Feedback"));
    b.flag(26, WA_TR(eht_ng16_mu, "Ng = 16 MU Feedback"));
    b.flag(27, WA_TR(eht_codebook_42_su, "Codebook Size {4, 2} SU Feedback"));
    b.flag(28, WA_TR(eht_codebook_75_mu, "Codebook Size {7, 5} MU Feedback"));
    b.flag(29, WA_TR(eht_triggered_su_bf, "Triggered SU Beamforming Feedback"));
    b.flag(30, WA_TR(eht_triggered_mu_bf, "Triggered MU Beamforming Partial BW Feedback"));
    b.flag(31, WA_TR(eht_triggered_cqi, "Triggered CQI Feedback"));
    b.flag(32, WA_TR(eht_partial_bw_dl_mu_mimo, "Partial Bandwidth DL MU-MIMO"));
    b.flag(33, WA_TR(eht_psr_sr, "EHT PSR-Based SR Support"));
    b.flag(34, WA_TR(eht_power_boost, "Power Boost Factor Support"));
    b.flag(35, WA_TR(eht_mu_4x_ltf, "EHT MU PPDU with 4x EHT-LTF and 0.8 µs GI"));
    b.number(36, 4, WA_TR(eht_max_nc, "Max Nc"));
    b.flag(40, WA_TR(eht_non_triggered_cqi, "Non-Triggered CQI Feedback"));
    b.flag(41, WA_TR(eht_tx_4096qam_small_ru, "Tx 1024-QAM and 4096-QAM < 242-tone RU"));
    b.flag(42, WA_TR(eht_rx_4096qam_small_ru, "Rx 1024-QAM and 4096-QAM < 242-tone RU"));
    b.flag(43, WA_TR(eht_ppe_present, "PPE Thresholds Present"));
}

} // namespace

ElementValue decode_eht_operation(Decoder& d) {
    EhtOperation op;
    auto params = d.bits(WA_TR(eht_operation_parameters, "EHT Operation Parameters"), 1);
    if (!params) {
        return {};
    }
    op.parameters = static_cast<std::uint8_t>(params->get(0, 8));
    const bool info_present =
        params->flag(0, WA_TR(eht_op_info_present, "EHT Operation Information Present"));
    const bool disabled_present =
        params->flag(1, WA_TR(eht_disabled_bitmap_present, "Disabled Subchannel Bitmap Present"));
    params->flag(2, WA_TR(eht_default_pe, "EHT Default PE Duration"));
    params->flag(3, WA_TR(eht_group_bu_limit, "Group Addressed BU Indication Limit"));
    params->number(4, 2, WA_TR(eht_group_bu_exponent, "Group Addressed BU Indication Exponent"));
    d.add(params->take());

    if (const auto basic =
            d.bytes(d.root(), WA_TR(eht_basic_mcs, "Basic EHT-MCS and NSS Set"), 4)) {
        std::ranges::copy(*basic, op.basic_mcs.begin());
    } else {
        return op;
    }

    if (info_present) {
        const auto start = d.offset();
        auto info = d.group(WA_TR(eht_operation_info, "EHT Operation Information"));
        EhtOperationInfo i;
        auto control = d.bits(WA_TR(eht_control, "Control"), 1);
        if (control) {
            i.channel_width = static_cast<std::uint8_t>(control->enumeration(
                0, 3, WA_TR(eht_channel_width, "Channel Width"), eht_width_name));
            info.children.push_back(control->take());
        }
        const auto c0 = d.u8(info, WA_TR(vht_ccfs0, "Channel Center Frequency Segment 0"));
        const auto c1 = d.u8(info, WA_TR(vht_ccfs1, "Channel Center Frequency Segment 1"));
        if (control && c0 && c1) {
            i.ccfs0 = *c0;
            i.ccfs1 = *c1;
            if (disabled_present) {
                auto bitmap =
                    d.bits(WA_TR(eht_disabled_subchannels, "Disabled Subchannel Bitmap"), 2);
                if (bitmap) {
                    i.disabled_subchannels = static_cast<std::uint16_t>(bitmap->get(0, 16));
                    for (unsigned s = 0; s < 16; ++s) {
                        if (bitmap->test(s)) {
                            bitmap->computed(
                                s, 1, WA_TR(eht_disabled_subchannel, "Disabled 20 MHz Subchannel"),
                                std::uint64_t{s});
                        }
                    }
                    info.children.push_back(bitmap->take());
                }
            }
            op.info = i;
        }
        d.close(info, start);
        d.add(std::move(info));
    }
    return op;
}

ElementValue decode_eht_capabilities(Decoder& d) {
    EhtCapabilities eht;
    auto mac = d.bits(WA_TR(eht_mac_capabilities, "EHT MAC Capabilities Information"), 2);
    if (!mac) {
        return {};
    }
    eht.mac = static_cast<std::uint16_t>(mac->get(0, 16));
    mac->flag(0, WA_TR(eht_epcs, "EPCS Priority Access Support"));
    mac->flag(1, WA_TR(eht_om_control, "EHT OM Control Support"));
    mac->flag(2, WA_TR(eht_txop_sharing_1, "Triggered TXOP Sharing Mode 1 Support"));
    mac->flag(3, WA_TR(eht_txop_sharing_2, "Triggered TXOP Sharing Mode 2 Support"));
    mac->flag(4, WA_TR(eht_restricted_twt, "Restricted TWT Support"));
    mac->flag(5, WA_TR(eht_scs_traffic_description, "SCS Traffic Description Support"));
    mac->enumeration(
        6, 2, WA_TR(vht_max_mpdu_length, "Maximum MPDU Length"), [](std::uint64_t v) -> Text {
            constexpr std::array<Text, 4> names{"3895", "7991", "11454", msg::reserved};
            return table_name(names, v);
        });
    mac->flag(8, WA_TR(eht_max_ampdu_exp_ext, "Maximum A-MPDU Length Exponent Extension"));
    d.add(mac->take());

    auto phy = d.bits(WA_TR(eht_phy_capabilities, "EHT PHY Capabilities Information"), 9);
    if (!phy) {
        return eht;
    }
    std::ranges::copy(phy->data(), eht.phy.begin());
    eht_phy_capabilities(*phy);
    d.add(phy->take());

    // Which MCS maps follow depends on the HE Capabilities of the same frame.
    const auto* he = d.previous<HeCapabilities>();
    auto set = d.group(WA_TR(eht_mcs_nss_set, "Supported EHT-MCS and NSS Set"));
    const auto start = d.offset();
    const bool has_160 = he != nullptr ? he->supports_160mhz() : d.remaining() >= 6;
    eht.mcs_80 = eht_mcs_map(d, set, WA_TR(eht_mcs_80, "EHT-MCS Map (BW <= 80 MHz)"));
    if (has_160 && d.remaining() >= 3) {
        eht.mcs_160 = eht_mcs_map(d, set, WA_TR(eht_mcs_160, "EHT-MCS Map (BW = 160 MHz)"));
    }
    if (eht.supports_320mhz() && d.remaining() >= 3) {
        eht.mcs_320 = eht_mcs_map(d, set, WA_TR(eht_mcs_320, "EHT-MCS Map (BW = 320 MHz)"));
    }
    d.close(set, start);
    d.add(std::move(set));
    if (eht.phy_bit(43)) {
        d.rest(d.root(), WA_TR(he_ppe_thresholds, "PPE Thresholds"));
    }
    return eht;
}

ElementValue decode_multi_link(Decoder& d) {
    MultiLink ml;
    auto control = d.bits(WA_TR(ml_control, "Multi-Link Control"), 2);
    if (!control) {
        return {};
    }
    ml.type = static_cast<std::uint8_t>(
        control->enumeration(0, 3, WA_TR(ml_type, "Type"), [](std::uint64_t v) -> Text {
            constexpr std::array<Text, 5> names{
                WA_TR(ml_type_basic, "Basic"), WA_TR(ml_type_probe, "Probe Request"),
                WA_TR(ml_type_reconfiguration, "Reconfiguration"), "TDLS",
                WA_TR(ml_type_priority_access, "Priority Access")};
            return table_name(names, v);
        }));
    if (ml.type != 0) {
        control->number(4, 12, WA_TR(ml_presence_bitmap, "Presence Bitmap"));
        d.add(control->take());
        d.rest(d.root(), msg::data);
        return ml;
    }
    const bool link_id_present =
        control->flag(4, WA_TR(ml_link_id_present, "Link ID Info Present"));
    const bool change_count_present =
        control->flag(5, WA_TR(ml_change_count_present, "BSS Parameters Change Count Present"));
    const bool sync_present = control->flag(
        6, WA_TR(ml_sync_present, "Medium Synchronization Delay Information Present"));
    const bool eml_present = control->flag(7, WA_TR(ml_eml_present, "EML Capabilities Present"));
    const bool mld_caps_present =
        control->flag(8, WA_TR(ml_mld_caps_present, "MLD Capabilities and Operations Present"));
    const bool mld_id_present = control->flag(9, WA_TR(ml_mld_id_present, "AP MLD ID Present"));
    const bool ext_caps_present = control->flag(
        10, WA_TR(ml_ext_caps_present, "Extended MLD Capabilities and Operations Present"));
    d.add(control->take());

    // Common Info
    const auto common_start = d.offset();
    auto common = d.group(WA_TR(ml_common_info, "Common Info"));
    const auto common_length = d.u8(common, WA_TR(ml_common_length, "Common Info Length"));
    ml.mld_mac = d.mac(common, WA_TR(ml_mld_mac, "MLD MAC Address"));
    if (link_id_present) {
        if (auto b = d.bits(WA_TR(ml_link_id_info, "Link ID Info"), 1)) {
            ml.link_id = static_cast<std::uint8_t>(b->number(0, 4, WA_TR(mlo_link_id, "Link ID")));
            common.children.push_back(b->take());
        }
    }
    if (change_count_present) {
        d.u8(common, WA_TR(rnr_bss_change_count, "BSS Parameters Change Count"));
    }
    if (sync_present) {
        d.u16(common, WA_TR(ml_sync_info, "Medium Synchronization Delay Information"), Unit::none,
              Display::hex);
    }
    if (eml_present) {
        if (auto b = d.bits(WA_TR(ml_eml_capabilities, "EML Capabilities"), 2)) {
            b->flag(0, WA_TR(ml_emlsr, "EMLSR Support"));
            b->flag(7, WA_TR(ml_emlmr, "EMLMR Support"));
            common.children.push_back(b->take());
        }
    }
    if (mld_caps_present) {
        if (auto b = d.bits(WA_TR(ml_mld_capabilities, "MLD Capabilities and Operations"), 2)) {
            ml.max_simultaneous_links = static_cast<std::uint8_t>(b->number(
                0, 4, WA_TR(ml_max_links, "Maximum Number of Simultaneous Links"), Unit::none, 1));
            b->flag(4, WA_TR(ml_srs, "SRS Support"));
            b->number(5, 2, WA_TR(ml_t2lm_support, "TID-to-Link Mapping Negotiation Support"));
            common.children.push_back(b->take());
        }
    }
    if (mld_id_present) {
        ml.ap_mld_id = d.u8(common, WA_TR(rnr_ap_mld_id, "AP MLD ID"));
    }
    if (ext_caps_present) {
        d.u16(common, WA_TR(ml_ext_capabilities, "Extended MLD Capabilities and Operations"),
              Unit::none, Display::hex);
    }
    if (common_length && d.offset() < common_start + *common_length) {
        const auto extra = common_start + *common_length - d.offset();
        d.bytes(common, msg::reserved, std::min(extra, d.remaining()));
    }
    d.close(common, common_start);
    d.add(std::move(common));

    // Link Info: subelements (0 = Per-STA Profile).
    while (d.remaining() >= 2) {
        const auto start = d.offset();
        const auto header = d.reader().array<2>();
        if (!header) {
            break;
        }
        const auto id = (*header)[0];
        const auto length = (*header)[1];
        const auto body = d.reader().bytes(length);
        if (!body) {
            d.reader().rest();
            d.malformed();
            break;
        }
        if (id != 0) {
            d.add(Decoder::node(id == element_id_vendor_specific
                                    ? WA_TR(subelement_vendor, "Vendor Specific Subelement")
                                    : WA_TR(subelement_unknown, "Unknown Subelement"),
                                std::vector<std::uint8_t>(body->begin(), body->end()),
                                ByteRange{.offset = start, .length = 2U + length}));
            continue;
        }
        auto profile = Decoder::node(WA_TR(ml_per_sta_profile, "Per-STA Profile"), {},
                                     ByteRange{.offset = start, .length = 2U + length});
        MultiLinkPerSta sta;
        if (body->size() >= 2) {
            const auto sta_control = static_cast<std::uint16_t>((*body)[0] | ((*body)[1] << 8U));
            BitField b{Decoder::node(WA_TR(ml_sta_control, "STA Control"),
                                     std::uint64_t{sta_control},
                                     ByteRange{.offset = start + 2, .length = 2}),
                       {(*body)[0], (*body)[1]}};
            b.node().display = Display::hex;
            sta.link_id = static_cast<std::uint8_t>(b.number(0, 4, WA_TR(mlo_link_id, "Link ID")));
            sta.complete_profile = b.flag(4, WA_TR(ml_complete_profile, "Complete Profile"));
            const bool mac_present =
                b.flag(5, WA_TR(ml_sta_mac_present, "STA MAC Address Present"));
            b.flag(6, WA_TR(ml_beacon_interval_present, "Beacon Interval Present"));
            b.flag(7, WA_TR(ml_tsf_offset_present, "TSF Offset Present"));
            b.flag(8, WA_TR(ml_dtim_info_present, "DTIM Info Present"));
            profile.children.push_back(b.take());
            // STA Info: length octet, then (optional) STA MAC address.
            if (body->size() >= 3 && mac_present && body->size() >= 9) {
                MacAddress mac{};
                std::ranges::copy(body->subspan(3, 6), mac.begin());
                sta.sta_mac = mac;
                profile.children.push_back(
                    Decoder::node(WA_TR(ml_sta_mac, "STA MAC Address"), core::format_mac(mac),
                                  ByteRange{.offset = start + 5, .length = 6}));
            }
            if (body->size() > 2) {
                profile.children.push_back(
                    Decoder::node(WA_TR(ml_sta_info_and_profile, "STA Info and STA Profile"),
                                  std::vector<std::uint8_t>(body->begin() + 2, body->end()),
                                  ByteRange{.offset = start + 4, .length = body->size() - 2}));
            }
        }
        ml.per_sta.push_back(sta);
        d.add(std::move(profile));
    }
    return ml;
}

} // namespace wifi_analyze::ie
