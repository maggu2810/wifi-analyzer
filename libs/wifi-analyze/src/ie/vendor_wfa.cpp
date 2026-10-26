// SPDX-License-Identifier: MIT
// Vendor-specific elements with Wi-Fi Alliance OUI 50:6F:9A. References: Wi-Fi P2P Technical
// Specification (type 0x09), Hotspot 2.0 Specification (0x10), Multi Band Operation and Optimized
// Connectivity Experience specifications (0x16), Wi-Fi Enhanced Open / OWE transition mode
// (0x1C).

#include <array>
#include <string>

#include "ie/decoders.hpp"

namespace wifi_analyze::ie {
namespace {

using core::BitField;
using core::table_name;

void read_vendor_type(Decoder& d) {
    d.u8(d.root(), WA_TR(vendor_type, "Vendor Type"));
}

MessageId p2p_attribute_label(std::uint8_t id) {
    switch (id) {
    case 0:
        return WA_TR(p2p_status, "Status");
    case 1:
        return WA_TR(p2p_minor_reason, "Minor Reason Code");
    case 2:
        return WA_TR(p2p_capability, "P2P Capability");
    case 3:
        return WA_TR(p2p_device_id, "P2P Device ID");
    case 4:
        return WA_TR(p2p_go_intent, "Group Owner Intent");
    case 5:
        return WA_TR(p2p_config_timeout, "Configuration Timeout");
    case 6:
        return WA_TR(p2p_listen_channel, "Listen Channel");
    case 7:
        return WA_TR(p2p_group_bssid, "P2P Group BSSID");
    case 8:
        return WA_TR(p2p_ext_listen_timing, "Extended Listen Timing");
    case 9:
        return WA_TR(p2p_intended_address, "Intended P2P Interface Address");
    case 10:
        return WA_TR(p2p_manageability, "P2P Manageability");
    case 11:
        return WA_TR(p2p_channel_list, "Channel List");
    case 12:
        return WA_TR(p2p_notice_of_absence, "Notice of Absence");
    case 13:
        return WA_TR(p2p_device_info, "P2P Device Info");
    case 14:
        return WA_TR(p2p_group_info, "P2P Group Info");
    case 15:
        return WA_TR(p2p_group_id, "P2P Group ID");
    case 16:
        return WA_TR(p2p_interface, "P2P Interface");
    case 17:
        return WA_TR(p2p_operating_channel, "Operating Channel");
    case 18:
        return WA_TR(p2p_invitation_flags, "Invitation Flags");
    case 221:
        return WA_TR(adv_vendor, "Vendor Specific");
    default:
        return WA_TR(p2p_unknown_attribute, "Unknown Attribute");
    }
}

MessageId mbo_attribute_label(std::uint8_t id) {
    switch (id) {
    case 1:
        return WA_TR(mbo_ap_capability, "MBO AP Capability Indication");
    case 2:
        return WA_TR(mbo_non_preferred_channels, "Non-preferred Channel Report");
    case 3:
        return WA_TR(mbo_cellular_capabilities, "Cellular Data Capabilities");
    case 4:
        return WA_TR(mbo_association_disallowed, "Association Disallowed");
    case 5:
        return WA_TR(mbo_cellular_preference, "Cellular Data Connection Preference");
    case 6:
        return WA_TR(mbo_transition_reason, "Transition Reason Code");
    case 7:
        return WA_TR(mbo_transition_rejection, "Transition Rejection Reason Code");
    case 8:
        return WA_TR(mbo_association_retry_delay, "Association Retry Delay");
    case 101:
        return WA_TR(oce_capability, "OCE Capability Indication");
    case 102:
        return WA_TR(oce_rssi_rejection, "RSSI-based (Re)Association Rejection");
    case 103:
        return WA_TR(oce_reduced_wan_metrics, "Reduced WAN Metrics");
    case 104:
        return WA_TR(oce_rnr_completeness, "RNR Completeness");
    default:
        return WA_TR(mbo_unknown_attribute, "Unknown Attribute");
    }
}

} // namespace

ElementValue decode_vendor_p2p(Decoder& d) {
    read_vendor_type(d);
    while (d.remaining() >= 3) {
        const auto start = d.offset();
        const auto id = d.reader().u8();
        const auto length = d.reader().u16le();
        if (!id || !length) {
            break;
        }
        const auto value_start = d.offset();
        const auto value = d.reader().bytes(*length);
        if (!value) {
            d.reader().rest();
            d.malformed();
            break;
        }
        const auto range = ByteRange{.offset = start, .length = 3U + *length};
        auto node = Decoder::node(p2p_attribute_label(*id), {}, range);
        const auto& v = *value;
        if (*id == 2 && *length == 2) {
            BitField dev{Decoder::node(WA_TR(p2p_device_capability, "Device Capability Bitmap"),
                                       std::uint64_t{v[0]},
                                       ByteRange{.offset = value_start, .length = 1}),
                         {v[0]}};
            dev.node().display = Display::hex;
            dev.flag(0, WA_TR(p2p_service_discovery, "Service Discovery"));
            dev.flag(1, WA_TR(p2p_client_discoverability, "P2P Client Discoverability"));
            dev.flag(2, WA_TR(p2p_concurrent, "Concurrent Operation"));
            dev.flag(3, WA_TR(p2p_infrastructure_managed, "P2P Infrastructure Managed"));
            dev.flag(4, WA_TR(p2p_device_limit, "P2P Device Limit"));
            dev.flag(5, WA_TR(p2p_invitation, "P2P Invitation Procedure"));
            node.children.push_back(dev.take());
            BitField grp{Decoder::node(WA_TR(p2p_group_capability, "Group Capability Bitmap"),
                                       std::uint64_t{v[1]},
                                       ByteRange{.offset = value_start + 1, .length = 1}),
                         {v[1]}};
            grp.node().display = Display::hex;
            grp.flag(0, WA_TR(p2p_group_owner, "P2P Group Owner"));
            grp.flag(1, WA_TR(p2p_persistent_group, "Persistent P2P Group"));
            grp.flag(2, WA_TR(p2p_group_limit, "P2P Group Limit"));
            grp.flag(3, WA_TR(p2p_intra_bss, "Intra-BSS Distribution"));
            grp.flag(4, WA_TR(p2p_cross_connection, "Cross Connection"));
            grp.flag(5, WA_TR(p2p_persistent_reconnect, "Persistent Reconnect"));
            grp.flag(6, WA_TR(p2p_group_formation, "Group Formation"));
            grp.flag(7, WA_TR(p2p_ip_allocation, "IP Address Allocation"));
            node.children.push_back(grp.take());
        } else if ((*id == 3 || *id == 7 || *id == 9) && *length == 6) {
            node.value = core::format_mac(v);
        } else if (*id == 13 && *length >= 17) {
            node.children.push_back(Decoder::node(WA_TR(p2p_device_address, "P2P Device Address"),
                                                  core::format_mac(v.subspan(0, 6)),
                                                  ByteRange{.offset = value_start, .length = 6}));
            const std::size_t secondary = v[16];
            const std::size_t name_pos = 17 + (secondary * 8);
            if (name_pos + 4 <= v.size()) {
                const auto name_len =
                    static_cast<std::size_t>((v[name_pos + 2] << 8U) | v[name_pos + 3]);
                if (name_pos + 4 + name_len <= v.size()) {
                    node.children.push_back(Decoder::node(
                        WA_TR(wps_device_name, "Device Name"),
                        core::display_text(v.subspan(name_pos + 4, name_len)),
                        ByteRange{.offset = value_start + name_pos, .length = 4 + name_len}));
                }
            }
            node.children.push_back(
                Decoder::node(msg::data, std::vector<std::uint8_t>(v.begin(), v.end()),
                              ByteRange{.offset = value_start, .length = *length}));
        } else {
            node.value = std::vector<std::uint8_t>(v.begin(), v.end());
        }
        d.add(std::move(node));
    }
    return {};
}

ElementValue decode_vendor_hs20(Decoder& d) {
    read_vendor_type(d);
    auto indication = d.bits(WA_TR(hs20_indication, "Hotspot 2.0 Indication"), 1);
    if (!indication) {
        return {};
    }
    Hs20Indication hs;
    hs.dgaf_disabled = indication->flag(0, WA_TR(hs20_dgaf_disabled, "DGAF Disabled"));
    const bool pps_mo = indication->flag(1, WA_TR(hs20_pps_mo_present, "PPS MO ID Present"));
    const bool anqp_domain =
        indication->flag(2, WA_TR(hs20_anqp_domain_present, "ANQP Domain ID Present"));
    hs.release = static_cast<std::uint8_t>(indication->enumeration(
        4, 4, WA_TR(hs20_release, "Release Number"), [](std::uint64_t v) -> Text {
            constexpr std::array<Text, 3> names{"Release 1", "Release 2", "Release 3"};
            return table_name(names, v);
        }));
    d.add(indication->take());
    if (pps_mo) {
        d.u16(d.root(), WA_TR(hs20_pps_mo_id, "PPS MO ID"));
    }
    if (anqp_domain) {
        d.u16(d.root(), WA_TR(hs20_anqp_domain_id, "ANQP Domain ID"));
    }
    return hs;
}

ElementValue decode_vendor_mbo_oce(Decoder& d) {
    read_vendor_type(d);
    while (d.remaining() >= 2) {
        const auto start = d.offset();
        const auto header = d.reader().array<2>();
        if (!header) {
            break;
        }
        const auto id = (*header)[0];
        const auto length = (*header)[1];
        const auto value_start = d.offset();
        const auto value = d.reader().bytes(length);
        if (!value) {
            d.reader().rest();
            d.malformed();
            break;
        }
        const auto range = ByteRange{.offset = start, .length = 2U + length};
        auto node = Decoder::node(mbo_attribute_label(id), {}, range);
        const auto& v = *value;
        if (id == 1 && length == 1) {
            BitField b{Decoder::node(WA_TR(mbo_capability_bits, "Capability"), std::uint64_t{v[0]},
                                     ByteRange{.offset = value_start, .length = 1}),
                       {v[0]}};
            b.node().display = Display::hex;
            b.flag(6, WA_TR(mbo_cellular_aware, "Cellular Data Aware"));
            node.children.push_back(b.take());
        } else if (id == 4 && length == 1) {
            constexpr std::array<Text, 6> names{
                msg::reserved,
                WA_TR(mbo_disallowed_unspecified, "Unspecified reason"),
                WA_TR(mbo_disallowed_max_sta, "Maximum number of associated STAs reached"),
                WA_TR(mbo_disallowed_overloaded, "Air interface is overloaded"),
                WA_TR(mbo_disallowed_auth_overloaded, "Authentication server overloaded"),
                WA_TR(mbo_disallowed_rssi, "Insufficient RSSI")};
            node.value = EnumValue{.raw = v[0], .name = table_name(names, v[0])};
            d.diagnostic(
                Severity::info,
                WA_TR(mbo_association_disallowed_diag, "AP currently disallows association"), {},
                range);
        } else if (id == 101 && length == 1) {
            BitField b{Decoder::node(WA_TR(mbo_capability_bits, "Capability"), std::uint64_t{v[0]},
                                     ByteRange{.offset = value_start, .length = 1}),
                       {v[0]}};
            b.node().display = Display::hex;
            b.number(0, 3, WA_TR(oce_version, "OCE Version"));
            b.flag(3, WA_TR(oce_sta_cfon, "STA-CFON"));
            b.flag(4, WA_TR(oce_11b_only_ap, "11b-only AP Present"));
            b.flag(5, WA_TR(oce_hlp, "HLP Enabled"));
            b.flag(6, WA_TR(oce_non_oce_ap, "Non-OCE AP Present"));
            node.children.push_back(b.take());
        } else if (id == 8 && length == 2) {
            node.value = std::uint64_t{static_cast<std::uint16_t>(v[0] | (v[1] << 8U))};
            node.unit = Unit::none;
        } else {
            node.value = std::vector<std::uint8_t>(v.begin(), v.end());
        }
        d.add(std::move(node));
    }
    return {};
}

ElementValue decode_vendor_owe_transition(Decoder& d) {
    read_vendor_type(d);
    OweTransition owe;
    const auto bssid = d.mac(d.root(), WA_TR(common_bssid, "BSSID"));
    const auto ssid_length = d.u8(d.root(), WA_TR(owe_ssid_length, "SSID Length"));
    if (!bssid || !ssid_length) {
        return {};
    }
    owe.bssid = *bssid;
    const auto start = d.offset();
    const auto ssid = d.reader().bytes(*ssid_length);
    if (!ssid) {
        d.malformed();
        return owe;
    }
    owe.ssid.assign(ssid->begin(), ssid->end());
    d.add(Decoder::node(WA_TR(ssid_name, "SSID"), core::display_text(*ssid), d.range_from(start)));
    if (d.remaining() >= 2) {
        owe.operating_class = d.u8(d.root(), WA_TR(common_operating_class, "Operating Class"));
        owe.channel = d.u8(d.root(), WA_TR(common_channel, "Channel"));
    }
    return owe;
}

} // namespace wifi_analyze::ie
