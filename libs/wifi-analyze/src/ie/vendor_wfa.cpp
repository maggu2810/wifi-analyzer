// SPDX-License-Identifier: MIT
// Vendor-specific elements with Wi-Fi Alliance OUI 50:6F:9A. References: Wi-Fi P2P Technical
// Specification (type 0x09), Wi-Fi Display Technical Specification (0x0A), Hotspot 2.0
// Specification (0x10 indication, 0x14 OSEN), Wi-Fi Aware / NAN Specification (0x13), Multi Band
// Operation and Optimized Connectivity Experience specifications (0x16), Wi-Fi Easy Connect / DPP
// (0x1A), Wi-Fi EasyMesh / Multi-AP Specification (0x1B), Wi-Fi Enhanced Open / OWE transition
// mode (0x1C), Wi-Fi QoS Management Specification (0x22), WPA3 Specification v3.4 RSN Overriding
// (0x29-0x2B). Cross-checked with Wireshark 4.6.9 (dissect_vendor_ie_wfa and the dissectors
// registered in "wlan.ie.wifi_alliance.subtype"; see docs/decoder-sources.md).

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

// --- Multi-AP (EasyMesh) subelements, shared with the WPS WFA vendor extension ------------

bool multi_ap_subelement(TreeNode& parent, std::uint8_t id, std::span<const std::uint8_t> v,
                         std::size_t start) {
    const auto range = ByteRange{.offset = start, .length = 2U + v.size()};
    const auto value_range = ByteRange{.offset = start + 2, .length = v.size()};
    if (id == 0x05 && v.size() == 2) {
        auto n =
            Decoder::node(WA_TR(wps_registrar_config_methods, "Registrar Configuration Methods"),
                          std::uint64_t{(static_cast<unsigned>(v[0]) << 8U) | v[1]}, range);
        n.display = Display::hex;
        parent.children.push_back(std::move(n));
    } else if (id == 0x06 && v.size() == 1) {
        BitField f{Decoder::node(WA_TR(multi_ap_extension, "Multi-AP Extension"),
                                 std::uint64_t{v[0]}, value_range),
                   {v[0]}};
        f.node().display = Display::hex;
        f.flag(7, WA_TR(multi_ap_backhaul_sta, "Backhaul STA"));
        f.flag(6, WA_TR(multi_ap_backhaul_bss, "Backhaul BSS"));
        f.flag(5, WA_TR(multi_ap_fronthaul_bss, "Fronthaul BSS"));
        f.flag(4, WA_TR(multi_ap_teardown, "Tear Down"));
        f.flag(3,
               WA_TR(multi_ap_p1_bsta_disallowed, "Profile-1 Backhaul STA Association Disallowed"));
        f.flag(2,
               WA_TR(multi_ap_p2_bsta_disallowed, "Profile-2 Backhaul STA Association Disallowed"));
        parent.children.push_back(f.take());
    } else if (id == 0x07 && v.size() == 1) {
        parent.children.push_back(
            Decoder::node(WA_TR(multi_ap_profile, "Multi-AP Profile"), std::uint64_t{v[0]}, range));
    } else if (id == 0x08 && v.size() == 2) {
        parent.children.push_back(Decoder::node(
            WA_TR(multi_ap_primary_vlan, "Primary VLAN ID"),
            std::uint64_t{static_cast<unsigned>(v[0]) | (static_cast<unsigned>(v[1]) << 8U)},
            range));
    } else {
        return false;
    }
    return true;
}

namespace {

/// Attribute list with 1-octet id and 1- or 2-octet length (big- or little-endian).
enum class LengthField : std::uint8_t { u8, u16le, u16be };

template <class LabelFn, class ValueFn>
void attribute_list(Decoder& d, LengthField length_field, LabelFn label, ValueFn value) {
    const std::size_t header = length_field == LengthField::u8 ? 2 : 3;
    while (d.remaining() >= header) {
        const auto start = d.offset();
        const auto id = d.reader().u8().value_or(0);
        std::size_t length = 0;
        switch (length_field) {
        case LengthField::u8:
            length = d.reader().u8().value_or(0);
            break;
        case LengthField::u16le:
            length = d.reader().u16le().value_or(0);
            break;
        case LengthField::u16be:
            length = d.reader().u16be().value_or(0);
            break;
        }
        const auto body = d.reader().bytes(length);
        if (!body) {
            d.reader().rest();
            d.malformed();
            return;
        }
        auto node = Decoder::node(label(id), std::uint64_t{id},
                                  ByteRange{.offset = start, .length = header + length});
        if (!value(node, id, *body, start + header) && !body->empty()) {
            node.children.push_back(
                Decoder::node(msg::data, std::vector<std::uint8_t>(body->begin(), body->end()),
                              ByteRange{.offset = start + header, .length = length}));
        }
        d.add(std::move(node));
    }
    if (!d.reader().empty()) {
        d.malformed();
    }
}

constexpr auto no_value = [](TreeNode&, std::uint8_t, std::span<const std::uint8_t>, std::size_t) {
    return false;
};

MessageId wfd_subelement_label(std::uint8_t id) {
    switch (id) {
    case 0:
        return WA_TR(wfd_device_information, "WFD Device Information");
    case 1:
        return WA_TR(wfd_associated_bssid, "Associated BSSID");
    case 2:
        return WA_TR(wfd_audio_formats, "WFD Audio Formats");
    case 3:
        return WA_TR(wfd_video_formats, "WFD Video Formats");
    case 4:
        return WA_TR(wfd_3d_video_formats, "WFD 3D Video Formats");
    case 5:
        return WA_TR(wfd_content_protection, "WFD Content Protection");
    case 6:
        return WA_TR(wfd_coupled_sink, "Coupled Sink Information");
    case 7:
        return WA_TR(wfd_extended_capability, "WFD Extended Capability");
    case 8:
        return WA_TR(wfd_local_ip, "Local IP Address");
    case 9:
        return WA_TR(wfd_session_information, "WFD Session Information");
    case 10:
        return WA_TR(wfd_alternative_mac, "Alternative MAC Address");
    default:
        return WA_TR(common_subelement, "Subelement");
    }
}

bool wfd_value(TreeNode& node, std::uint8_t id, std::span<const std::uint8_t> v,
               std::size_t start) {
    if (id == 0 && v.size() >= 6) {
        // Device Information: 16-bit big-endian bitmap, control port, max throughput.
        const auto info = static_cast<unsigned>((v[0] << 8U) | v[1]);
        const auto info_range = ByteRange{.offset = start, .length = 2};
        auto bits = Decoder::node(WA_TR(wfd_device_info_bitmap, "Device Information Bitmap"),
                                  std::uint64_t{info}, info_range);
        bits.display = Display::hex;
        bits.children.push_back(Decoder::node(
            WA_TR(wfd_device_type, "Device Type"),
            EnumValue{.raw = info & 3U,
                      .name = [&] -> Text {
                          constexpr std::array<Text, 4> names{
                              WA_TR(wfd_source, "Source"), WA_TR(wfd_primary_sink, "Primary Sink"),
                              WA_TR(wfd_secondary_sink, "Secondary Sink"),
                              WA_TR(wfd_source_primary_sink, "Source / Primary Sink")};
                          return names[info & 3U];
                      }()},
            info_range));
        bits.children.push_back(
            Decoder::node(WA_TR(wfd_session_available, "Available for WFD Session"),
                          ((info >> 4U) & 3U) == 1, info_range));
        bits.children.push_back(Decoder::node(WA_TR(wfd_service_discovery, "WFD Service Discovery"),
                                              ((info >> 6U) & 1U) != 0, info_range));
        bits.children.push_back(
            Decoder::node(WA_TR(wfd_content_protection_support, "Content Protection Support"),
                          ((info >> 8U) & 1U) != 0, info_range));
        node.children.push_back(std::move(bits));
        node.children.push_back(
            Decoder::node(WA_TR(wfd_control_port, "Session Management Control Port"),
                          std::uint64_t{static_cast<unsigned>((v[2] << 8U) | v[3])},
                          ByteRange{.offset = start + 2, .length = 2}));
        node.children.push_back(Decoder::node(WA_TR(wfd_max_throughput, "Maximum Throughput"),
                                              static_cast<double>((v[4] << 8U) | v[5]),
                                              ByteRange{.offset = start + 4, .length = 2},
                                              Unit::mbps));
        return v.size() == 6;
    }
    if ((id == 1 || id == 10) && v.size() == 6) {
        node.children.push_back(Decoder::node(WA_TR(common_mac, "MAC Address"), core::format_mac(v),
                                              ByteRange{.offset = start, .length = 6}));
        return true;
    }
    return false;
}

MessageId nan_attribute_label(std::uint8_t id) {
    switch (id) {
    case 0x00:
        return WA_TR(nan_master_indication, "Master Indication");
    case 0x01:
        return WA_TR(nan_cluster, "Cluster");
    case 0x02:
        return WA_TR(nan_service_id_list, "Service ID List");
    case 0x03:
        return WA_TR(nan_service_descriptor, "Service Descriptor");
    case 0x05:
        return WA_TR(nan_wlan_infrastructure, "WLAN Infrastructure");
    case 0x0b:
        return WA_TR(nan_country_code, "Country Code");
    case 0x0c:
        return WA_TR(nan_ranging, "Ranging");
    case 0x0f:
        return WA_TR(nan_device_capability, "Device Capability");
    case 0x12:
        return WA_TR(nan_availability, "NAN Availability");
    case 0x1d:
        return WA_TR(nan_element_container, "Element Container");
    case 0x22:
        return WA_TR(nan_cipher_suite_info, "Cipher Suite Info");
    case 0xdd:
        return WA_TR(element_vendor_specific, "Vendor Specific");
    default:
        return WA_TR(nan_attribute, "NAN Attribute");
    }
}

MessageId qos_mgmt_attribute_label(std::uint8_t id) {
    switch (id) {
    case 1:
        return WA_TR(qos_mgmt_port_range, "Port Range");
    case 2:
        return WA_TR(qos_mgmt_dscp_policy, "DSCP Policy");
    case 3:
        return WA_TR(qos_mgmt_tclas, "TCLAS");
    case 4:
        return WA_TR(qos_mgmt_domain_name, "Domain Name");
    default:
        return WA_TR(qos_mgmt_attribute, "QoS Management Attribute");
    }
}

} // namespace

// OSEN (Hotspot 2.0 Release 2): RSN element body without the version field.
// Wireshark: dissect_hs20_osen.
ElementValue decode_vendor_osen(Decoder& d) {
    read_vendor_type(d);
    read_suite(d, d.root(), WA_TR(rsn_group_cipher, "Group Data Cipher Suite"), false);
    if (d.reader().empty() || d.is_malformed()) {
        return {};
    }
    read_suite_list(d, WA_TR(rsn_pairwise_list, "Pairwise Cipher Suites"), false);
    if (d.reader().empty() || d.is_malformed()) {
        return {};
    }
    read_suite_list(d, WA_TR(rsn_akm_list, "AKM Suites"), true);
    if (d.remaining() >= 2) {
        d.u16(d.root(), WA_TR(rsn_capabilities, "RSN Capabilities"), Unit::none, Display::hex);
    }
    d.rest(d.root(), msg::data);
    return {};
}

// Wi-Fi Display subelements (id u8, length u16 big-endian). Wireshark: dissect_wifi_display_ie.
ElementValue decode_vendor_wfd(Decoder& d) {
    read_vendor_type(d);
    attribute_list(d, LengthField::u16be, wfd_subelement_label, wfd_value);
    return {};
}

// NAN attributes (id u8, length u16 little-endian). Wireshark: dissect_nan_beacon.
ElementValue decode_vendor_nan(Decoder& d) {
    read_vendor_type(d);
    attribute_list(d, LengthField::u16le, nan_attribute_label, no_value);
    return {};
}

// DPP: no public layout of the vendor element body in beacons; Wireshark shows it raw
// (dissect_wifi_dpp_ie).
ElementValue decode_vendor_dpp(Decoder& d) {
    read_vendor_type(d);
    d.rest(d.root(), msg::data);
    return {};
}

// Multi-AP (EasyMesh) element: subelements (id u8, length u8).
// Wireshark: dissect_wps_wfa_ext_via_dt (packet-wps.c).
ElementValue decode_vendor_multi_ap(Decoder& d) {
    read_vendor_type(d);
    attribute_list(
        d, LengthField::u8, [](std::uint8_t) { return WA_TR(common_subelement, "Subelement"); },
        [](TreeNode& node, std::uint8_t id, std::span<const std::uint8_t> v, std::size_t start) {
            return multi_ap_subelement(node, id, v, start - 2);
        });
    return {};
}

// QoS Management element: attributes (id u8, length u8). Wireshark: dissect_qos_mgmt.
ElementValue decode_vendor_qos_mgmt(Decoder& d) {
    read_vendor_type(d);
    attribute_list(d, LengthField::u8, qos_mgmt_attribute_label, no_value);
    return {};
}

// RSN Element Override (and Override 2): RSN element body. Wireshark: dissect_wfa_rsn_override.
// The typed value is not returned, so the BSS summary keeps using the RSN element.
ElementValue decode_vendor_rsn_override(Decoder& d) {
    read_vendor_type(d);
    const auto start = d.offset();
    const auto body = d.reader().rest();
    d.sub_decode(d.root(), decode_rsn, body, start);
    return {};
}

// RSNX Override: RSN Extension element body. Wireshark: dissect_wfa_rsnx_override.
ElementValue decode_vendor_rsnx_override(Decoder& d) {
    read_vendor_type(d);
    const auto start = d.offset();
    const auto body = d.reader().rest();
    d.sub_decode(d.root(), decode_rsn_extension, body, start);
    return {};
}

} // namespace wifi_analyze::ie
