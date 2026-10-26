// SPDX-License-Identifier: MIT
// Proprietary vendor elements without a public specification. The only reference for these
// layouts is the Wireshark 4.6.9 dissector named at each decoder (epan/dissectors/
// packet-ieee80211.c); fields Wireshark does not interpret are kept as raw data here as well.
// See docs/decoder-sources.md. Decoders are called with the reader positioned after the OUI.

#include <algorithm>
#include <array>
#include <bit>
#include <optional>
#include <string>

#include "ie/decoders.hpp"

namespace wifi_analyze::ie {
namespace {

using core::table_name;

/// Text field of `size` octets; trailing NUL padding is not shown but stays in the byte range.
void padded_text(Decoder& d, TreeNode& parent, MessageId label, std::size_t size) {
    const auto start = d.offset();
    const auto raw = d.reader().bytes(size);
    if (!raw) {
        d.malformed();
        return;
    }
    auto text = *raw;
    while (!text.empty() && text.back() == 0) {
        text = text.first(text.size() - 1);
    }
    parent.children.push_back(Decoder::node(label, core::display_text(text), d.range_from(start)));
}

void ap_name_rest(Decoder& d) {
    padded_text(d, d.root(), WA_TR(vendor_ap_name, "AP Name"), d.remaining());
}

std::uint8_t vendor_type(Decoder& d) {
    return d.u8(d.root(), WA_TR(vendor_type, "Vendor Type")).value_or(0);
}

/// Sub-TLVs (type u8, length u8) shown raw.
void raw_tlvs(Decoder& d) {
    while (d.remaining() >= 2) {
        const auto start = d.offset();
        auto tlv = d.group(WA_TR(vendor_tlv, "TLV"));
        d.u8(tlv, WA_TR(vendor_tlv_type, "Type"));
        const auto len = d.u8(tlv, msg::length);
        if (len && *len > 0) {
            d.bytes(tlv, msg::data, *len);
        }
        d.close(tlv, start);
        d.add(std::move(tlv));
        if (d.is_malformed()) {
            return;
        }
    }
    if (!d.reader().empty()) {
        d.malformed();
    }
}

std::optional<double> be_double(Decoder& d, TreeNode& parent, MessageId label) {
    const auto start = d.offset();
    const auto hi = d.reader().u32be();
    const auto lo = d.reader().u32be();
    if (!hi || !lo) {
        d.malformed();
        return std::nullopt;
    }
    const auto value = std::bit_cast<double>((static_cast<std::uint64_t>(*hi) << 32U) | *lo);
    parent.children.push_back(Decoder::node(label, value, d.range_from(start)));
    return value;
}

void atheros_capabilities(Decoder& d, MessageId label) {
    if (auto c = d.bits(label, 1)) {
        c->flag(0, WA_TR(atheros_turbo_prime, "Turbo Prime"));
        c->flag(1, WA_TR(atheros_compression, "Compression"));
        c->flag(2, WA_TR(atheros_fast_frames, "Fast Frames"));
        c->flag(3, WA_TR(atheros_xr, "eXtended Range"));
        c->flag(4, WA_TR(atheros_advanced_radar, "Advanced Radar"));
        c->flag(5, WA_TR(atheros_burst, "Burst"));
        c->flag(6, WA_TR(atheros_cwmin_tuning, "CWMin Tuning"));
        c->flag(7, WA_TR(atheros_boost, "Boost"));
        d.add(c->take());
    }
}

/// Aruba AP Health bitmap (32 bit, big-endian). Wireshark master: dissect_vendor_ie_aruba.
void aruba_ap_health(Decoder& d) {
    const auto start = d.offset();
    const auto raw = d.reader().u32be();
    if (!raw) {
        d.malformed();
        return;
    }
    const auto range = d.range_from(start);
    auto n = Decoder::node(WA_TR(aruba_ap_health, "AP Health"), std::uint64_t{*raw}, range);
    n.display = Display::hex;
    const auto field = [&](MessageId label, unsigned shift, unsigned bits, Text name) {
        const auto v = (*raw >> shift) & ((1U << bits) - 1U);
        n.children.push_back(Decoder::node(label, EnumValue{.raw = v, .name = name}, range));
    };
    const auto v = [&](unsigned shift, unsigned bits) {
        return (*raw >> shift) & ((1U << bits) - 1U);
    };
    const auto status = [](std::uint32_t x, std::uint32_t failure_previous) -> Text {
        if (x == 0) {
            return WA_TR(aruba_health_success, "Success");
        }
        return x == failure_previous
                   ? Text{WA_TR(aruba_health_previous_layer, "Failure at previous layer")}
                   : Text{WA_TR(aruba_health_failure, "Failure")};
    };
    field(msg::version, 0, 3, v(0, 3) == 0 ? Text{"1"} : Text{msg::reserved});
    field(WA_TR(aruba_health_ip, "IP Protocol"), 3, 1, v(3, 1) == 0 ? "IPv4" : "IPv6");
    field(WA_TR(aruba_health_uplink, "Uplink"), 4, 1,
          v(4, 1) == 0 ? Text{WA_TR(aruba_health_uplink_ok, "Uplink existed")}
                       : Text{WA_TR(aruba_health_no_uplink, "No uplink")});
    {
        constexpr std::array<Text, 4> types{"Ethernet", WA_TR(aruba_health_modem, "Modem"),
                                            WA_TR(aruba_mesh, "Mesh"),
                                            WA_TR(aruba_health_wifi_uplink, "Wi-Fi uplink")};
        field(WA_TR(aruba_health_uplink_type, "Uplink Type"), 5, 3, table_name(types, v(5, 3)));
    }
    field(WA_TR(aruba_health_network, "Network Layer"), 8, 4, status(v(8, 4), 15));
    field(WA_TR(aruba_health_proxy, "Proxy Server"), 12, 2, status(v(12, 2), 3));
    field(WA_TR(aruba_health_activate, "Activate"), 14, 4, status(v(14, 4), 15));
    field(WA_TR(aruba_health_central, "Central"), 18, 3, status(v(18, 3), 7));
    d.add(std::move(n));
}

} // namespace

// --- Cisco ------------------------------------------------------------------------------

// Cisco Aironet / CCX, OUI 00:40:96. Wireshark: dissect_vendor_ie_aironet.
ElementValue decode_vendor_cisco(Decoder& d) {
    const auto type =
        d.enumeration(d.root(), WA_TR(vendor_type, "Vendor Type"), 1, [](std::uint64_t v) -> Text {
            switch (v) {
            case 0:
                return WA_TR(cisco_dtpc, "DTPC (Dynamic Transmit Power Control)");
            case 3:
                return WA_TR(cisco_ccx_version, "CCX Version");
            case 4:
                return WA_TR(cisco_qos, "QoS Parameters");
            case 14:
                return WA_TR(cisco_qbss_v2, "QBSS Load v2");
            case 20:
                return WA_TR(cisco_client_mfp, "Client MFP");
            case 47:
                return WA_TR(cisco_ap_name_v2, "AP Name v2");
            default:
                return msg::unknown;
            }
        });
    switch (type.value_or(255)) {
    case 0:
        d.s8(d.root(), WA_TR(cisco_dtpc_power, "Transmit Power"), Unit::dbm);
        break;
    case 3:
        d.u8(d.root(), msg::version);
        break;
    case 4:
        d.u8(d.root(), msg::reserved);
        d.u8(d.root(), WA_TR(cisco_qos_parameter_set, "Parameter Set Count"));
        decode_edca_records(d, d.root());
        break;
    case 14:
        d.u16(d.root(), WA_TR(bss_load_stations, "Station Count"));
        d.u8(d.root(), WA_TR(cisco_channel_utilization, "Channel Utilization (x/255)"));
        d.u8(d.root(), WA_TR(cisco_call_admission_limit, "Call Admission Limit"));
        d.u8(d.root(), WA_TR(cisco_g711_quantum, "G.711 CU Quantum"));
        break;
    case 20:
        if (auto f = d.bits(WA_TR(cisco_client_mfp, "Client MFP"), 1)) {
            f->flag(0, WA_TR(cisco_mfp_enabled, "Enabled"));
            d.add(f->take());
        }
        break;
    case 47:
        ap_name_rest(d);
        return {};
    default:
        break;
    }
    d.rest(d.root(), msg::data);
    return {};
}

// Cisco CCX1 CKIP + Device Name, element 133. Wireshark: ieee80211_tag_cisco_ccx1_ckip.
ElementValue decode_cisco_ccx1(Decoder& d) {
    d.bytes(d.root(), msg::unknown, 10);
    padded_text(d, d.root(), WA_TR(vendor_ap_name, "AP Name"), 16);
    d.u8(d.root(), WA_TR(cisco_ccx1_clients, "Associated Clients"));
    d.rest(d.root(), msg::unknown);
    return {};
}

// --- Aruba ------------------------------------------------------------------------------

// Aruba Networks, OUI 00:0B:86. Wireshark: dissect_vendor_ie_aruba.
ElementValue decode_vendor_aruba(Decoder& d) {
    vendor_type(d);
    const auto subtype =
        d.enumeration(d.root(), WA_TR(vendor_subtype, "Subtype"), 1, [](std::uint64_t v) -> Text {
            constexpr std::array<Text, 11> names{Text{},
                                                 "CAC",
                                                 WA_TR(aruba_mesh, "Mesh"),
                                                 WA_TR(vendor_ap_name, "AP Name"),
                                                 "ARM",
                                                 "SLB",
                                                 WA_TR(aruba_sj_loop_protect, "SJ Loop Protect"),
                                                 WA_TR(aruba_auto_mesh, "Auto Mesh"),
                                                 "LCI",
                                                 WA_TR(aruba_gps, "GPS Ellipse"),
                                                 WA_TR(aruba_ap_health, "AP Health")};
            return table_name(names, v);
        });
    if (subtype == 3) {
        d.u8(d.root(), msg::unknown);
        ap_name_rest(d);
    } else if (subtype == 4) {
        // ARM (Wireshark master): one unknown octet, then the transmit power in 4 dB steps.
        d.u8(d.root(), msg::unknown);
        const auto start = d.offset();
        if (const auto arm = d.reader().u8()) {
            d.add(Decoder::node(WA_TR(aruba_arm_power, "ARM Transmit Power"),
                                std::int64_t{4} * *arm, d.range_from(start), Unit::dbm));
        }
    } else if (subtype == 10 && d.remaining() >= 5) {
        // AP Health (Wireshark master): one unknown octet, then a 32-bit big-endian bitmap.
        d.u8(d.root(), msg::unknown);
        aruba_ap_health(d);
    } else if (subtype == 9) {
        d.u8(d.root(), msg::unknown);
        d.u8(d.root(), msg::length);
        d.u8(d.root(), WA_TR(aruba_gps_subversion, "Subversion"));
        d.u8(d.root(), WA_TR(aruba_gps_hop, "Hop"));
        be_double(d, d.root(), WA_TR(aruba_gps_latitude, "Latitude (°)"));
        be_double(d, d.root(), WA_TR(aruba_gps_longitude, "Longitude (°)"));
        be_double(d, d.root(), WA_TR(aruba_gps_major_axis, "Major Axis (m)"));
        be_double(d, d.root(), WA_TR(aruba_gps_minor_axis, "Minor Axis (m)"));
        be_double(d, d.root(), WA_TR(aruba_gps_orientation, "Orientation (°)"));
        be_double(d, d.root(), WA_TR(aruba_gps_distance, "Distance (m)"));
    }
    d.rest(d.root(), msg::data);
    return {};
}

// --- vendors whose only known content is the AP name -----------------------------------

// Ruckus Networks 00:13:92 (type 3), Mist Systems 5C:5B:35 (type 1), Alcatel-Lucent
// DC:08:56 (type 1); Wireshark master also: Ubiquiti 00:15:6D (type 1), Meter 84:80:94 (type 0),
// Telecom Infra Project 48:D0:17 (type 2), Belden 3C:B9:A6 (type 1).
// Wireshark: dissect_vendor_ie_ruckus / _mist / _alcatel / _ubiquiti / _meter / _telecom /
// _belden.
ElementValue decode_vendor_ap_name_type(Decoder& d) {
    vendor_type(d);
    ap_name_rest(d);
    return {};
}

// Aerohive 00:19:77, type 33: version, subtype, host name length, host name.
// Wireshark: dissect_vendor_ie_aerohive.
ElementValue decode_vendor_aerohive(Decoder& d) {
    const auto type = vendor_type(d);
    d.u8(d.root(), msg::version);
    if (type == 33) {
        d.u8(d.root(), WA_TR(vendor_subtype, "Subtype"));
        const auto len = d.u8(d.root(), msg::length);
        if (len) {
            padded_text(d, d.root(), WA_TR(aerohive_host_name, "Host Name"),
                        std::min<std::size_t>(*len, d.remaining()));
        }
    }
    d.rest(d.root(), msg::data);
    return {};
}

// Arista (Mojo) 00:11:74: vendor type, subtype (6 = AP name: one unknown octet + name).
// Wireshark: dissect_vendor_ie_arista.
ElementValue decode_vendor_arista(Decoder& d) {
    vendor_type(d);
    const auto subtype = d.u8(d.root(), WA_TR(vendor_subtype, "Subtype"));
    if (subtype == 6) {
        d.u8(d.root(), msg::unknown);
        ap_name_rest(d);
    }
    d.rest(d.root(), msg::data);
    return {};
}

// Huawei 00:E0:FC (Wireshark master): vendor type, subtype (1 = AP name: one unknown octet +
// name). Wireshark: dissect_vendor_ie_huawei.
ElementValue decode_vendor_huawei(Decoder& d) {
    vendor_type(d);
    const auto subtype = d.u8(d.root(), WA_TR(vendor_subtype, "Subtype"));
    if (subtype == 1) {
        d.u8(d.root(), msg::unknown);
        ap_name_rest(d);
    }
    d.rest(d.root(), msg::data);
    return {};
}

// Fortinet 00:09:0F: subtype u16 (10 = system: TLVs AP name / model / serial).
// Wireshark: dissect_vendor_ie_fortinet.
ElementValue decode_vendor_fortinet(Decoder& d) {
    const auto subtype = d.u16(d.root(), WA_TR(vendor_subtype, "Subtype"));
    if (subtype == 10) {
        while (d.remaining() > 2) {
            const auto type = d.reader().u8().value_or(0);
            const auto len = d.reader().u8().value_or(0);
            switch (type) {
            case 1:
                padded_text(d, d.root(), WA_TR(vendor_ap_name, "AP Name"), len);
                break;
            case 2:
                padded_text(d, d.root(), WA_TR(vendor_ap_model, "AP Model"), len);
                break;
            case 3:
                padded_text(d, d.root(), WA_TR(vendor_ap_serial, "AP Serial Number"), len);
                break;
            default:
                d.bytes(d.root(), WA_TR(vendor_tlv, "TLV"), len);
                break;
            }
            if (d.is_malformed()) {
                return {};
            }
        }
    }
    d.rest(d.root(), msg::data);
    return {};
}

// Meru 00:0C:E6: TLVs (type u8, length u8) directly after the OUI.
// Wireshark: dissect_vendor_ie_meru.
ElementValue decode_vendor_meru(Decoder& d) {
    raw_tlvs(d);
    return {};
}

// Extreme / Zebra (WiNG) 00:A0:F8: subtype 1 = 7 unknown octets, AP name length, AP name.
// Wireshark: dissect_vendor_ie_extreme.
ElementValue decode_vendor_extreme(Decoder& d) {
    const auto subtype = d.u8(d.root(), WA_TR(vendor_subtype, "Subtype"));
    if (subtype == 1) {
        d.bytes(d.root(), msg::unknown, 7);
        const auto len = d.u8(d.root(), msg::length);
        if (len) {
            padded_text(d, d.root(), WA_TR(vendor_ap_name, "AP Name"),
                        std::min<std::size_t>(*len, d.remaining()));
        }
    }
    d.rest(d.root(), msg::data);
    return {};
}

// Symbol Proprietary, element 173 with OUI 00:A0:F8 (Extreme/Zebra): load information.
// Wireshark: ieee80211_tag_symbol_proprietary_ie / dissect_symbol_proprietary_ie_extreme.
ElementValue decode_symbol_proprietary(Decoder& d) {
    const auto oui = d.oui(d.root(), WA_TR(vendor_oui, "OUI"));
    if (oui && *oui == Oui{0x00, 0xa0, 0xf8}) {
        d.u16(d.root(), WA_TR(symbol_assoc_clients, "Associated Clients"));
        d.u16(d.root(), WA_TR(symbol_load_kbps, "Load"), Unit::kbps);
        d.u16(d.root(), WA_TR(symbol_load_pps, "Load (packets/s)"));
        d.u16(d.root(), WA_TR(symbol_client_tx_power, "Client Transmit Power"));
        d.u32(d.root(), WA_TR(symbol_timestamp, "Timestamp (Unix time)"));
    }
    d.rest(d.root(), msg::data);
    return {};
}

// Extreme Networks mesh 00:05:12. Wireshark: dissect_vendor_ie_extreme_mesh.
ElementValue decode_vendor_extreme_mesh(Decoder& d) {
    const auto type =
        d.enumeration(d.root(), WA_TR(vendor_type, "Vendor Type"), 1, [](std::uint64_t v) -> Text {
            constexpr std::array<Text, 4> names{Text{}, WA_TR(extreme_mesh_hello, "Hello"),
                                                WA_TR(mesh_id, "Mesh ID"), "MPID"};
            return table_name(names, v);
        });
    if (type == 1) {
        if (auto s = d.bits(WA_TR(extreme_mesh_services, "Services"), 1)) {
            s->flag(0, WA_TR(extreme_mesh_root, "Root"));
            s->flag(1, WA_TR(extreme_mesh_proxy, "Proxy"));
            s->flag(2, WA_TR(extreme_mesh_geo, "Geo"));
            s->flag(3, WA_TR(extreme_mesh_path_preference, "Path Preference"));
            s->flag(4, WA_TR(extreme_mesh_mobile, "Mobile"));
            d.add(s->take());
        }
        d.u8(d.root(), WA_TR(extreme_mesh_hops, "Hops to Root"));
        d.u16(d.root(), WA_TR(extreme_mesh_metric, "Metric to Root"));
        d.mac(d.root(), WA_TR(extreme_mesh_root_id, "Root ID"));
        d.mac(d.root(), WA_TR(extreme_mesh_next_hop, "Next Hop"));
    } else if (type == 2) {
        d.text(d.root(), WA_TR(mesh_id, "Mesh ID"), d.remaining());
    } else if (type == 3) {
        d.mac(d.root(), WA_TR(extreme_mesh_mpid, "Mesh Point ID"));
    }
    d.rest(d.root(), msg::data);
    return {};
}

// MikroTik / RouterBOARD 00:0C:42: vendor type, 2 unknown octets, sub-elements; sub-element
// 1 of length 30 = 10-octet prefix + identity (router name). Wireshark:
// dissect_vendor_ie_routerboard.
ElementValue decode_vendor_mikrotik(Decoder& d) {
    vendor_type(d);
    d.bytes(d.root(), msg::unknown, 2);
    while (d.remaining() >= 2) {
        const auto start = d.offset();
        const auto type = d.reader().u8().value_or(0);
        const auto len = d.reader().u8().value_or(0);
        auto sub = Decoder::node(WA_TR(vendor_tlv, "TLV"), std::uint64_t{type}, std::nullopt);
        if (type == 1 && len == 30 && d.remaining() >= 30) {
            d.bytes(sub, msg::unknown, 10);
            padded_text(d, sub, WA_TR(mikrotik_identity, "Identity"), 20);
        } else if (!d.bytes(sub, msg::data, len)) {
            d.add(std::move(sub));
            break;
        }
        sub.bytes = d.range_from(start);
        d.add(std::move(sub));
    }
    if (!d.reader().empty() && !d.is_malformed()) {
        d.malformed();
    }
    return {};
}

// --- chipset / device vendors ------------------------------------------------------------

// Atheros 00:03:7F: type, subtype, version; v0 Advanced Capability / eXtended Range.
// Wireshark: dissect_vendor_ie_atheros.
ElementValue decode_vendor_atheros(Decoder& d) {
    const auto type =
        d.enumeration(d.root(), WA_TR(vendor_type, "Vendor Type"), 1, [](std::uint64_t v) -> Text {
            if (v == 1) {
                return WA_TR(atheros_advanced_capability, "Advanced Capability");
            }
            return v == 3 ? Text{WA_TR(atheros_xr, "eXtended Range")} : Text{msg::unknown};
        });
    const auto subtype = d.u8(d.root(), WA_TR(vendor_subtype, "Subtype"));
    const auto version = d.u8(d.root(), msg::version);
    if (version == 0 && subtype == 1) {
        if (type == 1) {
            atheros_capabilities(d, WA_TR(atheros_capabilities, "Capabilities"));
            d.u16(d.root(), WA_TR(atheros_default_key, "Default Key Index"), Unit::none,
                  Display::hex);
        } else if (type == 3) {
            d.u8(d.root(), WA_TR(atheros_xr_info, "Info"), Unit::none, Display::hex);
            d.mac(d.root(), WA_TR(atheros_base_bssid, "Base BSSID"));
            d.mac(d.root(), WA_TR(atheros_xr_bssid, "XR BSSID"));
            d.u16(d.root(), WA_TR(atheros_xr_beacon_interval, "XR Beacon Interval"), Unit::tu);
            atheros_capabilities(d, WA_TR(atheros_base_capabilities, "Base Capabilities"));
            atheros_capabilities(d, WA_TR(atheros_xr_capabilities, "XR Capabilities"));
        }
    }
    d.rest(d.root(), msg::data);
    return {};
}

// Marvell 00:50:43: type 4 = mesh. Wireshark: dissect_vendor_ie_marvell.
ElementValue decode_vendor_marvell(Decoder& d) {
    const auto type = d.u8(d.root(), WA_TR(vendor_type, "Vendor Type"));
    if (type == 4) {
        d.u8(d.root(), WA_TR(vendor_subtype, "Subtype"));
        d.u8(d.root(), msg::version);
        d.u8(d.root(), WA_TR(mesh_path_selection_protocol, "Active Path Selection Protocol"));
        d.u8(d.root(), WA_TR(mesh_path_selection_metric, "Active Path Selection Metric"));
        d.u8(d.root(), WA_TR(mesh_capability, "Mesh Capability"), Unit::none, Display::hex);
    }
    d.rest(d.root(), msg::data);
    return {};
}

// Nintendo 00:1F:32 (StreetPass): vendor type, TLVs 0x11 services (5-octet entries) and 0xF0
// console ID. Wireshark: dissect_vendor_ie_nintendo.
ElementValue decode_vendor_nintendo(Decoder& d) {
    vendor_type(d);
    while (d.remaining() >= 2) {
        const auto start = d.offset();
        const auto type = d.reader().u8().value_or(0);
        const auto len = d.reader().u8().value_or(0);
        const auto label = type == 0x11   ? WA_TR(nintendo_services, "Services")
                           : type == 0xf0 ? WA_TR(nintendo_console_id, "Console ID")
                                          : WA_TR(vendor_tlv, "TLV");
        auto sub = Decoder::node(label, std::uint64_t{type}, std::nullopt);
        if (type == 0x11) {
            for (std::size_t i = 0; i + 5 <= len && d.remaining() >= 5; i += 5) {
                d.bytes(sub, WA_TR(nintendo_service, "Service"), 5);
            }
            if (len % 5 != 0) {
                d.bytes(sub, msg::data, len % 5);
            }
        } else {
            d.bytes(sub, msg::data, len);
        }
        sub.bytes = d.range_from(start);
        d.add(std::move(sub));
        if (d.is_malformed()) {
            break;
        }
    }
    if (!d.reader().empty() && !d.is_malformed()) {
        d.malformed();
    }
    return {};
}

// Apple 00:17:F2: vendor type; type 6 carries subtype u16 and length. Content not
// interpreted (as in Wireshark: dissect_vendor_ie_apple).
ElementValue decode_vendor_apple(Decoder& d) {
    const auto type = vendor_type(d);
    if (type == 6) {
        d.u16(d.root(), WA_TR(vendor_subtype, "Subtype"));
        d.u8(d.root(), msg::length);
    }
    d.rest(d.root(), msg::data);
    return {};
}

// Broadcom / Epigram 00:90:4C pre-802.11n HT: type 51 = HT Capabilities, 52 = HT Information
// (802.11n draft 1.0; same layouts as the HT Capabilities / HT Operation elements).
// Wireshark: dissect_vendor_ie_ht. The typed values are not returned, so the summary keeps
// using the standard elements.
ElementValue decode_vendor_broadcom_ht(Decoder& d) {
    const auto type =
        d.enumeration(d.root(), WA_TR(vendor_type, "Vendor Type"), 1, [](std::uint64_t v) -> Text {
            if (v == 51) {
                return WA_TR(element_ht_capabilities, "HT Capabilities");
            }
            return v == 52 ? Text{WA_TR(broadcom_ht_information, "HT Information")}
                           : Text{msg::unknown};
        });
    const auto start = d.offset();
    const auto body = d.reader().rest();
    if (type == 51) {
        d.sub_decode(d.root(), decode_ht_capabilities, body, start);
    } else if (type == 52) {
        d.sub_decode(d.root(), decode_ht_operation, body, start);
    } else if (!body.empty()) {
        d.add(Decoder::node(msg::data, std::vector<std::uint8_t>(body.begin(), body.end()),
                            ByteRange{.offset = start, .length = body.size()}));
    }
    return {};
}

// French drone remote identification (SGDSN, OUI 6A:5C:35), defined by the arrêté
// NOR ECOI1934044A of 27 Dec 2019. Wireshark: dissect_vendor_ie_sgdsn.
ElementValue decode_vendor_drone_id_fr(Decoder& d) {
    if (vendor_type(d) != 1) {
        d.rest(d.root(), msg::data);
        return {};
    }
    while (d.remaining() >= 2) {
        const auto start = d.offset();
        const auto type = d.reader().u8().value_or(0);
        const auto len = d.reader().u8().value_or(0);
        const auto value_start = d.offset();
        const auto body = d.reader().bytes(len);
        if (!body) {
            d.reader().rest();
            d.malformed();
            break;
        }
        const auto& v = *body;
        const auto range = ByteRange{.offset = start, .length = 2U + len};
        const auto value_range = ByteRange{.offset = value_start, .length = len};
        const auto le = [&v] {
            std::uint32_t x = 0;
            for (std::size_t i = v.size(); i > 0; --i) {
                x = (x << 8U) | v[i - 1];
            }
            return x;
        };
        TreeNode n;
        switch (type) {
        case 1:
            n = Decoder::node(msg::version, std::uint64_t{len == 1 ? v[0] : 0U}, range);
            break;
        case 2:
            n = Decoder::node(WA_TR(drone_id_fr, "ID (French format)"), core::display_text(v),
                              range);
            break;
        case 3:
            n = Decoder::node(WA_TR(drone_id_ansi, "ID (ANSI/CTA-2063 serial number)"),
                              core::display_text(v), range);
            break;
        case 4:
        case 5:
        case 8:
        case 9: {
            static constexpr std::array<MessageId, 4> labels{
                WA_TR(drone_latitude, "Latitude (°)"), WA_TR(drone_longitude, "Longitude (°)"),
                WA_TR(drone_takeoff_latitude, "Takeoff Latitude (°)"),
                WA_TR(drone_takeoff_longitude, "Takeoff Longitude (°)")};
            const auto index = type <= 5 ? type - 4U : type - 6U;
            n = Decoder::node(labels[index],
                              static_cast<double>(static_cast<std::int32_t>(le())) / 100000.0,
                              range);
            break;
        }
        case 6:
        case 7:
            n = Decoder::node(type == 6 ? WA_TR(drone_altitude_amsl, "Altitude AMSL (m)")
                                        : WA_TR(drone_altitude_agl, "Altitude AGL (m)"),
                              std::int64_t{static_cast<std::int16_t>(le())}, range);
            break;
        case 10:
            n = Decoder::node(WA_TR(drone_speed, "Horizontal Speed (m/s)"), std::uint64_t{le()},
                              range);
            break;
        case 11:
            n = Decoder::node(WA_TR(drone_heading, "Heading (°)"), std::uint64_t{le()}, range);
            break;
        default:
            n = Decoder::node(WA_TR(vendor_tlv, "TLV"), std::uint64_t{type}, range);
            break;
        }
        const bool fixed_ok = (type == 1 || type == 10)                            ? len == 1
                              : (type == 6 || type == 7 || type == 11)             ? len == 2
                              : (type == 4 || type == 5 || type == 8 || type == 9) ? len == 4
                                                                                   : true;
        if (!fixed_ok || type > 11 || type == 0) {
            n.value = std::vector<std::uint8_t>(v.begin(), v.end());
            n.bytes = value_range;
        }
        d.add(std::move(n));
    }
    if (!d.reader().empty() && !d.is_malformed()) {
        d.malformed();
    }
    return {};
}

} // namespace wifi_analyze::ie
