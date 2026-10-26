// SPDX-License-Identifier: MIT
// Vendor-specific elements with Microsoft OUI 00:50:F2. References: Wi-Fi Alliance WPA
// specification (type 1), WMM specification 1.2 (type 2), Wi-Fi Simple Configuration
// Technical Specification 2.0 (type 4, attributes big-endian TLV).

#include <array>
#include <string>

#include "ie/decoders.hpp"

namespace wifi_analyze::ie {
namespace {

using core::BitField;
using core::table_name;

std::uint8_t read_vendor_type(Decoder& d) {
    return d.u8(d.root(), WA_TR(vendor_type, "Vendor Type")).value_or(0);
}

void wmm_qos_info(Decoder& d, Wmm& wmm) {
    if (auto qos = d.bits(WA_TR(wmm_qos_info, "QoS Info"), 1)) {
        wmm.qos_info = static_cast<std::uint8_t>(qos->get(0, 8));
        qos->number(0, 4, WA_TR(wmm_parameter_set_count, "Parameter Set Count"));
        qos->flag(7, WA_TR(wmm_uapsd, "U-APSD"));
        d.add(qos->take());
    }
}

// --- WPS ---------------------------------------------------------------------------------

struct WpsAttribute {
    std::uint16_t type;
    MessageId label;
};

constexpr std::array wps_names{
    WpsAttribute{0x1008, WA_TR(wps_config_methods, "Config Methods")},
    WpsAttribute{0x1011, WA_TR(wps_device_name, "Device Name")},
    WpsAttribute{0x1012, WA_TR(wps_device_password_id, "Device Password ID")},
    WpsAttribute{0x1021, WA_TR(wps_manufacturer, "Manufacturer")},
    WpsAttribute{0x1023, WA_TR(wps_model_name, "Model Name")},
    WpsAttribute{0x1024, WA_TR(wps_model_number, "Model Number")},
    WpsAttribute{0x103b, WA_TR(wps_response_type, "Response Type")},
    WpsAttribute{0x103c, WA_TR(wps_rf_bands, "RF Bands")},
    WpsAttribute{0x1041, WA_TR(wps_selected_registrar, "Selected Registrar")},
    WpsAttribute{0x1042, WA_TR(wps_serial_number, "Serial Number")},
    WpsAttribute{0x1044, WA_TR(wps_state, "Wi-Fi Protected Setup State")},
    WpsAttribute{0x1047, WA_TR(wps_uuid_e, "UUID-E")},
    WpsAttribute{0x1049, WA_TR(wps_vendor_extension, "Vendor Extension")},
    WpsAttribute{0x104a, msg::version},
    WpsAttribute{0x1053,
                 WA_TR(wps_selected_registrar_config_methods, "Selected Registrar Config Methods")},
    WpsAttribute{0x1054, WA_TR(wps_primary_device_type, "Primary Device Type")},
    WpsAttribute{0x1057, WA_TR(wps_ap_setup_locked, "AP Setup Locked")},
};

MessageId wps_label(std::uint16_t type) {
    for (const auto& a : wps_names) {
        if (a.type == type) {
            return a.label;
        }
    }
    return WA_TR(wps_unknown_attribute, "Unknown Attribute");
}

std::string wps_version(std::uint8_t v) {
    return std::to_string(v >> 4U) + "." + std::to_string(v & 0x0fU);
}

void config_methods(BitField& b) {
    b.flag(0, WA_TR(wps_cm_usba, "USBA (Flash Drive)"));
    b.flag(1, WA_TR(wps_cm_ethernet, "Ethernet"));
    b.flag(2, WA_TR(wps_cm_label, "Label"));
    b.flag(3, WA_TR(wps_cm_display, "Display"));
    b.flag(4, WA_TR(wps_cm_ext_nfc, "External NFC Token"));
    b.flag(5, WA_TR(wps_cm_int_nfc, "Integrated NFC Token"));
    b.flag(6, WA_TR(wps_cm_nfc_interface, "NFC Interface"));
    b.flag(7, WA_TR(wps_cm_push_button, "Push Button"));
    b.flag(8, WA_TR(wps_cm_keypad, "Keypad"));
    b.flag(9, WA_TR(wps_cm_virtual_push_button, "Virtual Push Button"));
    b.flag(10, WA_TR(wps_cm_physical_push_button, "Physical Push Button"));
    b.flag(13, WA_TR(wps_cm_virtual_display, "Virtual Display PIN"));
    b.flag(14, WA_TR(wps_cm_physical_display, "Physical Display PIN"));
}

Text device_category_name(std::uint64_t v) {
    constexpr std::array<Text, 13> names{
        Text{},
        WA_TR(wps_cat_computer, "Computer"),
        WA_TR(wps_cat_input, "Input Device"),
        WA_TR(wps_cat_printer, "Printer, Scanner, Fax or Copier"),
        WA_TR(wps_cat_camera, "Camera"),
        WA_TR(wps_cat_storage, "Storage"),
        WA_TR(wps_cat_network_infrastructure, "Network Infrastructure"),
        WA_TR(wps_cat_display, "Display"),
        WA_TR(wps_cat_multimedia, "Multimedia Device"),
        WA_TR(wps_cat_gaming, "Gaming Device"),
        WA_TR(wps_cat_telephone, "Telephone"),
        WA_TR(wps_cat_audio, "Audio Device"),
        WA_TR(wps_cat_docking, "Docking Device"),
    };
    return table_name(names, v);
}

/// Big-endian integer node of `size` octets at content offset `start`.
TreeNode be_node(MessageId label, std::span<const std::uint8_t> v, std::size_t start,
                 Display display = Display::decimal) {
    std::uint64_t raw = 0;
    for (const auto b : v) {
        raw = (raw << 8U) | b;
    }
    auto n = Decoder::node(label, raw, ByteRange{.offset = start, .length = v.size()});
    n.display = display;
    return n;
}

void wps_vendor_extension(TreeNode& node, std::span<const std::uint8_t> v, std::size_t start,
                          Wps& wps) {
    if (v.size() < 3) {
        return;
    }
    const Oui oui{v[0], v[1], v[2]};
    node.children.push_back(Decoder::node(WA_TR(vendor_oui, "OUI"), core::format_oui(oui),
                                          ByteRange{.offset = start, .length = 3}));
    if (oui != Oui{0x00, 0x37, 0x2a}) { // WFA vendor extension
        return;
    }
    std::size_t pos = 3;
    while (pos + 2 <= v.size()) {
        const auto id = v[pos];
        const auto len = v[pos + 1];
        if (pos + 2 + len > v.size()) {
            break;
        }
        const auto data = v.subspan(pos + 2, len);
        const auto range = ByteRange{.offset = start + pos, .length = 2U + len};
        if (id == 0x00 && len == 1) {
            wps.version2 = data[0];
            node.children.push_back(
                Decoder::node(WA_TR(wps_version2, "Version2"), wps_version(data[0]), range));
        } else if (id == 0x01) {
            auto macs = Decoder::node(WA_TR(wps_authorized_macs, "Authorized MACs"), {}, range);
            for (std::size_t i = 0; i + 6 <= data.size(); i += 6) {
                macs.children.push_back(Decoder::node(WA_TR(common_mac, "MAC Address"),
                                                      core::format_mac(data.subspan(i, 6))));
            }
            node.children.push_back(std::move(macs));
        } else if (id == 0x02 && len == 1) {
            node.children.push_back(Decoder::node(
                WA_TR(wps_network_key_shareable, "Network Key Shareable"), data[0] != 0, range));
        } else if (id == 0x03 && len == 1) {
            node.children.push_back(Decoder::node(WA_TR(wps_request_to_enroll, "Request to Enroll"),
                                                  data[0] != 0, range));
        } else if (id == 0x04 && len == 1) {
            node.children.push_back(Decoder::node(WA_TR(wps_settings_delay, "Settings Delay Time"),
                                                  std::uint64_t{data[0]}, range));
        } else {
            node.children.push_back(
                Decoder::node(WA_TR(wps_unknown_attribute, "Unknown Attribute"),
                              std::vector<std::uint8_t>(data.begin(), data.end()), range));
        }
        pos += 2U + len;
    }
}

} // namespace

ElementValue decode_vendor_wpa(Decoder& d) {
    read_vendor_type(d);
    Wpa wpa;
    const auto version = d.u16(d.root(), msg::version);
    if (!version) {
        return {};
    }
    wpa.version = *version;
    if (d.reader().empty()) {
        return wpa;
    }
    wpa.group_cipher =
        read_suite(d, d.root(), WA_TR(wpa_multicast_cipher, "Multicast Cipher Suite"), false);
    if (!wpa.group_cipher || d.reader().empty()) {
        return wpa;
    }
    wpa.pairwise_ciphers =
        read_suite_list(d, WA_TR(wpa_unicast_ciphers, "Unicast Cipher Suites"), false);
    if (d.is_malformed() || d.reader().empty()) {
        return wpa;
    }
    wpa.akms = read_suite_list(d, WA_TR(rsn_akm_list, "AKM Suites"), true);
    if (!d.is_malformed() && d.remaining() >= 2) {
        d.u16(d.root(), WA_TR(wpa_capabilities, "WPA Capabilities"), Unit::none, Display::hex);
    }
    d.diagnostic(Severity::warning,
                 WA_TR(wpa_legacy, "Legacy WPA (WPA1) is deprecated and insecure"));
    return wpa;
}

ElementValue decode_vendor_wmm(Decoder& d) {
    read_vendor_type(d);
    Wmm wmm;
    const auto subtype =
        d.enumeration(d.root(), WA_TR(wmm_subtype, "Subtype"), 1, [](std::uint64_t v) -> Text {
            constexpr std::array<Text, 3> names{WA_TR(wmm_information, "WMM Information Element"),
                                                WA_TR(wmm_parameter, "WMM Parameter Element"),
                                                "TSPEC"};
            return table_name(names, v);
        });
    const auto version = d.u8(d.root(), msg::version);
    if (!subtype || !version) {
        return {};
    }
    wmm.subtype = static_cast<std::uint8_t>(*subtype);
    if (*subtype == 0) {
        wmm_qos_info(d, wmm);
    } else if (*subtype == 1) {
        wmm_qos_info(d, wmm);
        d.u8(d.root(), msg::reserved);
        wmm.access_categories = decode_edca_records(d, d.root());
    } else {
        d.rest(d.root(), msg::data);
    }
    return wmm;
}

ElementValue decode_vendor_wps(Decoder& d) {
    read_vendor_type(d);
    Wps wps;
    while (d.remaining() >= 4) {
        const auto start = d.offset();
        const auto type = *d.reader().u16be();
        const auto length = *d.reader().u16be();
        const auto value_start = d.offset();
        const auto value = d.reader().bytes(length);
        if (!value) {
            d.reader().rest();
            d.malformed();
            break;
        }
        const auto label = wps_label(type);
        const auto range = ByteRange{.offset = start, .length = 4U + length};
        const auto& v = *value;
        TreeNode node;

        switch (type) {
        case 0x104a: // Version
            if (length == 1) {
                wps.version = v[0];
                node = Decoder::node(label, wps_version(v[0]), range);
            }
            break;
        case 0x1044: // State
            if (length == 1) {
                wps.state = v[0];
                node = Decoder::node(
                    label,
                    EnumValue{.raw = v[0],
                              .name = v[0] == 1   ? WA_TR(wps_not_configured, "Not configured")
                                      : v[0] == 2 ? WA_TR(wps_configured, "Configured")
                                                  : Text{msg::reserved}},
                    range);
            }
            break;
        case 0x1057: // AP Setup Locked
        case 0x1041: // Selected Registrar
            if (length == 1) {
                (type == 0x1057 ? wps.ap_setup_locked : wps.selected_registrar) = v[0] != 0;
                node = Decoder::node(label, v[0] != 0, range);
            }
            break;
        case 0x1012: // Device Password ID
            if (length == 2) {
                wps.device_password_id = static_cast<std::uint16_t>((v[0] << 8U) | v[1]);
                constexpr std::array<Text, 8> names{
                    WA_TR(wps_pw_default, "Default (PIN)"),
                    WA_TR(wps_pw_user, "User-specified"),
                    WA_TR(wps_pw_machine, "Machine-specified"),
                    WA_TR(wps_pw_rekey, "Rekey"),
                    WA_TR(wps_pw_push_button, "Push Button"),
                    WA_TR(wps_pw_registrar, "Registrar-specified"),
                    Text{},
                    WA_TR(wps_pw_nfc_handover, "NFC Connection Handover")};
                node = Decoder::node(label,
                                     EnumValue{.raw = *wps.device_password_id,
                                               .name = table_name(names, *wps.device_password_id)},
                                     range);
            }
            break;
        case 0x1008: // Config Methods
        case 0x1053: // Selected Registrar Config Methods
            if (length == 2) {
                const auto methods = static_cast<std::uint16_t>((v[0] << 8U) | v[1]);
                if (type == 0x1008) {
                    wps.config_methods = methods;
                }
                // Big-endian on the air; BitField numbers bits LSB-first of the value.
                BitField b{be_node(label, v, value_start, Display::hex),
                           {static_cast<std::uint8_t>(methods & 0xffU),
                            static_cast<std::uint8_t>(methods >> 8U)}};
                config_methods(b);
                node = b.take();
                node.bytes = range;
            }
            break;
        case 0x103b: // Response Type
            if (length == 1) {
                constexpr std::array<Text, 4> names{
                    WA_TR(wps_rt_enrollee_info, "Enrollee, Info only"),
                    WA_TR(wps_rt_enrollee_8021x, "Enrollee, open 802.1X"),
                    WA_TR(wps_rt_registrar, "Registrar"), "AP"};
                node = Decoder::node(label, EnumValue{.raw = v[0], .name = table_name(names, v[0])},
                                     range);
            }
            break;
        case 0x103c: // RF Bands
            if (length == 1) {
                BitField b{Decoder::node(label, std::uint64_t{v[0]}, range), {v[0]}};
                b.node().display = Display::hex;
                b.flag(0, WA_TR(band_2_4, "2.4 GHz"));
                b.flag(1, WA_TR(band_5, "5 GHz"));
                b.flag(2, WA_TR(band_60, "60 GHz"));
                node = b.take();
            }
            break;
        case 0x1021:
            wps.manufacturer = core::display_text(v);
            node = Decoder::node(label, wps.manufacturer, range);
            break;
        case 0x1023:
            wps.model_name = core::display_text(v);
            node = Decoder::node(label, wps.model_name, range);
            break;
        case 0x1024:
            wps.model_number = core::display_text(v);
            node = Decoder::node(label, wps.model_number, range);
            break;
        case 0x1042:
            wps.serial_number = core::display_text(v);
            node = Decoder::node(label, wps.serial_number, range);
            break;
        case 0x1011:
            wps.device_name = core::display_text(v);
            node = Decoder::node(label, wps.device_name, range);
            break;
        case 0x1054: // Primary Device Type
            if (length == 8) {
                const auto category = static_cast<std::uint16_t>((v[0] << 8U) | v[1]);
                wps.primary_device_category = category;
                node = Decoder::node(label, {}, range);
                node.children.push_back(Decoder::node(
                    WA_TR(wps_category, "Category"),
                    EnumValue{.raw = category, .name = device_category_name(category)},
                    ByteRange{.offset = value_start, .length = 2}));
                node.children.push_back(
                    Decoder::node(WA_TR(vendor_oui, "OUI"), core::format_mac(v.subspan(2, 4)),
                                  ByteRange{.offset = value_start + 2, .length = 4}));
                node.children.push_back(be_node(WA_TR(wps_subcategory, "Subcategory"),
                                                v.subspan(6, 2), value_start + 6));
            }
            break;
        case 0x1049: // Vendor Extension
            node = Decoder::node(label, {}, range);
            wps_vendor_extension(node, v, value_start, wps);
            break;
        default:
            break;
        }

        if (node.children.empty() && std::holds_alternative<std::monostate>(node.value)) {
            node = Decoder::node(label, std::vector<std::uint8_t>(v.begin(), v.end()), range);
        }
        if (label == WA_TR(wps_unknown_attribute, "Unknown Attribute")) {
            node.children.push_back(Decoder::node(WA_TR(wps_attribute_type, "Attribute Type"),
                                                  std::uint64_t{type},
                                                  ByteRange{.offset = start, .length = 2}));
            node.children.back().display = Display::hex;
        }
        d.add(std::move(node));
    }
    return wps;
}

} // namespace wifi_analyze::ie
