// SPDX-License-Identifier: MIT
// Basic standard elements. Reference: IEEE Std 802.11-2020, clause 9.4.2 (element formats).

#include <algorithm>
#include <array>
#include <string>

#include "ie/decoders.hpp"

namespace wifi_analyze::ie {
namespace {

using core::table_name;

constexpr std::array<Text, 128> membership_selectors = [] {
    std::array<Text, 128> t{};
    t[121] = WA_TR(rates_selector_eht, "EHT PHY");
    t[122] = WA_TR(rates_selector_he, "HE PHY");
    t[123] = WA_TR(rates_selector_sae_h2e, "SAE Hash-to-Element only");
    t[124] = WA_TR(rates_selector_epd, "EPD");
    t[125] = WA_TR(rates_selector_glk, "GLK");
    t[126] = WA_TR(rates_selector_vht, "VHT PHY");
    t[127] = WA_TR(rates_selector_ht, "HT PHY");
    return t;
}();

} // namespace

Text access_network_type_name(std::uint64_t v) {
    switch (v) {
    case 0:
        return WA_TR(ant_private, "Private network");
    case 1:
        return WA_TR(ant_private_guest, "Private network with guest access");
    case 2:
        return WA_TR(ant_chargeable_public, "Chargeable public network");
    case 3:
        return WA_TR(ant_free_public, "Free public network");
    case 4:
        return WA_TR(ant_personal_device, "Personal device network");
    case 5:
        return WA_TR(ant_emergency, "Emergency services only network");
    case 14:
        return WA_TR(ant_test, "Test or experimental");
    case 15:
        return WA_TR(ant_wildcard, "Wildcard");
    default:
        return msg::reserved;
    }
}

ElementValue decode_ssid(Decoder& d) {
    Ssid ssid;
    const auto data = d.reader().rest();
    ssid.bytes.assign(data.begin(), data.end());
    ssid.hidden = std::ranges::all_of(data, [](std::uint8_t b) { return b == 0; });
    auto n = Decoder::node(WA_TR(ssid_name, "SSID"), core::display_text(data),
                           ByteRange{.offset = 0, .length = data.size()});
    d.add(std::move(n));
    if (ssid.hidden) {
        d.add(Decoder::node(WA_TR(ssid_hidden, "Hidden SSID"), true,
                            ByteRange{.offset = 0, .length = data.size()}));
    }
    if (data.size() > 32) {
        d.diagnostic(Severity::warning, WA_TR(ssid_too_long, "SSID is longer than 32 octets ({0})"),
                     {std::to_string(data.size())});
    }
    return ssid;
}

ElementValue decode_supported_rates(Decoder& d) {
    SupportedRates rates;
    for (auto start = d.offset(); const auto octet = d.reader().u8(); start = d.offset()) {
        const auto b = *octet;
        const auto value = static_cast<std::uint8_t>(b & 0x7fU);
        const bool basic = (b & 0x80U) != 0;
        const auto range = d.range_from(start);
        if (basic && !membership_selectors[value].empty()) {
            rates.membership_selectors.push_back(value);
            d.add(Decoder::node(WA_TR(rates_membership_selector, "BSS Membership Selector"),
                                EnumValue{.raw = value, .name = membership_selectors[value]},
                                range));
        } else {
            rates.rates.push_back(Rate{.units_500kbps = value, .basic = basic});
            d.add(Decoder::node(basic ? WA_TR(rates_basic_rate, "Basic Rate")
                                      : WA_TR(rates_rate, "Supported Rate"),
                                static_cast<double>(value) / 2.0, range, Unit::mbps));
        }
    }
    return rates;
}

ElementValue decode_ds_parameter_set(Decoder& d) {
    const auto channel = d.u8(d.root(), WA_TR(ds_current_channel, "Current Channel"));
    if (!channel) {
        return {};
    }
    return DsParameterSet{.channel = *channel};
}

ElementValue decode_tim(Decoder& d) {
    d.u8(d.root(), WA_TR(tim_dtim_count, "DTIM Count"));
    d.u8(d.root(), WA_TR(tim_dtim_period, "DTIM Period"));
    if (auto control = d.bits(WA_TR(tim_bitmap_control, "Bitmap Control"), 1)) {
        control->flag(0, WA_TR(tim_group_traffic, "Group Addressed Traffic Buffered"));
        control->number(1, 7, WA_TR(tim_bitmap_offset, "Bitmap Offset"));
        d.add(control->take());
    }
    d.rest(d.root(), WA_TR(tim_partial_bitmap, "Partial Virtual Bitmap"));
    return {};
}

ElementValue decode_ibss_parameter_set(Decoder& d) {
    d.u16(d.root(), WA_TR(ibss_atim_window, "ATIM Window"), Unit::tu);
    return {};
}

ElementValue decode_country(Decoder& d) {
    Country country;
    const auto start = d.offset();
    const auto code = d.reader().bytes(2);
    if (!code) {
        d.malformed();
        return {};
    }
    country.code = core::display_text(*code);
    d.add(Decoder::node(WA_TR(country_code, "Country Code"), country.code, d.range_from(start)));
    // Conformant lengths are 3 + 3n (+ 1 padding octet). A length of 2 + 3n means the
    // environment octet is missing (seen e.g. on the Android emulator's AP); the triplets are
    // still decoded.
    if (d.content().size() % 3 == 2) {
        d.diagnostic(Severity::warning,
                     WA_TR(country_missing_environment,
                           "Country string has no environment octet (non-conformant)"),
                     {}, ByteRange{.offset = 0, .length = 2});
    } else {
        const auto env = d.enumeration(
            d.root(), WA_TR(country_environment, "Environment"), 1, [](std::uint64_t v) -> Text {
                switch (v) {
                case ' ':
                    return WA_TR(country_env_any, "All environments");
                case 'O':
                    return WA_TR(country_env_outdoor, "Outdoor");
                case 'I':
                    return WA_TR(country_env_indoor, "Indoor");
                case 'X':
                    return WA_TR(country_env_noncountry, "Non-country entity");
                case 1:
                case 2:
                case 3:
                case 4:
                case 5:
                    return WA_TR(country_env_table, "Operating classes of Annex E table");
                default:
                    return msg::reserved;
                }
            });
        if (!env) {
            return country;
        }
        country.environment = static_cast<std::uint8_t>(*env);
    }

    while (d.remaining() >= 3) {
        const auto triplet_start = d.offset();
        if (d.reader().peek_u8().value_or(0) >= 201) {
            auto t = d.group(WA_TR(country_operating_triplet, "Operating Triplet"));
            d.u8(t, WA_TR(country_operating_extension, "Operating Extension Identifier"));
            d.u8(t, WA_TR(country_operating_class, "Operating Class"));
            d.u8(t, WA_TR(country_coverage_class, "Coverage Class"));
            d.close(t, triplet_start);
            d.add(std::move(t));
        } else {
            auto t = d.group(WA_TR(country_subband_triplet, "Subband Triplet"));
            d.u8(t, WA_TR(country_first_channel, "First Channel"));
            d.u8(t, WA_TR(country_channel_count, "Number of Channels"));
            d.s8(t, WA_TR(country_max_power, "Maximum Transmit Power"), Unit::dbm);
            d.close(t, triplet_start);
            d.add(std::move(t));
        }
    }
    if (d.remaining() == 1) {
        d.rest(d.root(), WA_TR(country_padding, "Padding"));
    }
    return country;
}

ElementValue decode_bss_load(Decoder& d) {
    BssLoad load;
    const auto stations = d.u16(d.root(), WA_TR(bss_load_stations, "Station Count"));
    const auto start = d.offset();
    const auto utilization = d.reader().u8();
    if (!stations || !utilization) {
        d.malformed();
        return {};
    }
    auto util = Decoder::node(WA_TR(bss_load_utilization, "Channel Utilization"),
                              static_cast<double>(*utilization) * 100.0 / 255.0,
                              d.range_from(start), Unit::percent);
    util.children.push_back(Decoder::node(WA_TR(bss_load_utilization_raw, "Raw Value (x/255)"),
                                          std::uint64_t{*utilization}, d.range_from(start)));
    d.add(std::move(util));
    const auto capacity = d.u16(
        d.root(), WA_TR(bss_load_admission_capacity, "Available Admission Capacity (32 µs/s)"));
    load.station_count = *stations;
    load.channel_utilization = *utilization;
    load.available_admission_capacity = capacity.value_or(0);
    return load;
}

ElementValue decode_power_constraint(Decoder& d) {
    const auto v =
        d.u8(d.root(), WA_TR(power_constraint_local, "Local Power Constraint"), Unit::db);
    if (!v) {
        return {};
    }
    return PowerConstraint{.local_power_constraint_db = *v};
}

ElementValue decode_tpc_report(Decoder& d) {
    d.s8(d.root(), WA_TR(tpc_transmit_power, "Transmit Power"), Unit::dbm);
    d.s8(d.root(), WA_TR(tpc_link_margin, "Link Margin"), Unit::db);
    return {};
}

ElementValue decode_channel_switch_announcement(Decoder& d) {
    d.u8(d.root(), WA_TR(csa_mode, "Channel Switch Mode"));
    d.u8(d.root(), WA_TR(csa_new_channel, "New Channel Number"));
    d.u8(d.root(), WA_TR(csa_count, "Channel Switch Count"));
    return {};
}

ElementValue decode_extended_channel_switch_announcement(Decoder& d) {
    d.u8(d.root(), WA_TR(csa_mode, "Channel Switch Mode"));
    d.u8(d.root(), WA_TR(csa_new_operating_class, "New Operating Class"));
    d.u8(d.root(), WA_TR(csa_new_channel, "New Channel Number"));
    d.u8(d.root(), WA_TR(csa_count, "Channel Switch Count"));
    return {};
}

ElementValue decode_quiet(Decoder& d) {
    d.u8(d.root(), WA_TR(quiet_count, "Quiet Count"));
    d.u8(d.root(), WA_TR(quiet_period, "Quiet Period"));
    d.u16(d.root(), WA_TR(quiet_duration, "Quiet Duration"), Unit::tu);
    d.u16(d.root(), WA_TR(quiet_offset, "Quiet Offset"), Unit::tu);
    return {};
}

ElementValue decode_erp(Decoder& d) {
    if (auto erp = d.bits(WA_TR(erp_information, "ERP Information"), 1)) {
        erp->flag(0, WA_TR(erp_non_erp_present, "Non-ERP Present"));
        erp->flag(1, WA_TR(erp_use_protection, "Use Protection"));
        erp->flag(2, WA_TR(erp_barker_preamble, "Barker Preamble Mode"));
        d.add(erp->take());
    }
    return {};
}

ElementValue decode_ap_channel_report(Decoder& d) {
    d.u8(d.root(), WA_TR(ap_channel_report_operating_class, "Operating Class"));
    auto channels = d.group(WA_TR(ap_channel_report_channels, "Channels"));
    const auto start = d.offset();
    while (!d.reader().empty()) {
        d.u8(channels, WA_TR(common_channel, "Channel"));
    }
    d.close(channels, start);
    d.add(std::move(channels));
    return {};
}

ElementValue decode_mobility_domain(Decoder& d) {
    MobilityDomain md;
    const auto mdid = d.u16(d.root(), WA_TR(mobility_domain_id, "Mobility Domain Identifier"),
                            Unit::none, Display::hex);
    auto policy = d.bits(WA_TR(mobility_domain_policy, "FT Capability and Policy"), 1);
    if (!mdid || !policy) {
        return {};
    }
    md.mdid = *mdid;
    md.ft_over_ds =
        policy->flag(0, WA_TR(mobility_domain_ft_over_ds, "Fast BSS Transition over DS"));
    md.resource_request_protocol = policy->flag(
        1, WA_TR(mobility_domain_resource_request, "Resource Request Protocol Capability"));
    d.add(policy->take());
    return md;
}

ElementValue decode_supported_operating_classes(Decoder& d) {
    d.u8(d.root(), WA_TR(supported_op_classes_current, "Current Operating Class"));
    auto list = d.group(WA_TR(supported_op_classes_list, "Operating Classes"));
    const auto start = d.offset();
    while (!d.reader().empty()) {
        d.u8(list, WA_TR(common_operating_class, "Operating Class"));
    }
    d.close(list, start);
    d.add(std::move(list));
    return {};
}

ElementValue decode_rm_enabled_capabilities(Decoder& d) {
    auto caps = d.bits(WA_TR(rm_capabilities, "RM Enabled Capabilities"), 5);
    if (!caps) {
        return {};
    }
    RmEnabledCapabilities rm;
    std::ranges::copy_n(caps->data().begin(), 5, rm.bytes.begin());
    caps->flag(0, WA_TR(rm_link_measurement, "Link Measurement"), true);
    caps->flag(1, WA_TR(rm_neighbor_report, "Neighbor Report"), true);
    caps->flag(2, WA_TR(rm_parallel, "Parallel Measurements"), true);
    caps->flag(3, WA_TR(rm_repeated, "Repeated Measurements"), true);
    caps->flag(4, WA_TR(rm_beacon_passive, "Beacon Passive Measurement"), true);
    caps->flag(5, WA_TR(rm_beacon_active, "Beacon Active Measurement"), true);
    caps->flag(6, WA_TR(rm_beacon_table, "Beacon Table Measurement"), true);
    caps->flag(7, WA_TR(rm_beacon_conditions, "Beacon Measurement Reporting Conditions"), true);
    caps->flag(8, WA_TR(rm_frame, "Frame Measurement"), true);
    caps->flag(9, WA_TR(rm_channel_load, "Channel Load Measurement"), true);
    caps->flag(10, WA_TR(rm_noise_histogram, "Noise Histogram Measurement"), true);
    caps->flag(11, WA_TR(rm_statistics, "Statistics Measurement"), true);
    caps->flag(12, WA_TR(rm_lci, "LCI Measurement"), true);
    caps->flag(13, WA_TR(rm_lci_azimuth, "LCI Azimuth"), true);
    caps->flag(14, WA_TR(rm_tx_stream, "Transmit Stream/Category Measurement"), true);
    caps->flag(15, WA_TR(rm_triggered_tx_stream, "Triggered Transmit Stream/Category Measurement"),
               true);
    caps->flag(16, WA_TR(rm_ap_channel_report, "AP Channel Report"), true);
    caps->flag(17, WA_TR(rm_mib, "RM MIB"), true);
    caps->number(18, 3,
                 WA_TR(rm_op_channel_max_duration, "Operating Channel Max Measurement Duration"));
    caps->number(
        21, 3,
        WA_TR(rm_nonop_channel_max_duration, "Nonoperating Channel Max Measurement Duration"));
    caps->number(24, 3, WA_TR(rm_measurement_pilot, "Measurement Pilot Capability"));
    caps->flag(27, WA_TR(rm_measurement_pilot_info, "Measurement Pilot Transmission Information"),
               true);
    caps->flag(28, WA_TR(rm_neighbor_tsf_offset, "Neighbor Report TSF Offset"), true);
    caps->flag(29, WA_TR(rm_rcpi, "RCPI Measurement"), true);
    caps->flag(30, WA_TR(rm_rsni, "RSNI Measurement"), true);
    caps->flag(31, WA_TR(rm_bss_avg_access_delay, "BSS Average Access Delay"), true);
    caps->flag(32, WA_TR(rm_bss_admission_capacity, "BSS Available Admission Capacity"), true);
    caps->flag(33, WA_TR(rm_antenna, "Antenna"), true);
    caps->flag(34, WA_TR(rm_ftm_range_report, "FTM Range Report"), true);
    caps->flag(35, WA_TR(rm_civic_location, "Civic Location Measurement"), true);
    d.add(caps->take());
    return rm;
}

ElementValue decode_bss_coexistence(Decoder& d) {
    if (auto b = d.bits(WA_TR(coexistence_information, "20/40 BSS Coexistence Information"), 1)) {
        b->flag(0, WA_TR(coexistence_info_request, "Information Request"));
        b->flag(1, WA_TR(coexistence_40_intolerant, "Forty MHz Intolerant"));
        b->flag(2, WA_TR(coexistence_20_width_request, "20 MHz BSS Width Request"));
        b->flag(3, WA_TR(coexistence_obss_exemption_request, "OBSS Scanning Exemption Request"));
        b->flag(4, WA_TR(coexistence_obss_exemption_grant, "OBSS Scanning Exemption Grant"));
        d.add(b->take());
    }
    return {};
}

ElementValue decode_obss_scan_parameters(Decoder& d) {
    d.u16(d.root(), WA_TR(obss_passive_dwell, "OBSS Scan Passive Dwell"), Unit::tu);
    d.u16(d.root(), WA_TR(obss_active_dwell, "OBSS Scan Active Dwell"), Unit::tu);
    d.u16(d.root(), WA_TR(obss_trigger_interval, "BSS Channel Width Trigger Scan Interval"));
    d.u16(d.root(), WA_TR(obss_passive_total, "OBSS Scan Passive Total Per Channel"), Unit::tu);
    d.u16(d.root(), WA_TR(obss_active_total, "OBSS Scan Active Total Per Channel"), Unit::tu);
    d.u16(d.root(), WA_TR(obss_transition_delay, "BSS Width Channel Transition Delay Factor"));
    d.u16(d.root(), WA_TR(obss_activity_threshold, "OBSS Scan Activity Threshold"));
    return {};
}

ElementValue decode_interworking(Decoder& d) {
    auto options = d.bits(WA_TR(interworking_access_network_options, "Access Network Options"), 1);
    if (!options) {
        return {};
    }
    Interworking iw;
    iw.access_network_type = static_cast<std::uint8_t>(
        options->enumeration(0, 4, WA_TR(interworking_access_network_type, "Access Network Type"),
                             access_network_type_name));
    iw.internet = options->flag(4, WA_TR(interworking_internet, "Internet"));
    iw.asra =
        options->flag(5, WA_TR(interworking_asra, "ASRA (Additional Step Required for Access)"));
    iw.esr = options->flag(6, WA_TR(interworking_esr, "ESR (Emergency Services Reachable)"));
    iw.uesa = options->flag(
        7, WA_TR(interworking_uesa, "UESA (Unauthenticated Emergency Service Accessible)"));
    d.add(options->take());

    const auto remaining = d.remaining();
    if (remaining == 2 || remaining == 8) {
        iw.venue_group = d.u8(d.root(), WA_TR(interworking_venue_group, "Venue Group"));
        iw.venue_type = d.u8(d.root(), WA_TR(interworking_venue_type, "Venue Type"));
    }
    if (d.remaining() == 6) {
        iw.hessid = d.mac(d.root(), WA_TR(interworking_hessid, "HESSID"));
    }
    return iw;
}

ElementValue decode_advertisement_protocol(Decoder& d) {
    while (!d.reader().empty()) {
        const auto start = d.offset();
        auto tuple = d.group(WA_TR(adv_protocol_tuple, "Advertisement Protocol Tuple"));
        auto info = d.bits(WA_TR(adv_query_response_info, "Query Response Info"), 1);
        if (!info) {
            break;
        }
        info->number(0, 7, WA_TR(adv_query_response_limit, "Query Response Length Limit"));
        info->flag(7, WA_TR(adv_pame_bi, "PAME-BI"));
        tuple.children.push_back(info->take());
        const auto id =
            d.enumeration(tuple, WA_TR(adv_protocol_id, "Advertisement Protocol ID"), 1,
                          [](std::uint64_t v) -> Text {
                              switch (v) {
                              case 0:
                                  return "ANQP";
                              case 1:
                                  return WA_TR(adv_mih_is, "MIH Information Service");
                              case 2:
                                  return WA_TR(adv_mih_es, "MIH Command and Event Services");
                              case 3:
                                  return "EAS";
                              case 4:
                                  return "RLQP";
                              case 221:
                                  return WA_TR(adv_vendor, "Vendor Specific");
                              default:
                                  return msg::reserved;
                              }
                          });
        if (id == 221) {
            d.rest(tuple, msg::data); // vendor-specific format, length implied
        }
        d.close(tuple, start);
        d.add(std::move(tuple));
    }
    return {};
}

ElementValue decode_roaming_consortium(Decoder& d) {
    d.u8(d.root(), WA_TR(roaming_anqp_ois, "Number of ANQP OIs"));
    auto lengths = d.bits(WA_TR(roaming_oi_lengths, "OI #1 and #2 Lengths"), 1);
    if (!lengths) {
        return {};
    }
    const auto len1 = lengths->number(0, 4, WA_TR(roaming_oi1_length, "OI #1 Length"));
    const auto len2 = lengths->number(4, 4, WA_TR(roaming_oi2_length, "OI #2 Length"));
    d.add(lengths->take());
    d.bytes(d.root(), WA_TR(roaming_oi1, "OI #1"), static_cast<std::size_t>(len1));
    if (len2 > 0) {
        d.bytes(d.root(), WA_TR(roaming_oi2, "OI #2"), static_cast<std::size_t>(len2));
    }
    d.rest(d.root(), WA_TR(roaming_oi3, "OI #3"));
    return {};
}

ElementValue decode_mesh_configuration(Decoder& d) {
    d.u8(d.root(), WA_TR(mesh_path_selection_protocol, "Active Path Selection Protocol"));
    d.u8(d.root(), WA_TR(mesh_path_selection_metric, "Active Path Selection Metric"));
    d.u8(d.root(), WA_TR(mesh_congestion_control, "Congestion Control Mode"));
    d.u8(d.root(), WA_TR(mesh_sync_method, "Synchronization Method"));
    d.u8(d.root(), WA_TR(mesh_auth_protocol, "Authentication Protocol"));
    if (auto info = d.bits(WA_TR(mesh_formation_info, "Mesh Formation Info"), 1)) {
        info->flag(0, WA_TR(mesh_connected_to_gate, "Connected to Mesh Gate"));
        info->number(1, 6, WA_TR(mesh_peerings, "Number of Peerings"));
        info->flag(7, WA_TR(mesh_connected_to_as, "Connected to AS"));
        d.add(info->take());
    }
    if (auto caps = d.bits(WA_TR(mesh_capability, "Mesh Capability"), 1)) {
        caps->flag(0, WA_TR(mesh_accepting_peerings, "Accepting Additional Mesh Peerings"));
        caps->flag(1, WA_TR(mesh_mcca_supported, "MCCA Supported"));
        caps->flag(2, WA_TR(mesh_mcca_enabled, "MCCA Enabled"));
        caps->flag(3, WA_TR(mesh_forwarding, "Mesh Forwarding"));
        caps->flag(4, WA_TR(mesh_mbca_enabled, "MBCA Enabled"));
        caps->flag(5, WA_TR(mesh_tbtt_adjusting, "TBTT Adjusting"));
        caps->flag(6, WA_TR(mesh_power_save, "Mesh Power Save Level"));
        d.add(caps->take());
    }
    return {};
}

ElementValue decode_mesh_id(Decoder& d) {
    d.text(d.root(), WA_TR(mesh_id, "Mesh ID"), d.remaining());
    return {};
}

ElementValue decode_transmit_power_envelope(Decoder& d) {
    auto info = d.bits(WA_TR(tpe_information, "Transmit Power Information"), 1);
    if (!info) {
        return {};
    }
    const auto count = info->number(0, 3, WA_TR(tpe_count, "Maximum Transmit Power Count"));
    const auto interpretation = info->enumeration(
        3, 3, WA_TR(tpe_interpretation, "Maximum Transmit Power Interpretation"),
        [](std::uint64_t v) -> Text {
            switch (v) {
            case 0:
                return WA_TR(tpe_local_eirp, "Local EIRP");
            case 1:
                return WA_TR(tpe_local_eirp_psd, "Local EIRP PSD");
            case 2:
                return WA_TR(tpe_regulatory_eirp, "Regulatory client EIRP");
            case 3:
                return WA_TR(tpe_regulatory_eirp_psd, "Regulatory client EIRP PSD");
            default:
                return msg::reserved;
            }
        });
    info->enumeration(6, 2, WA_TR(tpe_category, "Maximum Transmit Power Category"),
                      [](std::uint64_t v) -> Text {
                          switch (v) {
                          case 0:
                              return WA_TR(tpe_category_default, "Default");
                          case 1:
                              return WA_TR(tpe_category_subordinate, "Subordinate device");
                          default:
                              return msg::reserved;
                          }
                      });
    d.add(info->take());

    // EIRP: count + 1 values (20, 40, 80, 160 MHz). PSD: 1 value for count 0, else 2^(count-1).
    const bool psd = interpretation == 1 || interpretation == 3;
    const auto n = static_cast<std::size_t>(count);
    const std::size_t values = psd ? (n == 0 ? 1 : (std::size_t{1} << (n - 1))) : n + 1;
    auto list = d.group(WA_TR(tpe_values, "Maximum Transmit Power"));
    const auto start = d.offset();
    for (std::size_t i = 0; i < values && !d.reader().empty(); ++i) {
        const auto value_start = d.offset();
        const auto raw = static_cast<std::int8_t>(d.reader().u8().value_or(0));
        list.children.push_back(
            Decoder::node(WA_TR(common_value, "Value"), static_cast<double>(raw) / 2.0,
                          d.range_from(value_start), psd ? Unit::dbm_per_mhz : Unit::dbm));
    }
    d.close(list, start);
    d.add(std::move(list));
    return {};
}

ElementValue decode_operating_mode_notification(Decoder& d) {
    if (auto b = d.bits(WA_TR(omn_operating_mode, "Operating Mode"), 1)) {
        b->enumeration(
            0, 2, WA_TR(omn_channel_width, "Channel Width"), [](std::uint64_t v) -> Text {
                constexpr std::array<Text, 4> names{"20 MHz", "40 MHz", "80 MHz", "160/80+80 MHz"};
                return table_name(names, v);
            });
        b->flag(2, WA_TR(omn_160_80p80, "160/80+80 MHz BW"));
        b->flag(3, WA_TR(omn_no_ldpc, "No LDPC"));
        b->number(4, 3, WA_TR(omn_rx_nss, "Rx NSS"), Unit::none, 1);
        b->flag(7, WA_TR(omn_rx_nss_type, "Rx NSS Type"));
        d.add(b->take());
    }
    return {};
}

} // namespace wifi_analyze::ie
