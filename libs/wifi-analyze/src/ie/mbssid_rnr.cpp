// SPDX-License-Identifier: MIT
// Multiple BSSID (71), Nontransmitted BSSID Capability (83), Multiple BSSID-Index (85) and
// Reduced Neighbor Report (201). Reference: IEEE Std 802.11-2020 and IEEE Std 802.11ax-2021
// (RNR TBTT Information field formats), IEEE Std 802.11be-2024 (MLD Parameters).

#include <array>
#include <string>

#include "ie/decoders.hpp"

namespace wifi_analyze::ie {
namespace {

void add_capability_info_bits(core::BitField& b) {
    b.flag(0, WA_TR(capinfo_ess, "ESS"));
    b.flag(1, WA_TR(capinfo_ibss, "IBSS"));
    b.flag(4, WA_TR(capinfo_privacy, "Privacy"));
    b.flag(5, WA_TR(capinfo_short_preamble, "Short Preamble"));
    b.flag(8, WA_TR(capinfo_spectrum_mgmt, "Spectrum Management"));
    b.flag(9, WA_TR(capinfo_qos, "QoS"));
    b.flag(10, WA_TR(capinfo_short_slot, "Short Slot Time"));
    b.flag(11, WA_TR(capinfo_apsd, "APSD"));
    b.flag(12, WA_TR(capinfo_radio_measurement, "Radio Measurement"));
    b.flag(13, WA_TR(capinfo_epd, "EPD"));
}

void add_bss_parameters(core::BitField& b) {
    b.flag(0, WA_TR(rnr_oct_recommended, "OCT Recommended"));
    b.flag(1, WA_TR(rnr_same_ssid, "Same SSID"));
    b.flag(2, WA_TR(rnr_multiple_bssid, "Multiple BSSID"));
    b.flag(3, WA_TR(rnr_transmitted_bssid, "Transmitted BSSID"));
    b.flag(4, WA_TR(rnr_member_of_ess, "Member of ESS with 2.4/5 GHz Co-Located AP"));
    b.flag(5, WA_TR(rnr_unsolicited_probe, "Unsolicited Probe Responses Active"));
    b.flag(6, WA_TR(rnr_co_located, "Co-Located AP"));
}

/// Field layout of a TBTT Information field (type 0) by its length (802.11ax / 802.11be).
struct TbttLayout {
    bool bssid;
    bool short_ssid;
    bool bss_parameters;
    bool psd;
    bool mld;
};

std::optional<TbttLayout> tbtt_layout(std::size_t length) {
    switch (length) {
    case 1:
        return TbttLayout{false, false, false, false, false};
    case 2:
        return TbttLayout{false, false, true, false, false};
    case 5:
        return TbttLayout{false, true, false, false, false};
    case 6:
        return TbttLayout{false, true, true, false, false};
    case 7:
        return TbttLayout{true, false, false, false, false};
    case 8:
        return TbttLayout{true, false, true, false, false};
    case 9:
        return TbttLayout{true, false, true, true, false};
    case 11:
        return TbttLayout{true, true, false, false, false};
    case 12:
        return TbttLayout{true, true, true, false, false};
    case 13:
        return TbttLayout{true, true, true, true, false};
    default:
        if (length >= 16) {
            return TbttLayout{true, true, true, true, true};
        }
        return std::nullopt;
    }
}

} // namespace

ElementValue decode_multiple_bssid(Decoder& d) {
    MultipleBssid mbssid;
    const auto indicator = d.u8(d.root(), WA_TR(mbssid_max_indicator, "MaxBSSID Indicator"));
    if (!indicator) {
        return {};
    }
    mbssid.max_bssid_indicator = *indicator;
    if (*indicator <= 8) {
        d.add(Decoder::node(WA_TR(mbssid_max_bssids, "Maximum Number of BSSIDs"),
                            std::uint64_t{1} << *indicator));
    }

    while (d.remaining() >= 2) {
        const auto start = d.offset();
        const auto header = d.reader().array<2>();
        if (!header) {
            break;
        }
        const auto id = (*header)[0];
        const auto length = (*header)[1];
        const auto body_offset = d.offset();
        const auto body = d.reader().bytes(length);
        if (!body) {
            d.reader().rest();
            d.malformed();
            break;
        }
        if (id == 0) {
            auto profile = Decoder::node(WA_TR(mbssid_profile, "Nontransmitted BSSID Profile"), {},
                                         ByteRange{.offset = start, .length = 2U + length});
            d.nested_elements(profile, *body, body_offset);
            d.add(std::move(profile));
            ++mbssid.nontransmitted_profiles;
        } else {
            d.add(Decoder::node(id == element_id_vendor_specific
                                    ? WA_TR(subelement_vendor, "Vendor Specific Subelement")
                                    : WA_TR(subelement_unknown, "Unknown Subelement"),
                                std::vector<std::uint8_t>(body->begin(), body->end()),
                                ByteRange{.offset = start, .length = 2U + length}));
        }
    }
    return mbssid;
}

ElementValue decode_nontransmitted_bssid_capability(Decoder& d) {
    if (auto caps = d.bits(WA_TR(nontx_capability, "Nontransmitted BSSID Capability"), 2)) {
        add_capability_info_bits(*caps);
        d.add(caps->take());
    }
    return {};
}

ElementValue decode_multiple_bssid_index(Decoder& d) {
    d.u8(d.root(), WA_TR(mbssid_index, "BSSID Index"));
    if (!d.reader().empty()) {
        d.u8(d.root(), WA_TR(tim_dtim_period, "DTIM Period"));
        d.u8(d.root(), WA_TR(tim_dtim_count, "DTIM Count"));
    }
    return {};
}

ElementValue decode_reduced_neighbor_report(Decoder& d) {
    ReducedNeighborReport rnr;
    while (!d.reader().empty()) {
        const auto start = d.offset();
        auto ap = d.group(WA_TR(rnr_neighbor_ap, "Neighbor AP Information"));
        auto header = d.bits(WA_TR(rnr_tbtt_header, "TBTT Information Header"), 2);
        if (!header) {
            break;
        }
        const auto field_type =
            header->number(0, 2, WA_TR(rnr_tbtt_field_type, "TBTT Information Field Type"));
        header->flag(2, WA_TR(rnr_filtered, "Filtered Neighbor AP"));
        const auto count =
            header->number(4, 4, WA_TR(rnr_tbtt_count, "TBTT Information Count"), Unit::none, 1) +
            1;
        const auto length = static_cast<std::size_t>(
            header->number(8, 8, WA_TR(rnr_tbtt_length, "TBTT Information Length"), Unit::octets));
        ap.children.push_back(header->take());

        RnrNeighbor neighbor;
        const auto op_class = d.u8(ap, WA_TR(common_operating_class, "Operating Class"));
        const auto channel = d.u8(ap, WA_TR(common_channel, "Channel"));
        if (!op_class || !channel) {
            d.close(ap, start);
            d.add(std::move(ap));
            break;
        }
        neighbor.operating_class = *op_class;
        neighbor.channel = *channel;

        const auto layout = field_type == 0 ? tbtt_layout(length) : std::nullopt;
        for (std::uint64_t i = 0; i < count; ++i) {
            const auto info_start = d.offset();
            const auto info_bytes = d.reader().bytes(length);
            if (!info_bytes) {
                d.malformed();
                break;
            }
            auto info = Decoder::node(WA_TR(rnr_tbtt_info, "TBTT Information"), {},
                                      ByteRange{.offset = info_start, .length = length});
            if (!layout) {
                info.value = std::vector<std::uint8_t>(info_bytes->begin(), info_bytes->end());
                ap.children.push_back(std::move(info));
                continue;
            }
            // Re-read the field with a sub-decoder positioned on it.
            core::ByteReader r{*info_bytes};
            RnrTbttInfo tbtt;
            const auto pos = [&] {
                return info_start + r.offset();
            };
            const auto range = [&](std::size_t from) {
                return ByteRange{.offset = from, .length = pos() - from};
            };
            auto p = pos();
            const auto offset_value = r.u8().value_or(0);
            info.children.push_back(Decoder::node(WA_TR(rnr_tbtt_offset, "Neighbor AP TBTT Offset"),
                                                  std::uint64_t{offset_value}, range(p), Unit::tu));
            if (layout->bssid) {
                p = pos();
                tbtt.bssid = r.array<6>();
                info.children.push_back(Decoder::node(WA_TR(common_bssid, "BSSID"),
                                                      core::format_mac(*tbtt.bssid), range(p)));
            }
            if (layout->short_ssid) {
                p = pos();
                tbtt.short_ssid = r.u32le();
                auto n = Decoder::node(WA_TR(rnr_short_ssid, "Short SSID"),
                                       std::uint64_t{*tbtt.short_ssid}, range(p));
                n.display = Display::hex;
                info.children.push_back(std::move(n));
            }
            if (layout->bss_parameters) {
                p = pos();
                tbtt.bss_parameters = r.u8();
                core::BitField b{Decoder::node(WA_TR(rnr_bss_parameters, "BSS Parameters"),
                                               std::uint64_t{*tbtt.bss_parameters}, range(p)),
                                 {*tbtt.bss_parameters}};
                b.node().display = Display::hex;
                add_bss_parameters(b);
                info.children.push_back(b.take());
            }
            if (layout->psd) {
                p = pos();
                const auto psd = static_cast<std::int8_t>(r.u8().value_or(0));
                info.children.push_back(Decoder::node(WA_TR(rnr_psd, "20 MHz PSD"),
                                                      static_cast<double>(psd) / 2.0, range(p),
                                                      Unit::dbm_per_mhz));
            }
            if (layout->mld) {
                p = pos();
                const auto mld = r.bytes(3);
                core::BitField b{Decoder::node(WA_TR(rnr_mld_parameters, "MLD Parameters"),
                                               std::vector<std::uint8_t>(mld->begin(), mld->end()),
                                               range(p)),
                                 std::vector<std::uint8_t>(mld->begin(), mld->end())};
                tbtt.mld_ap_id =
                    static_cast<std::uint8_t>(b.number(0, 8, WA_TR(rnr_ap_mld_id, "AP MLD ID")));
                tbtt.mld_link_id =
                    static_cast<std::uint8_t>(b.number(8, 4, WA_TR(mlo_link_id, "Link ID")));
                b.number(12, 8, WA_TR(rnr_bss_change_count, "BSS Parameters Change Count"));
                b.flag(20, WA_TR(rnr_all_updates, "All Updates Included"));
                b.flag(21, WA_TR(rnr_disabled_link, "Disabled Link Indication"));
                info.children.push_back(b.take());
                const auto rest_start = pos();
                const auto rest = r.rest();
                if (!rest.empty()) {
                    info.children.push_back(Decoder::node(
                        msg::reserved, std::vector<std::uint8_t>(rest.begin(), rest.end()),
                        range(rest_start)));
                }
            }
            neighbor.tbtt.push_back(tbtt);
            ap.children.push_back(std::move(info));
        }
        d.close(ap, start);
        d.add(std::move(ap));
        rnr.neighbors.push_back(std::move(neighbor));
        if (d.is_malformed()) {
            break;
        }
    }
    return rnr;
}

} // namespace wifi_analyze::ie
