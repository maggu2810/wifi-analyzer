// SPDX-License-Identifier: MIT
// Derived per-BSS summary. Channel width rules: IEEE Std 802.11-2020 (VHT Operation, Table 9-274
// "VHT Operation Information subfields"), 802.11ax-2021 (6 GHz Operation Information),
// 802.11be-2024 (EHT Operation Information). PHY rates: N_SD x bits x R / T_symbol.

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdlib>
#include <set>
#include <string>

#include <wifi_analyze/oui.hpp>
#include <wifi_analyze/summary.hpp>

#include "core/decoder.hpp"
#include "core/tr.hpp"
#include "ie/decoders.hpp"

namespace wifi_analyze {
namespace {

// --- PHY rate model ----------------------------------------------------------------------

struct Modulation {
    unsigned bits;
    double rate;
};

constexpr std::array<Modulation, 14> mcs_table{{
    {1, 1.0 / 2},
    {2, 1.0 / 2},
    {2, 3.0 / 4},
    {4, 1.0 / 2},
    {4, 3.0 / 4},
    {6, 2.0 / 3},
    {6, 3.0 / 4},
    {6, 5.0 / 6},
    {8, 3.0 / 4},
    {8, 5.0 / 6},
    {10, 3.0 / 4},
    {10, 5.0 / 6},
    {12, 3.0 / 4},
    {12, 5.0 / 6},
}};

std::optional<unsigned> data_subcarriers(int phy, unsigned width) {
    if (phy <= 5) { // HT / VHT
        switch (width) {
        case 20:
            return 52;
        case 40:
            return 108;
        case 80:
            return phy == 5 ? std::optional<unsigned>{234} : std::nullopt;
        case 160:
            return phy == 5 ? std::optional<unsigned>{468} : std::nullopt;
        default:
            return std::nullopt;
        }
    }
    switch (width) { // HE / EHT
    case 20:
        return 234;
    case 40:
        return 468;
    case 80:
        return 980;
    case 160:
        return 1960;
    case 320:
        return phy == 7 ? std::optional<unsigned>{3920} : std::nullopt;
    default:
        return std::nullopt;
    }
}

/// Highest MCS of a VHT/HE 2-bit MCS map entry; nullopt = not supported.
std::optional<unsigned> map_max_mcs(int phy, unsigned entry) {
    if (entry == 3) {
        return std::nullopt;
    }
    if (phy == 5) {
        return 7 + entry; // 0-7, 0-8, 0-9
    }
    return 7 + (2 * entry); // HE: 0-7, 0-9, 0-11
}

double best_rate_from_map(int phy, unsigned width, std::uint16_t map, bool sgi,
                          std::uint8_t& nss_out) {
    double best = 0;
    for (unsigned ss = 1; ss <= 8; ++ss) {
        const auto mcs = map_max_mcs(phy, (map >> (2 * (ss - 1))) & 0x3U);
        if (!mcs) {
            continue;
        }
        nss_out = std::max<std::uint8_t>(nss_out, static_cast<std::uint8_t>(ss));
        for (int m = static_cast<int>(*mcs); m >= 0; --m) {
            if (const auto r = phy_rate_mbps(phy, width, static_cast<unsigned>(m), ss, sgi)) {
                best = std::max(best, *r);
                break;
            }
        }
    }
    return best;
}

// --- channel helpers ---------------------------------------------------------------------

std::optional<std::uint32_t> freq(Band band, unsigned channel) {
    return frequency_from_channel(band, static_cast<std::uint16_t>(channel));
}

unsigned channel_distance(unsigned a, unsigned b) {
    return a > b ? a - b : b - a;
}

// --- security ----------------------------------------------------------------------------

struct AkmClasses {
    bool psk{false};
    bool sae{false};
    bool eap{false};
    bool eap_sha256{false};
    bool eap_192{false};
    bool owe{false};
    bool other{false};
};

AkmClasses classify(const std::vector<Suite>& akms) {
    AkmClasses c;
    for (const auto& a : akms) {
        if (a.oui == oui_ieee80211) {
            switch (a.type) {
            case 2:
            case 4:
            case 6:
            case 19:
            case 20:
                c.psk = true;
                break;
            case 8:
            case 9:
            case 24:
            case 25:
                c.sae = true;
                break;
            case 1:
            case 3:
            case 13:
            case 23:
                c.eap = true;
                break;
            case 5:
                c.eap = true;
                c.eap_sha256 = true;
                break;
            case 12:
                c.eap_192 = true;
                break;
            case 11:
                c.eap = true;
                break;
            case 18:
                c.owe = true;
                break;
            default:
                c.other = true;
                break;
            }
        } else if (a.oui == oui_microsoft) {
            (a.type == 2 ? c.psk : c.eap) = true;
        } else {
            c.other = true;
        }
    }
    return c;
}

bool is_weak(const Suite& s) {
    return (s.oui == oui_ieee80211 || s.oui == oui_microsoft) &&
           (s.type == 1 || s.type == 2 || s.type == 5);
}

SecuritySummary summarize_security(const DecodedIes& ies, const DecodeContext& context) {
    SecuritySummary sec;
    const auto* rsn = ies.first<Rsn>();
    const auto* wpa = ies.first<Wpa>();
    if (const auto* rsnx = ies.first<RsnExtension>()) {
        sec.sae_hash_to_element = rsnx->sae_hash_to_element();
        sec.sae_pk = rsnx->sae_pk();
    }
    sec.rsn = rsn != nullptr;
    sec.wpa1 = wpa != nullptr;

    if (rsn != nullptr) {
        sec.group_cipher = rsn->group_cipher;
        sec.pairwise_ciphers = rsn->pairwise_ciphers;
        sec.akms = rsn->akms;
        sec.group_management_cipher = rsn->group_management_cipher;
        sec.pmf = !rsn->capabilities    ? Pmf::disabled
                  : rsn->mfp_required() ? Pmf::required
                  : rsn->mfp_capable()  ? Pmf::capable
                                        : Pmf::disabled;
        // Defaults when the element is shortened (IEEE 802.11-2020: CCMP-128 and PSK/802.1X).
        if (!rsn->group_cipher) {
            sec.group_cipher = Suite{.oui = oui_ieee80211, .type = 4};
        }
        if (rsn->pairwise_ciphers.empty() && rsn->akms.empty()) {
            sec.pairwise_ciphers = {Suite{.oui = oui_ieee80211, .type = 4}};
            sec.akms = {Suite{.oui = oui_ieee80211, .type = 1}};
        }
    } else if (wpa != nullptr) {
        sec.group_cipher = wpa->group_cipher;
        sec.pairwise_ciphers = wpa->pairwise_ciphers;
        sec.akms = wpa->akms;
        sec.pmf = Pmf::disabled;
    }

    const auto rsn_classes = classify(sec.akms);
    const auto wpa_classes = wpa != nullptr ? classify(wpa->akms) : AkmClasses{};

    if (rsn != nullptr) {
        const auto& c = rsn_classes;
        if (c.owe && !c.psk && !c.sae && !c.eap && !c.eap_192) {
            sec.type = SecurityType::enhanced_open;
        } else if (c.psk || c.sae) {
            if (c.psk && c.sae) {
                sec.type = SecurityType::wpa2_wpa3_personal;
            } else if (c.sae) {
                sec.type = SecurityType::wpa3_personal;
            } else {
                sec.type =
                    wpa_classes.psk ? SecurityType::wpa_wpa2_personal : SecurityType::wpa2_personal;
            }
        } else if (c.eap_192) {
            sec.type = SecurityType::wpa3_enterprise_192;
        } else if (c.eap) {
            if (sec.pmf == Pmf::required) {
                sec.type = SecurityType::wpa3_enterprise;
            } else if (c.eap_sha256 && sec.pmf == Pmf::capable) {
                sec.type = SecurityType::wpa2_wpa3_enterprise;
            } else {
                sec.type = wpa_classes.eap ? SecurityType::wpa_wpa2_enterprise
                                           : SecurityType::wpa2_enterprise;
            }
        } else if (c.other) {
            sec.type = SecurityType::other;
        } else {
            sec.type = SecurityType::unknown;
        }
    } else if (wpa != nullptr) {
        sec.type = wpa_classes.eap ? SecurityType::wpa_enterprise : SecurityType::wpa_personal;
    } else if (ies.first<OweTransition>() != nullptr) {
        sec.type = SecurityType::enhanced_open_transition;
    } else if (context.privacy) {
        sec.type = *context.privacy ? SecurityType::wep : SecurityType::open;
    } else {
        sec.type = SecurityType::open_or_wep;
    }

    const bool weak_cipher =
        (sec.group_cipher && is_weak(*sec.group_cipher)) ||
        std::ranges::any_of(sec.pairwise_ciphers, [](const Suite& s) { return is_weak(s); });
    sec.weak = weak_cipher || sec.wpa1 || sec.type == SecurityType::open ||
               sec.type == SecurityType::open_or_wep || sec.type == SecurityType::wep;
    return sec;
}

// --- PHY ---------------------------------------------------------------------------------

void apply_width(PhySummary& phy, unsigned width, std::vector<std::uint32_t> centers,
                 bool eighty_plus_eighty = false) {
    if (centers.empty() || std::ranges::any_of(centers, [](std::uint32_t c) { return c == 0; })) {
        return;
    }
    phy.channel_width_mhz = static_cast<std::uint16_t>(width);
    phy.center_frequencies_mhz = std::move(centers);
    phy.eighty_plus_eighty = eighty_plus_eighty;
}

/// VHT-style segment interpretation (also used for the HE 6 GHz 160/80+80 case).
void apply_segments(PhySummary& phy, Band band, unsigned seg0, unsigned seg1, unsigned base_width) {
    const auto f0 = freq(band, seg0).value_or(0);
    const auto distance = seg1 == 0 ? 0 : channel_distance(seg0, seg1);
    if (distance == 8) {
        apply_width(phy, base_width * 2, {freq(band, seg1).value_or(0)});
    } else if (distance > 16) {
        apply_width(phy, base_width * 2, {f0, freq(band, seg1).value_or(0)}, true);
    } else {
        apply_width(phy, base_width, {f0});
    }
}

PhySummary summarize_phy(const DecodedIes& ies, const DecodeContext& context) {
    PhySummary phy;
    const auto* ds = ies.first<DsParameterSet>();
    const auto* ht = ies.first<HtCapabilities>();
    const auto* htop = ies.first<HtOperation>();
    const auto* vht = ies.first<VhtCapabilities>();
    const auto* vhtop = ies.first<VhtOperation>();
    const auto* he = ies.first<HeCapabilities>();
    const auto* heop = ies.first<HeOperation>();
    const auto* eht = ies.first<EhtCapabilities>();
    const auto* ehtop = ies.first<EhtOperation>();

    phy.generation = eht != nullptr   ? 7
                     : he != nullptr  ? 6
                     : vht != nullptr ? 5
                     : ht != nullptr  ? 4
                                      : 0;

    // Band and primary channel.
    if (context.frequency_mhz) {
        if (const auto ch = channel_from_frequency(*context.frequency_mhz)) {
            phy.band = ch->band;
            phy.primary_channel = ch->channel;
        }
        phy.primary_frequency_mhz = context.frequency_mhz;
    }
    if (phy.band == Band::unknown) {
        if (heop != nullptr && heop->six_ghz) {
            phy.band = Band::ghz_6;
            phy.primary_channel = heop->six_ghz->primary_channel;
        } else if (htop != nullptr) {
            phy.band = htop->primary_channel <= 14 ? Band::ghz_2_4 : Band::ghz_5;
            phy.primary_channel = htop->primary_channel;
        } else if (ds != nullptr) {
            phy.band = ds->channel <= 14 ? Band::ghz_2_4 : Band::ghz_5;
            phy.primary_channel = ds->channel;
        }
    }
    if (!phy.primary_channel) {
        if (heop != nullptr && heop->six_ghz && phy.band == Band::ghz_6) {
            phy.primary_channel = heop->six_ghz->primary_channel;
        } else if (htop != nullptr) {
            phy.primary_channel = htop->primary_channel;
        } else if (ds != nullptr) {
            phy.primary_channel = ds->channel;
        }
    }
    if (!phy.primary_frequency_mhz && phy.primary_channel) {
        phy.primary_frequency_mhz = freq(phy.band, *phy.primary_channel);
    }

    // Operating width, widest description wins (EHT > HE 6 GHz > VHT > HT).
    if (phy.primary_frequency_mhz) {
        phy.center_frequencies_mhz = {*phy.primary_frequency_mhz};
    }
    if (htop != nullptr && htop->any_channel_width && phy.primary_frequency_mhz) {
        if (htop->secondary_channel_offset == 1) {
            apply_width(phy, 40, {*phy.primary_frequency_mhz + 10});
        } else if (htop->secondary_channel_offset == 3) {
            apply_width(phy, 40, {*phy.primary_frequency_mhz - 10});
        }
    }
    const VhtOperation* vht_info = vhtop;
    if (vht_info == nullptr && heop != nullptr && heop->vht_operation) {
        vht_info = &*heop->vht_operation;
    }
    if (vht_info != nullptr && phy.band != Band::ghz_6) {
        const auto band = phy.band == Band::unknown ? Band::ghz_5 : phy.band;
        unsigned seg1 = vht_info->ccfs1;
        if (seg1 == 0 && htop != nullptr && htop->ccfs2 != 0) {
            seg1 = htop->ccfs2; // Extended NSS BW signalling
        }
        switch (vht_info->channel_width) {
        case 1:
            apply_segments(phy, band, vht_info->ccfs0, seg1, 80);
            break;
        case 2:
            apply_width(phy, 160, {freq(band, vht_info->ccfs0).value_or(0)});
            break;
        case 3:
            apply_width(phy, 160,
                        {freq(band, vht_info->ccfs0).value_or(0), freq(band, seg1).value_or(0)},
                        true);
            break;
        default:
            break;
        }
    }
    if (heop != nullptr && heop->six_ghz) {
        const auto& six = *heop->six_ghz;
        switch (six.channel_width) {
        case 0:
        case 1:
        case 2:
            apply_width(phy, 20U << six.channel_width, {freq(Band::ghz_6, six.ccfs0).value_or(0)});
            break;
        case 3:
            apply_segments(phy, Band::ghz_6, six.ccfs0, six.ccfs1, 80);
            break;
        default:
            break;
        }
    }
    if (ehtop != nullptr && ehtop->info && phy.band != Band::unknown) {
        const auto& info = *ehtop->info;
        const unsigned width = 20U << std::min<unsigned>(info.channel_width, 4);
        if (width >= phy.channel_width_mhz) {
            const unsigned center = info.channel_width >= 3 ? info.ccfs1 : info.ccfs0;
            apply_width(phy, width, {freq(phy.band, center).value_or(0)});
            phy.eighty_plus_eighty = false;
        }
        phy.punctured_subchannels = info.disabled_subchannels;
    }

    // Standards.
    std::set<PhyStandard> standards;
    double legacy = 0;
    for (const auto* rates : ies.all<SupportedRates>()) {
        for (const auto& r : rates->rates) {
            legacy = std::max(legacy, r.units_500kbps / 2.0);
            const bool dsss = r.units_500kbps == 2 || r.units_500kbps == 4 ||
                              r.units_500kbps == 11 || r.units_500kbps == 22;
            if (phy.band == Band::ghz_2_4) {
                standards.insert(dsss ? PhyStandard::b : PhyStandard::g);
            } else if (phy.band == Band::ghz_5) {
                standards.insert(PhyStandard::a);
            }
        }
    }
    if (legacy > 0) {
        phy.max_legacy_rate_mbps = legacy;
    }
    if (ht != nullptr) {
        standards.insert(PhyStandard::n);
    }
    if (vht != nullptr) {
        standards.insert(PhyStandard::ac);
    }
    if (he != nullptr) {
        standards.insert(PhyStandard::ax);
    }
    if (eht != nullptr) {
        standards.insert(PhyStandard::be);
    }
    phy.standards.assign(standards.begin(), standards.end());

    // Rates and spatial streams.
    const unsigned width = phy.eighty_plus_eighty ? 160 : phy.channel_width_mhz;
    double best = 0;
    std::uint8_t nss = 0;
    if (ht != nullptr) {
        const unsigned w = (width >= 40 && ht->supports_40mhz()) ? 40 : 20;
        const auto streams = ht->rx_spatial_streams();
        nss = std::max(nss, streams);
        if (streams > 0) {
            const bool sgi = w == 40 ? ht->short_gi_40() : ht->short_gi_20();
            best = std::max(best, phy_rate_mbps(4, w, 7, streams, sgi).value_or(0));
        }
    }
    if (vht != nullptr && width >= 20) {
        const unsigned w = std::min(width, 160U);
        const bool sgi = w >= 160 ? vht->short_gi_160()
                         : w == 80
                             ? vht->short_gi_80()
                             : ht != nullptr && (w == 40 ? ht->short_gi_40() : ht->short_gi_20());
        best = std::max(best, best_rate_from_map(5, w, vht->rx_mcs_map, sgi, nss));
    }
    if (he != nullptr) {
        const unsigned w = std::min(width, 160U);
        std::uint16_t map = he->rx_mcs_80;
        if (w == 160 && he->rx_mcs_160) {
            map = *he->rx_mcs_160;
        }
        best = std::max(best, best_rate_from_map(6, w, map, false, nss));
    }
    if (eht != nullptr) {
        const std::optional<EhtMcsMap>* map = &eht->mcs_80;
        if (width == 320 && eht->mcs_320) {
            map = &eht->mcs_320;
        } else if (width >= 160 && eht->mcs_160) {
            map = &eht->mcs_160;
        }
        if (*map) {
            constexpr std::array<unsigned, 3> group_mcs{9, 11, 13};
            for (unsigned g = 0; g < 3; ++g) {
                const unsigned streams = (**map).rx_max_nss[g];
                if (streams > 0) {
                    nss = std::max(nss, static_cast<std::uint8_t>(streams));
                    best = std::max(
                        best, phy_rate_mbps(7, width, group_mcs[g], streams, false).value_or(0));
                }
            }
        }
    }
    phy.max_spatial_streams = nss;
    if (best > 0) {
        phy.max_rate_mbps = best;
    } else if (legacy > 0) {
        phy.max_rate_mbps = legacy;
    }
    return phy;
}

} // namespace

std::optional<double> phy_rate_mbps(int phy, unsigned width_mhz, unsigned mcs, unsigned nss,
                                    bool short_gi) noexcept {
    const unsigned max_mcs = phy == 4 ? 7 : phy == 5 ? 9 : phy == 6 ? 11 : phy == 7 ? 13 : 0;
    if (phy < 4 || phy > 7 || mcs > max_mcs || nss == 0 || nss > (phy == 4 ? 4U : 8U)) {
        return std::nullopt;
    }
    const auto nsd = data_subcarriers(phy, width_mhz);
    if (!nsd) {
        return std::nullopt;
    }
    // VHT MCS 9 is not valid at 20 MHz except for 3 and 6 spatial streams.
    if (phy == 5 && width_mhz == 20 && mcs == 9 && nss != 3 && nss != 6) {
        return std::nullopt;
    }
    const double symbol_us = phy >= 6 ? 13.6 : (short_gi ? 3.6 : 4.0);
    const auto& m = mcs_table[mcs];
    const double rate = nss * (*nsd) * m.bits * m.rate / symbol_us;
    return std::round(rate * 10.0) / 10.0;
}

std::uint8_t HtCapabilities::rx_spatial_streams() const noexcept {
    std::uint8_t streams = 0;
    for (std::uint8_t i = 0; i < 4; ++i) {
        if (mcs_set[i] == 0xff) {
            streams = static_cast<std::uint8_t>(i + 1);
        }
    }
    return streams;
}

BssSummary summarize(const DecodedIes& ies, const DecodeContext& context) {
    BssSummary s;
    if (const auto* ssid = ies.first<Ssid>()) {
        s.ssid_present = true;
        s.ssid_raw = ssid->bytes;
        s.hidden = ssid->hidden;
        s.ssid = core::display_text(ssid->bytes);
    }
    s.security = summarize_security(ies, context);
    s.phy = summarize_phy(ies, context);

    if (const auto* load = ies.first<BssLoad>()) {
        s.bss_load = *load;
    }
    if (const auto* country = ies.first<Country>()) {
        s.country = country->code;
        s.country_environment = country->environment;
    }
    if (const auto* rm = ies.first<RmEnabledCapabilities>()) {
        s.roaming.k = rm->neighbor_report();
    }
    const auto* ext = ies.first<ExtendedCapabilities>();
    if (ext != nullptr) {
        s.roaming.v = ext->bss_transition();
        s.twt_responder = ext->twt_responder();
    }
    if (const auto* md = ies.first<MobilityDomain>()) {
        s.roaming.r = true;
        s.roaming.ft_over_ds = md->ft_over_ds;
    }
    if (const auto* wmm = ies.first<Wmm>()) {
        s.wmm = true;
        s.uapsd = wmm->uapsd();
    }
    if (const auto* he = ies.first<HeCapabilities>()) {
        s.twt_responder = s.twt_responder || he->mac_bit(2);
    }
    if (const auto* heop = ies.first<HeOperation>(); heop != nullptr && !heop->bss_color_disabled) {
        s.bss_color = heop->bss_color;
    }
    for (const auto* ml : ies.all<MultiLink>()) {
        if (ml->type == 0) {
            s.mlo = MloSummary{.mld_mac = ml->mld_mac,
                               .link_id = ml->link_id,
                               .max_simultaneous_links = ml->max_simultaneous_links,
                               .reported_links = ml->per_sta.size()};
            break;
        }
    }
    for (const auto* rnr : ies.all<ReducedNeighborReport>()) {
        for (const auto& n : rnr->neighbors) {
            for (const auto& t : n.tbtt) {
                s.neighbors.push_back(
                    NeighborSummary{.operating_class = n.operating_class,
                                    .channel = n.channel,
                                    .band = band_from_operating_class(n.operating_class),
                                    .bssid = t.bssid,
                                    .same_ssid = t.same_ssid(),
                                    .co_located = t.co_located()});
            }
        }
    }
    for (const auto* mbssid : ies.all<MultipleBssid>()) {
        s.nontransmitted_bssids += mbssid->nontransmitted_profiles;
    }
    if (const auto* wps = ies.first<Wps>()) {
        s.device = DeviceInfo{.manufacturer = wps->manufacturer,
                              .model_name = wps->model_name,
                              .model_number = wps->model_number,
                              .device_name = wps->device_name,
                              .serial_number = wps->serial_number};
    }
    if (const auto* iw = ies.first<Interworking>()) {
        s.access_network_type = iw->access_network_type;
        s.internet = iw->internet;
    }
    if (const auto* hs = ies.first<Hs20Indication>()) {
        s.hotspot20_release = static_cast<std::uint8_t>(hs->release + 1);
    }

    std::set<std::uint32_t> seen;
    for (const auto& e : ies.elements) {
        if (e.key.oui && seen.insert(core::oui_value(*e.key.oui)).second) {
            const auto name = oui_name(*e.key.oui, context.oui_database);
            s.vendors.push_back(
                VendorTag{.oui = *e.key.oui, .name = std::string{name.value_or("")}});
        }
        if (e.status == DecodeStatus::malformed || e.status == DecodeStatus::truncated) {
            ++s.problem_count;
        }
    }
    s.element_count = ies.elements.size();
    s.problem_count += ies.diagnostics.size();
    return s;
}

Text security_type_name(SecurityType type) noexcept {
    switch (type) {
    case SecurityType::unknown:
        return msg::unknown;
    case SecurityType::open:
        return WA_TR(sec_open, "Open");
    case SecurityType::open_or_wep:
        return WA_TR(sec_open_or_wep, "Open or WEP");
    case SecurityType::wep:
        return "WEP";
    case SecurityType::enhanced_open:
        return WA_TR(sec_enhanced_open, "Enhanced Open (OWE)");
    case SecurityType::enhanced_open_transition:
        return WA_TR(sec_enhanced_open_transition, "Open (OWE transition)");
    case SecurityType::wpa_personal:
        return WA_TR(sec_wpa_personal, "WPA-Personal");
    case SecurityType::wpa_enterprise:
        return WA_TR(sec_wpa_enterprise, "WPA-Enterprise");
    case SecurityType::wpa_wpa2_personal:
        return WA_TR(sec_wpa_wpa2_personal, "WPA/WPA2-Personal");
    case SecurityType::wpa_wpa2_enterprise:
        return WA_TR(sec_wpa_wpa2_enterprise, "WPA/WPA2-Enterprise");
    case SecurityType::wpa2_personal:
        return WA_TR(sec_wpa2_personal, "WPA2-Personal");
    case SecurityType::wpa2_wpa3_personal:
        return WA_TR(sec_wpa2_wpa3_personal, "WPA2/WPA3-Personal");
    case SecurityType::wpa3_personal:
        return WA_TR(sec_wpa3_personal, "WPA3-Personal");
    case SecurityType::wpa2_enterprise:
        return WA_TR(sec_wpa2_enterprise, "WPA2-Enterprise");
    case SecurityType::wpa2_wpa3_enterprise:
        return WA_TR(sec_wpa2_wpa3_enterprise, "WPA2/WPA3-Enterprise");
    case SecurityType::wpa3_enterprise:
        return WA_TR(sec_wpa3_enterprise, "WPA3-Enterprise");
    case SecurityType::wpa3_enterprise_192:
        return WA_TR(sec_wpa3_enterprise_192, "WPA3-Enterprise 192-bit");
    case SecurityType::other:
        return WA_TR(sec_other, "Other");
    }
    return msg::unknown;
}

std::string_view security_type_key(SecurityType type) noexcept {
    switch (type) {
    case SecurityType::unknown:
        return "unknown";
    case SecurityType::open:
        return "open";
    case SecurityType::open_or_wep:
        return "open_or_wep";
    case SecurityType::wep:
        return "wep";
    case SecurityType::enhanced_open:
        return "enhanced_open";
    case SecurityType::enhanced_open_transition:
        return "enhanced_open_transition";
    case SecurityType::wpa_personal:
        return "wpa_personal";
    case SecurityType::wpa_enterprise:
        return "wpa_enterprise";
    case SecurityType::wpa_wpa2_personal:
        return "wpa_wpa2_personal";
    case SecurityType::wpa_wpa2_enterprise:
        return "wpa_wpa2_enterprise";
    case SecurityType::wpa2_personal:
        return "wpa2_personal";
    case SecurityType::wpa2_wpa3_personal:
        return "wpa2_wpa3_personal";
    case SecurityType::wpa3_personal:
        return "wpa3_personal";
    case SecurityType::wpa2_enterprise:
        return "wpa2_enterprise";
    case SecurityType::wpa2_wpa3_enterprise:
        return "wpa2_wpa3_enterprise";
    case SecurityType::wpa3_enterprise:
        return "wpa3_enterprise";
    case SecurityType::wpa3_enterprise_192:
        return "wpa3_enterprise_192";
    case SecurityType::other:
        return "other";
    }
    return "unknown";
}

Text pmf_name(Pmf pmf) noexcept {
    switch (pmf) {
    case Pmf::unknown:
        return msg::unknown;
    case Pmf::disabled:
        return WA_TR(pmf_disabled, "Disabled");
    case Pmf::capable:
        return WA_TR(pmf_capable, "Capable");
    case Pmf::required:
        return WA_TR(pmf_required, "Required");
    }
    return msg::unknown;
}

std::string_view phy_standard_name(PhyStandard standard) noexcept {
    switch (standard) {
    case PhyStandard::b:
        return "802.11b";
    case PhyStandard::a:
        return "802.11a";
    case PhyStandard::g:
        return "802.11g";
    case PhyStandard::n:
        return "802.11n";
    case PhyStandard::ac:
        return "802.11ac";
    case PhyStandard::ax:
        return "802.11ax";
    case PhyStandard::be:
        return "802.11be";
    }
    return {};
}

std::string generation_name(const PhySummary& phy) {
    switch (phy.generation) {
    case 7:
        return "Wi-Fi 7";
    case 6:
        return phy.band == Band::ghz_6 ? "Wi-Fi 6E" : "Wi-Fi 6";
    case 5:
        return "Wi-Fi 5";
    case 4:
        return "Wi-Fi 4";
    default:
        break;
    }
    std::string legacy = "802.11";
    bool first = true;
    for (const auto s : phy.standards) {
        if (s == PhyStandard::a || s == PhyStandard::b || s == PhyStandard::g) {
            if (!first) {
                legacy += '/';
            }
            legacy += phy_standard_name(s).substr(6);
            first = false;
        }
    }
    return first ? std::string{"Legacy"} : legacy;
}

TreeNode describe(const BssSummary& s) {
    using core::Decoder;
    TreeNode root = Decoder::node(WA_TR(summary_title, "Summary"));
    const auto add = [&root](TreeNode n) -> TreeNode& {
        return root.children.emplace_back(std::move(n));
    };

    if (s.ssid_present) {
        add(Decoder::node(WA_TR(ssid_name, "SSID"), s.ssid));
        if (s.hidden) {
            add(Decoder::node(WA_TR(ssid_hidden, "Hidden SSID"), true));
        }
    }

    auto security = Decoder::node(WA_TR(summary_security, "Security"),
                                  EnumValue{.raw = static_cast<std::uint64_t>(s.security.type),
                                            .name = security_type_name(s.security.type)});
    security.display = Display::name_only;
    if (s.security.weak) {
        security.significance = Significance::warning;
    }
    if (s.security.rsn || s.security.wpa1) {
        security.children.push_back(
            Decoder::node(WA_TR(summary_pmf, "Management Frame Protection"),
                          EnumValue{.raw = static_cast<std::uint64_t>(s.security.pmf),
                                    .name = pmf_name(s.security.pmf)}));
        security.children.back().display = Display::name_only;
        const auto list = [&](MessageId label, const std::vector<Suite>& suites, bool akm) {
            auto n = Decoder::node(label);
            for (const auto& suite : suites) {
                n.children.push_back(Decoder::node(
                    msg::item,
                    EnumValue{.raw = (std::uint64_t{core::oui_value(suite.oui)} << 8U) | suite.type,
                              .name =
                                  akm ? ie::akm_suite_name(suite) : ie::cipher_suite_name(suite)}));
                n.children.back().display = Display::suite;
            }
            security.children.push_back(std::move(n));
        };
        list(WA_TR(summary_akms, "Authentication"), s.security.akms, true);
        list(WA_TR(summary_pairwise, "Pairwise Ciphers"), s.security.pairwise_ciphers, false);
        if (s.security.group_cipher) {
            list(WA_TR(summary_group_cipher, "Group Cipher"), {*s.security.group_cipher}, false);
        }
        if (s.security.group_management_cipher) {
            list(WA_TR(summary_group_mgmt_cipher, "Group Management Cipher"),
                 {*s.security.group_management_cipher}, false);
        }
        if (s.security.sae_hash_to_element) {
            security.children.push_back(
                Decoder::node(WA_TR(rsnx_sae_h2e, "SAE Hash-to-Element"), true));
        }
        if (s.security.sae_pk) {
            security.children.push_back(Decoder::node(WA_TR(rsnx_sae_pk, "SAE-PK"), true));
        }
    }
    add(std::move(security));

    auto phy = Decoder::node(WA_TR(summary_phy, "PHY"), generation_name(s.phy));
    if (!s.phy.standards.empty()) {
        std::string standards;
        for (const auto st : s.phy.standards) {
            standards += (standards.empty() ? "" : ", ") + std::string{phy_standard_name(st)};
        }
        phy.children.push_back(Decoder::node(WA_TR(summary_standards, "Standards"), standards));
    }
    if (s.phy.band != Band::unknown) {
        phy.children.push_back(
            Decoder::node(WA_TR(summary_band, "Band"), std::string{band_name(s.phy.band)}));
    }
    if (s.phy.primary_channel) {
        phy.children.push_back(Decoder::node(WA_TR(summary_primary_channel, "Primary Channel"),
                                             std::uint64_t{*s.phy.primary_channel}));
    }
    if (s.phy.primary_frequency_mhz) {
        phy.children.push_back(Decoder::node(WA_TR(summary_frequency, "Frequency"),
                                             std::uint64_t{*s.phy.primary_frequency_mhz},
                                             std::nullopt, Unit::mhz));
    }
    phy.children.push_back(Decoder::node(WA_TR(summary_channel_width, "Channel Width"),
                                         s.phy.eighty_plus_eighty
                                             ? std::string{"80+80 MHz"}
                                             : std::to_string(s.phy.channel_width_mhz) + " MHz"));
    for (const auto c : s.phy.center_frequencies_mhz) {
        phy.children.push_back(Decoder::node(WA_TR(summary_center_frequency, "Center Frequency"),
                                             std::uint64_t{c}, std::nullopt, Unit::mhz));
    }
    if (s.phy.punctured_subchannels && *s.phy.punctured_subchannels != 0) {
        auto n = Decoder::node(WA_TR(summary_punctured, "Punctured Subchannels"),
                               std::uint64_t{*s.phy.punctured_subchannels});
        n.display = Display::hex;
        phy.children.push_back(std::move(n));
    }
    if (s.phy.max_spatial_streams > 0) {
        phy.children.push_back(Decoder::node(WA_TR(summary_nss, "Spatial Streams"),
                                             std::uint64_t{s.phy.max_spatial_streams}));
    }
    if (s.phy.max_rate_mbps) {
        phy.children.push_back(Decoder::node(WA_TR(summary_max_rate, "Max PHY Rate (estimate)"),
                                             *s.phy.max_rate_mbps, std::nullopt, Unit::mbps));
    }
    add(std::move(phy));

    if (s.bss_load) {
        auto load = Decoder::node(WA_TR(summary_load, "Load"));
        load.children.push_back(Decoder::node(WA_TR(bss_load_stations, "Station Count"),
                                              std::uint64_t{s.bss_load->station_count}));
        load.children.push_back(Decoder::node(WA_TR(bss_load_utilization, "Channel Utilization"),
                                              s.bss_load->channel_utilization * 100.0 / 255.0,
                                              std::nullopt, Unit::percent));
        add(std::move(load));
    }
    if (!s.country.empty()) {
        add(Decoder::node(WA_TR(country_code, "Country Code"), s.country));
    }

    auto features = Decoder::node(WA_TR(summary_features, "Features"));
    features.children.push_back(
        Decoder::node(WA_TR(summary_11k, "802.11k (Radio Measurement)"), s.roaming.k));
    features.children.push_back(
        Decoder::node(WA_TR(summary_11v, "802.11v (BSS Transition)"), s.roaming.v));
    features.children.push_back(
        Decoder::node(WA_TR(summary_11r, "802.11r (Fast Transition)"), s.roaming.r));
    if (s.roaming.r) {
        features.children.push_back(
            Decoder::node(WA_TR(mobility_domain_ft_over_ds, "Fast BSS Transition over DS"),
                          s.roaming.ft_over_ds));
    }
    features.children.push_back(Decoder::node(WA_TR(element_wmm, "WMM"), s.wmm));
    if (s.wmm) {
        features.children.push_back(Decoder::node(WA_TR(wmm_uapsd, "U-APSD"), s.uapsd));
    }
    features.children.push_back(
        Decoder::node(WA_TR(summary_twt, "Target Wake Time"), s.twt_responder));
    if (s.bss_color) {
        features.children.push_back(
            Decoder::node(WA_TR(he_bss_color, "BSS Color"), std::uint64_t{*s.bss_color}));
    }
    add(std::move(features));

    if (s.mlo) {
        auto mlo = Decoder::node(WA_TR(summary_mlo, "Multi-Link Operation"));
        if (s.mlo->mld_mac) {
            mlo.children.push_back(Decoder::node(WA_TR(ml_mld_mac, "MLD MAC Address"),
                                                 core::format_mac(*s.mlo->mld_mac)));
        }
        if (s.mlo->link_id) {
            mlo.children.push_back(
                Decoder::node(WA_TR(mlo_link_id, "Link ID"), std::uint64_t{*s.mlo->link_id}));
        }
        if (s.mlo->max_simultaneous_links) {
            mlo.children.push_back(
                Decoder::node(WA_TR(ml_max_links, "Maximum Number of Simultaneous Links"),
                              std::uint64_t{*s.mlo->max_simultaneous_links} + 1));
        }
        add(std::move(mlo));
    }
    if (!s.neighbors.empty()) {
        auto n = Decoder::node(WA_TR(summary_neighbors, "Reported Neighbor APs"),
                               std::uint64_t{s.neighbors.size()});
        for (const auto& nb : s.neighbors) {
            std::string text =
                std::string{band_name(nb.band)} + " ch " + std::to_string(nb.channel);
            if (nb.bssid) {
                text += " " + core::format_mac(*nb.bssid);
            }
            auto item = Decoder::node(msg::item, text);
            if (nb.same_ssid) {
                item.children.push_back(Decoder::node(WA_TR(rnr_same_ssid, "Same SSID"), true));
            }
            if (nb.co_located) {
                item.children.push_back(
                    Decoder::node(WA_TR(rnr_co_located, "Co-Located AP"), true));
            }
            n.children.push_back(std::move(item));
        }
        add(std::move(n));
    }
    if (s.nontransmitted_bssids > 0) {
        add(Decoder::node(WA_TR(summary_nontransmitted, "Nontransmitted BSSIDs"),
                          std::uint64_t{s.nontransmitted_bssids}));
    }
    if (!s.device.empty()) {
        auto dev = Decoder::node(WA_TR(summary_device, "Device"));
        const auto field = [&dev](MessageId label, const std::string& v) {
            if (!v.empty()) {
                dev.children.push_back(Decoder::node(label, v));
            }
        };
        field(WA_TR(wps_manufacturer, "Manufacturer"), s.device.manufacturer);
        field(WA_TR(wps_model_name, "Model Name"), s.device.model_name);
        field(WA_TR(wps_model_number, "Model Number"), s.device.model_number);
        field(WA_TR(wps_device_name, "Device Name"), s.device.device_name);
        field(WA_TR(wps_serial_number, "Serial Number"), s.device.serial_number);
        add(std::move(dev));
    }
    if (s.access_network_type || s.hotspot20_release) {
        auto iw = Decoder::node(WA_TR(summary_interworking, "Interworking / Passpoint"));
        if (s.access_network_type) {
            iw.children.push_back(Decoder::node(
                WA_TR(interworking_access_network_type, "Access Network Type"),
                EnumValue{.raw = *s.access_network_type,
                          .name = ie::access_network_type_name(*s.access_network_type)}));
            iw.children.back().display = Display::name_only;
        }
        if (s.internet) {
            iw.children.push_back(
                Decoder::node(WA_TR(interworking_internet, "Internet"), *s.internet));
        }
        if (s.hotspot20_release) {
            iw.children.push_back(Decoder::node(WA_TR(summary_hs20_release, "Hotspot 2.0 Release"),
                                                std::uint64_t{*s.hotspot20_release}));
        }
        add(std::move(iw));
    }
    if (!s.vendors.empty()) {
        auto v = Decoder::node(WA_TR(summary_vendors, "Vendor Elements"));
        for (const auto& tag : s.vendors) {
            v.children.push_back(
                Decoder::node(msg::item, core::format_oui(tag.oui) +
                                             (tag.name.empty() ? "" : " (" + tag.name + ")")));
        }
        add(std::move(v));
    }
    return root;
}

} // namespace wifi_analyze
