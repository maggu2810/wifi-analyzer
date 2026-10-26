// SPDX-License-Identifier: MIT
// RSN element (48) and RSN Extension element (244). Reference: IEEE Std 802.11-2020, RSNE
// (cipher suite selectors Table 9-149, AKM suite selectors Table 9-151) and RSNXE; AKM 24/25
// (SAE-EXT-KEY) from IEEE Std 802.11-2024; WFA vendor AKMs (OSEN, DPP).
// Cross-checked with Wireshark 4.6.9 packet-ieee80211.c; the dissector per element is listed in
// docs/decoder-sources.md.

#include <array>
#include <string>

#include "ie/decoders.hpp"

namespace wifi_analyze::ie {
namespace {

using core::table_name;

constexpr std::array<Text, 14> ieee_ciphers{
    WA_TR(cipher_use_group, "Use group cipher"),
    "WEP-40",
    "TKIP",
    Text{},
    "CCMP-128",
    "WEP-104",
    "BIP-CMAC-128",
    WA_TR(cipher_group_not_allowed, "Group addressed traffic not allowed"),
    "GCMP-128",
    "GCMP-256",
    "CCMP-256",
    "BIP-GMAC-128",
    "BIP-GMAC-256",
    "BIP-CMAC-256",
};

constexpr std::array<Text, 6> microsoft_ciphers{msg::none, "WEP-40",   "TKIP",
                                                Text{},    "CCMP-128", "WEP-104"};

constexpr std::array<Text, 26> ieee_akms{
    Text{},
    "802.1X",
    "PSK",
    "FT-802.1X",
    "FT-PSK",
    "802.1X-SHA-256",
    "PSK-SHA-256",
    "TDLS",
    "SAE",
    "FT-SAE",
    "APPeerKey",
    "802.1X Suite B",
    "802.1X Suite B 192",
    "FT-802.1X-SHA-384",
    "FILS-SHA-256",
    "FILS-SHA-384",
    "FT-FILS-SHA-256",
    "FT-FILS-SHA-384",
    "OWE",
    "FT-PSK-SHA-384",
    "PSK-SHA-384",
    "PASN",
    Text{},
    "802.1X-SHA-384",
    "SAE-EXT-KEY",
    "FT-SAE-EXT-KEY",
};

bool is_weak_cipher(const Suite& s) {
    const bool ieee = s.oui == oui_ieee80211 || s.oui == oui_microsoft;
    return ieee && (s.type == 1 || s.type == 2 || s.type == 5);
}

Text unknown_vendor_suite() {
    return WA_TR(suite_vendor_specific, "Vendor specific");
}

} // namespace

Text cipher_suite_name(const Suite& suite) {
    if (suite.oui == oui_ieee80211) {
        return table_name(ieee_ciphers, suite.type);
    }
    if (suite.oui == oui_microsoft) {
        return table_name(microsoft_ciphers, suite.type);
    }
    return unknown_vendor_suite();
}

Text akm_suite_name(const Suite& suite) {
    if (suite.oui == oui_ieee80211) {
        return table_name(ieee_akms, suite.type);
    }
    if (suite.oui == oui_microsoft) {
        constexpr std::array<Text, 3> names{Text{}, "802.1X", "PSK"};
        return table_name(names, suite.type);
    }
    if (suite.oui == oui_wfa) {
        switch (suite.type) {
        case 1:
            return "OSEN";
        case 2:
            return "DPP";
        default:
            break;
        }
    }
    return unknown_vendor_suite();
}

std::optional<Suite> read_suite(Decoder& d, TreeNode& parent, MessageId label, bool akm) {
    const auto start = d.offset();
    const auto oui = d.reader().array<3>();
    const auto type = d.reader().u8();
    if (!oui || !type) {
        d.malformed();
        return std::nullopt;
    }
    const Suite suite{.oui = *oui, .type = *type};
    const std::uint64_t raw = (std::uint64_t{core::oui_value(suite.oui)} << 8U) | suite.type;
    auto n = Decoder::node(
        label,
        EnumValue{.raw = raw, .name = akm ? akm_suite_name(suite) : cipher_suite_name(suite)},
        d.range_from(start));
    n.display = Display::suite;
    if (!akm && is_weak_cipher(suite)) {
        d.warn_node(n, Severity::warning,
                    WA_TR(rsn_weak_cipher, "Insecure cipher in use (WEP or TKIP)"));
    }
    parent.children.push_back(std::move(n));
    return suite;
}

std::vector<Suite> read_suite_list(Decoder& d, MessageId label, bool akm) {
    std::vector<Suite> suites;
    const auto start = d.offset();
    auto group = d.group(label);
    const auto count = d.u16(group, msg::count);
    for (std::uint16_t i = 0; count && i < *count; ++i) {
        const auto s = read_suite(
            d, group,
            akm ? WA_TR(rsn_akm, "AKM Suite") : WA_TR(rsn_pairwise, "Pairwise Cipher Suite"), akm);
        if (!s) {
            break;
        }
        suites.push_back(*s);
    }
    d.close(group, start);
    d.add(std::move(group));
    return suites;
}

ElementValue decode_rsn(Decoder& d) {
    Rsn rsn;
    const auto version = d.u16(d.root(), msg::version);
    if (!version) {
        return {};
    }
    rsn.version = *version;
    if (d.reader().empty()) {
        return rsn;
    }
    rsn.group_cipher =
        read_suite(d, d.root(), WA_TR(rsn_group_cipher, "Group Data Cipher Suite"), false);
    if (!rsn.group_cipher || d.reader().empty()) {
        return rsn;
    }
    rsn.pairwise_ciphers =
        read_suite_list(d, WA_TR(rsn_pairwise_list, "Pairwise Cipher Suites"), false);
    if (d.is_malformed() || d.reader().empty()) {
        return rsn;
    }
    rsn.akms = read_suite_list(d, WA_TR(rsn_akm_list, "AKM Suites"), true);
    if (d.is_malformed() || d.reader().empty()) {
        return rsn;
    }

    auto caps = d.bits(WA_TR(rsn_capabilities, "RSN Capabilities"), 2);
    if (!caps) {
        return rsn;
    }
    rsn.capabilities = static_cast<std::uint16_t>(caps->get(0, 16));
    caps->flag(0, WA_TR(rsn_preauth, "Preauthentication"));
    caps->flag(1, WA_TR(rsn_no_pairwise, "No Pairwise"));
    const auto replay_name = [](std::uint64_t v) -> Text {
        constexpr std::array<Text, 4> names{"1", "2", "4", "16"};
        return core::table_name(names, v);
    };
    caps->enumeration(2, 2, WA_TR(rsn_ptksa_replay, "PTKSA Replay Counter"), replay_name);
    caps->enumeration(4, 2, WA_TR(rsn_gtksa_replay, "GTKSA Replay Counter"), replay_name);
    caps->flag(6, WA_TR(rsn_mfpr, "Management Frame Protection Required"));
    caps->flag(7, WA_TR(rsn_mfpc, "Management Frame Protection Capable"));
    caps->flag(8, WA_TR(rsn_joint_multiband, "Joint Multi-band RSNA"));
    caps->flag(9, WA_TR(rsn_peerkey, "PeerKey Enabled"));
    caps->flag(10, WA_TR(rsn_spp_amsdu_capable, "SPP A-MSDU Capable"));
    caps->flag(11, WA_TR(rsn_spp_amsdu_required, "SPP A-MSDU Required"));
    caps->flag(12, WA_TR(rsn_pbac, "PBAC"));
    caps->flag(13, WA_TR(rsn_extended_key_id, "Extended Key ID for Individually Addressed Frames"));
    caps->flag(14, WA_TR(rsn_ocvc, "OCVC (Operating Channel Validation)"));
    d.add(caps->take());
    if (rsn.mfp_required() && !rsn.mfp_capable()) {
        d.diagnostic(Severity::warning,
                     WA_TR(rsn_mfpr_without_mfpc, "MFP required but not capable (invalid)"));
    }
    if (d.reader().empty()) {
        return rsn;
    }

    const auto pmkid_start = d.offset();
    auto pmkids = d.group(WA_TR(rsn_pmkid_list, "PMKIDs"));
    const auto count = d.u16(pmkids, msg::count);
    for (std::uint16_t i = 0; count && i < *count; ++i) {
        if (!d.bytes(pmkids, WA_TR(rsn_pmkid, "PMKID"), 16)) {
            break;
        }
        ++rsn.pmkid_count;
    }
    d.close(pmkids, pmkid_start);
    d.add(std::move(pmkids));
    if (d.is_malformed() || d.reader().empty()) {
        return rsn;
    }
    rsn.group_management_cipher = read_suite(
        d, d.root(), WA_TR(rsn_group_mgmt_cipher, "Group Management Cipher Suite"), false);
    return rsn;
}

ElementValue decode_rsn_extension(Decoder& d) {
    RsnExtension rsnx;
    const auto size = d.remaining();
    auto caps = d.bits(WA_TR(rsnx_capabilities, "Extended RSN Capabilities"), size == 0 ? 1 : size);
    if (!caps) {
        return {};
    }
    rsnx.bytes = caps->data();
    caps->number(0, 4, WA_TR(rsnx_field_length, "Field Length"), Unit::none, 1);
    caps->flag(4, WA_TR(rsnx_protected_twt, "Protected TWT Operations Support"));
    caps->flag(5, WA_TR(rsnx_sae_h2e, "SAE Hash-to-Element"));
    caps->flag(6, WA_TR(rsnx_sae_pk, "SAE-PK"));
    if (size >= 2) {
        caps->flag(8, WA_TR(rsnx_secure_ltf, "Secure LTF Support"));
        caps->flag(9, WA_TR(rsnx_secure_rtt, "Secure RTT Support"));
    }
    d.add(caps->take());
    return rsnx;
}

} // namespace wifi_analyze::ie
