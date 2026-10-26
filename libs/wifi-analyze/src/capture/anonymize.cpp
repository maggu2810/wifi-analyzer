// SPDX-License-Identifier: MIT
#include <algorithm>
#include <format>
#include <optional>

#include <wifi_analyze/capture.hpp>
#include <wifi_analyze/tlv.hpp>

namespace wifi_analyze {
namespace {

constexpr std::uint8_t id_ssid = 0;
constexpr std::uint8_t id_multiple_bssid = 71;
constexpr std::uint8_t id_interworking = 107;
constexpr std::uint8_t id_mesh_id = 114;
constexpr std::uint8_t id_rnr = 201;
constexpr std::uint8_t ext_multi_link = 107;

/// FNV-1a 64 over salt + data.
std::uint64_t hash(std::span<const std::uint8_t> data, std::uint64_t salt) {
    std::uint64_t h = 0xcbf29ce484222325ULL;
    for (unsigned i = 0; i < 8; ++i) {
        h = (h ^ ((salt >> (8U * i)) & 0xffU)) * 0x100000001b3ULL;
    }
    for (const auto b : data) {
        h = (h ^ b) * 0x100000001b3ULL;
    }
    return h;
}

void anonymize_mac_at(std::vector<std::uint8_t>& data, std::size_t pos, const AnonymizeOptions& o) {
    if (pos + 6 > data.size()) {
        return;
    }
    MacAddress mac{};
    std::copy_n(data.begin() + static_cast<std::ptrdiff_t>(pos), 6, mac.begin());
    const auto anon = anonymize_mac(mac, o);
    std::ranges::copy(anon, data.begin() + static_cast<std::ptrdiff_t>(pos));
}

void append_element(std::vector<std::uint8_t>& out, std::uint8_t id,
                    std::span<const std::uint8_t> payload) {
    // Fragment if needed (IEEE 802.11-2020 element fragmentation).
    // An empty payload still yields one (empty) element.
    for (std::size_t pos = 0; pos == 0 || pos < payload.size();) {
        const auto chunk = std::min<std::size_t>(element_max_length, payload.size() - pos);
        out.push_back(pos == 0 ? id : element_id_fragment);
        out.push_back(static_cast<std::uint8_t>(chunk));
        out.insert(out.end(), payload.begin() + static_cast<std::ptrdiff_t>(pos),
                   payload.begin() + static_cast<std::ptrdiff_t>(pos + chunk));
        pos += chunk;
        if (chunk == 0) {
            break;
        }
    }
}

std::vector<std::uint8_t> anonymize_wps(std::span<const std::uint8_t> payload,
                                        const AnonymizeOptions& o) {
    // payload: OUI(3) + type(1) + TLVs (type u16be, length u16be).
    std::vector<std::uint8_t> out(payload.begin(), payload.begin() + 4);
    std::size_t pos = 4;
    while (pos + 4 <= payload.size()) {
        const auto type = static_cast<std::uint16_t>((payload[pos] << 8U) | payload[pos + 1]);
        const auto len = static_cast<std::size_t>((payload[pos + 2] << 8U) | payload[pos + 3]);
        if (pos + 4 + len > payload.size()) {
            break;
        }
        const auto value = payload.subspan(pos + 4, len);
        std::vector<std::uint8_t> replacement(value.begin(), value.end());
        if (type == 0x1011) { // Device Name
            const auto text = std::format("device-{:08x}", hash(value, o.salt) & 0xffffffffU);
            replacement.assign(text.begin(), text.end());
        } else if (type == 0x1042) { // Serial Number
            replacement.assign(1, '0');
        } else if (type == 0x1047 || type == 0x1048) { // UUID-E / UUID-R
            const auto h = hash(value, o.salt);
            for (std::size_t i = 0; i < replacement.size(); ++i) {
                replacement[i] = static_cast<std::uint8_t>(h >> (8U * (i % 8)));
            }
        }
        out.push_back(static_cast<std::uint8_t>(type >> 8U));
        out.push_back(static_cast<std::uint8_t>(type & 0xffU));
        out.push_back(static_cast<std::uint8_t>(replacement.size() >> 8U));
        out.push_back(static_cast<std::uint8_t>(replacement.size() & 0xffU));
        out.insert(out.end(), replacement.begin(), replacement.end());
        pos += 4 + len;
    }
    out.insert(out.end(), payload.begin() + static_cast<std::ptrdiff_t>(pos), payload.end());
    return out;
}

std::vector<std::uint8_t> anonymize_stream(std::span<const std::uint8_t> ies,
                                           const AnonymizeOptions& o, unsigned depth);

std::vector<std::uint8_t> anonymize_payload(const RawElement& e, const AnonymizeOptions& o,
                                            unsigned depth) {
    std::vector<std::uint8_t> p = e.payload;
    if (e.truncated) {
        return p;
    }
    switch (e.id) {
    case id_ssid:
    case id_mesh_id:
        return anonymize_ssid(p, o);
    case id_interworking:
        if (p.size() == 7 || p.size() == 9) {
            anonymize_mac_at(p, p.size() - 6, o);
        }
        return p;
    case id_multiple_bssid: {
        if (p.empty() || depth > 4) {
            return p;
        }
        std::vector<std::uint8_t> out{p[0]};
        std::size_t pos = 1;
        while (pos + 2 <= p.size()) {
            const auto sub_id = p[pos];
            const std::size_t len = p[pos + 1];
            if (pos + 2 + len > p.size()) {
                break;
            }
            const auto body = std::span{p}.subspan(pos + 2, len);
            const auto replaced = sub_id == 0 ? anonymize_stream(body, o, depth + 1)
                                              : std::vector<std::uint8_t>(body.begin(), body.end());
            if (replaced.size() > 255) {
                return p; // cannot re-encode, keep original
            }
            out.push_back(sub_id);
            out.push_back(static_cast<std::uint8_t>(replaced.size()));
            out.insert(out.end(), replaced.begin(), replaced.end());
            pos += 2 + len;
        }
        out.insert(out.end(), p.begin() + static_cast<std::ptrdiff_t>(pos), p.end());
        return out;
    }
    case id_rnr: {
        std::size_t pos = 0;
        while (pos + 4 <= p.size()) {
            const auto count = static_cast<std::size_t>((p[pos] >> 4U) & 0xfU) + 1;
            const std::size_t len = p[pos + 1];
            const auto type = p[pos] & 0x3U;
            pos += 4;
            for (std::size_t i = 0; i < count && pos + len <= p.size(); ++i, pos += len) {
                if (type != 0) {
                    continue;
                }
                // Layouts by length: 5/6 = offset + Short SSID; >= 7 = offset + BSSID, and
                // from 11 on a Short SSID after the BSSID.
                std::optional<std::size_t> short_ssid;
                if (len == 5 || len == 6) {
                    short_ssid = pos + 1;
                } else if (len >= 7) {
                    anonymize_mac_at(p, pos + 1, o);
                    if (len >= 11) {
                        short_ssid = pos + 7;
                    }
                }
                if (short_ssid) {
                    const auto h = hash(std::span{p}.subspan(*short_ssid, 4), o.salt);
                    for (std::size_t k = 0; k < 4; ++k) {
                        p[*short_ssid + k] = static_cast<std::uint8_t>(h >> (8U * k));
                    }
                }
            }
        }
        return p;
    }
    case element_id_vendor_specific:
        if (p.size() >= 4 && p[0] == 0x00 && p[1] == 0x50 && p[2] == 0xf2 && p[3] == 0x04) {
            return anonymize_wps(p, o);
        }
        if (p.size() >= 4 + 6 + 1 && p[0] == 0x50 && p[1] == 0x6f && p[2] == 0x9a &&
            p[3] == 0x1c) { // OWE transition: BSSID, SSID length, SSID, [op class, channel]
            anonymize_mac_at(p, 4, o);
            const std::size_t ssid_len = p[10];
            if (11 + ssid_len <= p.size()) {
                const auto ssid = anonymize_ssid(std::span{p}.subspan(11, ssid_len), o);
                std::vector<std::uint8_t> out(p.begin(), p.begin() + 10);
                out.push_back(static_cast<std::uint8_t>(ssid.size()));
                out.insert(out.end(), ssid.begin(), ssid.end());
                out.insert(out.end(), p.begin() + static_cast<std::ptrdiff_t>(11 + ssid_len),
                           p.end());
                return out;
            }
        }
        return p;
    case element_id_extension:
        if (e.ext_id == ext_multi_link && p.size() >= 1 + 2 + 1 + 6 && (p[1] & 0x7U) == 0) {
            anonymize_mac_at(p, 4, o); // ext id, control (2), common info length, MLD MAC
        }
        return p;
    default:
        return p;
    }
}

std::vector<std::uint8_t> anonymize_stream(std::span<const std::uint8_t> ies,
                                           const AnonymizeOptions& o, unsigned depth) {
    const auto stream = split_elements(ies);
    std::vector<std::uint8_t> out;
    out.reserve(ies.size());
    for (const auto& e : stream.elements) {
        if (e.truncated) {
            out.insert(out.end(), ies.begin() + static_cast<std::ptrdiff_t>(e.stream_range.offset),
                       ies.begin() + static_cast<std::ptrdiff_t>(e.stream_range.end()));
            continue;
        }
        append_element(out, e.id, anonymize_payload(e, o, depth));
    }
    if (stream.trailing) {
        out.insert(out.end(), ies.begin() + static_cast<std::ptrdiff_t>(stream.trailing->offset),
                   ies.end());
    }
    return out;
}

} // namespace

std::vector<std::uint8_t> anonymize_ies(std::span<const std::uint8_t> ies,
                                        const AnonymizeOptions& options) {
    return anonymize_stream(ies, options, 0);
}

MacAddress anonymize_mac(const MacAddress& mac, const AnonymizeOptions& options) {
    const auto h = hash(mac, options.salt);
    MacAddress out{};
    for (std::size_t i = 0; i < 6; ++i) {
        out[i] = static_cast<std::uint8_t>(h >> (8U * i));
    }
    if (options.keep_oui && (mac[0] & 0x02U) == 0) {
        std::copy_n(mac.begin(), 3, out.begin());
    } else {
        out[0] = static_cast<std::uint8_t>((out[0] | 0x02U) & 0xfeU); // locally administered
    }
    return out;
}

std::vector<std::uint8_t> anonymize_ssid(std::span<const std::uint8_t> ssid,
                                         const AnonymizeOptions& options) {
    if (std::ranges::all_of(ssid, [](std::uint8_t b) { return b == 0; })) {
        return {ssid.begin(), ssid.end()};
    }
    const auto text = std::format("ssid-{:08x}", hash(ssid, options.salt) & 0xffffffffU);
    return {text.begin(), text.end()};
}

} // namespace wifi_analyze
