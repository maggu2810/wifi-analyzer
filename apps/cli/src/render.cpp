// SPDX-License-Identifier: MIT
#include "render.hpp"

#include <algorithm>
#include <format>

#include <wifi_analyze/channel.hpp>
#include <wifi_analyze/hex.hpp>

namespace wifi_analyze_cli {
namespace {

namespace wa = wifi_analyze;

constexpr std::string_view bold = "1";
constexpr std::string_view dim = "2";
constexpr std::string_view red = "31";
constexpr std::string_view green = "32";
constexpr std::string_view yellow = "33";
constexpr std::string_view cyan = "36";

constexpr unsigned value_column = 44;

std::string pad_right(std::string s, std::size_t width) {
    const auto w = display_width(s);
    if (w < width) {
        s.append(width - w, ' ');
    }
    return s;
}

std::string truncate(std::string s, std::size_t width) {
    if (display_width(s) <= width) {
        return s;
    }
    // Cut at a code point boundary, leave room for the ellipsis.
    std::size_t cps = 0;
    std::size_t i = 0;
    for (; i < s.size(); ++i) {
        if ((static_cast<unsigned char>(s[i]) & 0xc0U) != 0x80U) {
            if (cps == width - 1) {
                break;
            }
            ++cps;
        }
    }
    s.resize(i);
    return s + "…";
}

std::string_view status_text(wa::DecodeStatus s) {
    switch (s) {
    case wa::DecodeStatus::ok:
        return {};
    case wa::DecodeStatus::unknown:
        return "not decoded";
    case wa::DecodeStatus::malformed:
        return "malformed";
    case wa::DecodeStatus::truncated:
        return "truncated";
    }
    return {};
}

std::string element_id_text(const wa::DecodedElement& e) {
    if (e.key.ext_id) {
        return std::format("255/{}", *e.key.ext_id);
    }
    if (e.key.oui) {
        auto text = std::format("221 {:02x}:{:02x}:{:02x}", (*e.key.oui)[0], (*e.key.oui)[1],
                                (*e.key.oui)[2]);
        if (e.key.vendor_type) {
            text += std::format("/{}", *e.key.vendor_type);
        }
        return text;
    }
    return std::to_string(e.key.id);
}

std::string signal_bar(int level) {
    std::string bar;
    for (int i = 0; i < 4; ++i) {
        bar += i < level ? "▇" : "▁";
    }
    return bar;
}

} // namespace

int signal_level(int dbm) noexcept {
    if (dbm >= -55) {
        return 4;
    }
    if (dbm >= -67) {
        return 3;
    }
    if (dbm >= -75) {
        return 2;
    }
    if (dbm >= -85) {
        return 1;
    }
    return 0;
}

std::size_t display_width(std::string_view s) noexcept {
    return static_cast<std::size_t>(std::ranges::count_if(
        s, [](char c) { return (static_cast<unsigned char>(c) & 0xc0U) != 0x80U; }));
}

std::string TextRenderer::style(std::string_view text, std::string_view code) const {
    if (!options_.color) {
        return std::string{text};
    }
    return std::format("\x1b[{}m{}\x1b[0m", code, text);
}

void TextRenderer::section(std::string_view title) {
    out_ << style(title, bold) << '\n';
}

void TextRenderer::header(const DecodedBss& bss) {
    std::vector<std::string> parts;
    if (bss.input != nullptr && bss.input->bssid) {
        parts.push_back("BSS " + format_mac(*bss.input->bssid));
    }
    if (bss.summary.ssid_present) {
        parts.push_back(bss.summary.hidden ? "<hidden>" : std::format("\"{}\"", bss.summary.ssid));
    } else if (bss.input != nullptr && bss.input->ssid) {
        parts.push_back(std::format("\"{}\"", *bss.input->ssid));
    }
    const auto& phy = bss.summary.phy;
    if (phy.primary_frequency_mhz) {
        auto freq = std::format("{} MHz", *phy.primary_frequency_mhz);
        if (phy.primary_channel) {
            freq += std::format(" (ch {}, {})", *phy.primary_channel, wa::band_name(phy.band));
        }
        parts.push_back(std::move(freq));
    }
    std::string line;
    for (const auto& p : parts) {
        line += (line.empty() ? "" : "  ") + p;
    }
    out_ << style(line, bold);
    if (bss.input != nullptr && bss.input->signal_dbm) {
        const auto level = signal_level(*bss.input->signal_dbm);
        const auto color = level >= 3 ? green : level >= 2 ? yellow : red;
        out_ << "  "
             << style(std::format("{} dBm {}", *bss.input->signal_dbm, signal_bar(level)), color);
    }
    out_ << '\n';
    out_ << style(std::string(std::min<unsigned>(options_.width, 100), '-'), dim) << '\n';
}

void TextRenderer::tree(const wa::TreeNode& node, unsigned depth) {
    for (const auto& child : node.children) {
        if (child.significance == wa::Significance::detail && !options_.verbose) {
            continue;
        }
        const std::string indent(2 * std::size_t{depth}, ' ');
        std::string label = indent + std::string{loc_.text(child.label)};
        const auto value = wa::format_value(child, loc_);
        std::string line;
        if (child.label == wa::MessageId::common_item) {
            // List entries are rendered as bullets.
            line = indent + "- " + value;
        } else if (value.empty()) {
            line = style(label, cyan);
        } else {
            const auto width = display_width(label);
            std::string leader = " ";
            if (width + 2 < value_column) {
                leader += std::string(value_column - width - 2, '.');
            }
            leader += ' ';
            auto text = value;
            if (child.significance == wa::Significance::warning) {
                text = style(text, yellow);
            }
            line = label + style(leader, dim) + text;
        }
        if (options_.verbose && child.bytes) {
            line += style(std::format("  [{}+{}]", child.bytes->offset, child.bytes->length), dim);
            if (child.bits) {
                line += style(std::format(" bits {}..{}", child.bits->first,
                                          child.bits->first + child.bits->count - 1),
                              dim);
            }
        }
        out_ << line << '\n';
        tree(child, depth + 1);
    }
}

void TextRenderer::diagnostics(const std::vector<wa::Diagnostic>& list, unsigned depth) {
    for (const auto& d : list) {
        if (d.severity == wa::Severity::info && !options_.verbose) {
            continue;
        }
        const auto [prefix, color] = d.severity == wa::Severity::error ? std::pair{"error", red}
                                     : d.severity == wa::Severity::warning
                                         ? std::pair{"warning", yellow}
                                         : std::pair{"info", dim};
        out_ << std::string(2 * std::size_t{depth}, ' ')
             << style(std::format("{}: {}", prefix, loc_.format(d.message, d.args)), color) << '\n';
    }
}

void TextRenderer::hexdump(std::span<const std::uint8_t> data, unsigned depth) {
    const std::string indent(2 * std::size_t{depth}, ' ');
    for (std::size_t line = 0; line < data.size(); line += 16) {
        std::string hex;
        std::string ascii;
        for (std::size_t i = line; i < line + 16; ++i) {
            if (i < data.size()) {
                hex += std::format("{:02x} ", data[i]);
                ascii.push_back(data[i] >= 0x20 && data[i] < 0x7f ? static_cast<char>(data[i])
                                                                  : '.');
            } else {
                hex += "   ";
            }
            if (i == line + 7) {
                hex += ' ';
            }
        }
        out_ << indent << style(std::format("{:04x}  {} |{}|", line, hex, ascii), dim) << '\n';
    }
}

void TextRenderer::element(const wa::DecodedElement& e, std::size_t index) {
    auto title = std::format("[{}] {} ({})", index, loc_.text(e.name), element_id_text(e));
    out_ << style(title, bold);
    out_ << style(std::format("  @{} len {}", e.raw.stream_range.offset, e.raw.payload.size()),
                  dim);
    if (const auto status = status_text(e.status); !status.empty()) {
        const auto color = e.status == wa::DecodeStatus::unknown ? dim : red;
        out_ << "  " << style(std::format("[{}]", status), color);
    }
    out_ << '\n';
    if (options_.raw) {
        out_ << "  " << style(wa::to_hex(e.raw.payload), dim) << '\n';
    }
    tree(e.tree, 1);
    diagnostics(e.diagnostics, 1);
    if (options_.hexdump) {
        hexdump(e.content(), 1);
    }
}

void TextRenderer::element_list(const wa::DecodedIes& ies) {
    for (std::size_t i = 0; i < ies.elements.size(); ++i) {
        element(ies.elements[i], i);
    }
    diagnostics(ies.diagnostics, 0);
}

void TextRenderer::bss(const DecodedBss& bss) {
    header(bss);
    tree(wa::describe(bss.summary), 0);
    if (options_.summary_only) {
        out_ << '\n';
        return;
    }
    out_ << '\n';
    section(std::format("Elements ({})", bss.ies.elements.size()));
    element_list(bss.ies);
    if (bss.beacon_ies) {
        out_ << '\n';
        section(std::format("Beacon elements ({})", bss.beacon_ies->elements.size()));
        element_list(*bss.beacon_ies);
    }
    out_ << '\n';
}

void TextRenderer::table(const std::vector<const DecodedBss*>& rows) {
    // Fixed columns: SIGNAL(9) CH(4) BAND(5) WIDTH(6) GEN(9) SECURITY(22) SSID(rest) BSSID(17)
    const std::size_t fixed = 9 + 1 + 4 + 1 + 5 + 1 + 6 + 1 + 9 + 1 + 22 + 1 + 1 + 17;
    const std::size_t ssid_width = options_.width > fixed + 8 ? options_.width - fixed : 16;
    out_ << style(std::format("{:<9} {:>4} {:<5} {:<6} {:<9} {:<22} {} {:<17}", "SIGNAL", "CH",
                              "BAND", "WIDTH", "GEN", "SECURITY", pad_right("SSID", ssid_width),
                              "BSSID"),
                  bold)
         << '\n';
    for (const auto* row : rows) {
        const auto& s = row->summary;
        std::string signal = "    ?    ";
        std::string_view signal_color = dim;
        if (row->input->signal_dbm) {
            const auto level = signal_level(*row->input->signal_dbm);
            signal = std::format("{:>4} {}", *row->input->signal_dbm, signal_bar(level));
            signal_color = level >= 3 ? green : level >= 2 ? yellow : red;
        }
        const auto channel = s.phy.primary_channel ? std::to_string(*s.phy.primary_channel) : "?";
        const auto band = wa::band_name(s.phy.band);
        const auto width = s.phy.eighty_plus_eighty ? std::string{"80+80"}
                                                    : std::to_string(s.phy.channel_width_mhz);
        std::string security{wa::security_type_name(s.security.type).render(loc_)};
        security = pad_right(truncate(security, 22), 22);
        if (s.security.weak) {
            security = style(security, yellow);
        }
        const auto ssid = s.hidden || !s.ssid_present ? std::string{"<hidden>"} : s.ssid;
        const auto bssid = row->input->bssid ? format_mac(*row->input->bssid) : std::string{};
        out_ << style(pad_right(signal, 9), signal_color) << ' '
             << std::format("{:>4} {:<5} {:<6} {:<9} ", channel,
                            band.empty() ? "?" : std::string{band.substr(0, band.find(' '))}, width,
                            wa::generation_name(s.phy))
             << security << ' ' << pad_right(truncate(ssid, ssid_width), ssid_width) << ' ' << bssid
             << '\n';
    }
}

void TextRenderer::elements(const std::vector<wa::ElementInfo>& infos) {
    out_ << style(std::format("{:<16} {:<38} {:<8} {}", "ID", "TYPE", "DECODED", "NAME"), bold)
         << '\n';
    for (const auto& info : infos) {
        std::string id = std::to_string(info.key.id);
        if (info.key.ext_id) {
            id = std::format("255/{}", *info.key.ext_id);
        } else if (info.key.oui) {
            id = std::format("221 {:02x}:{:02x}:{:02x}/{}", (*info.key.oui)[0], (*info.key.oui)[1],
                             (*info.key.oui)[2], info.key.vendor_type.value_or(0));
        }
        out_ << std::format("{:<16} {:<38} {:<8} {}", id, info.type, info.decoded ? "yes" : "-",
                            loc_.text(info.name))
             << '\n';
    }
}

} // namespace wifi_analyze_cli
