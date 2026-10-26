// SPDX-License-Identifier: MIT
#include <cmath>
#include <format>
#include <string>

#include <wifi_analyze/hex.hpp>
#include <wifi_analyze/i18n.hpp>
#include <wifi_analyze/tree.hpp>

#include "core/tr.hpp"

namespace wifi_analyze {
namespace {

std::string format_hex(std::uint64_t value, std::size_t octets) {
    constexpr std::string_view digits = "0123456789abcdef";
    const std::size_t width = std::max<std::size_t>(2, octets * 2);
    std::string out(width, '0');
    for (std::size_t i = 0; i < width; ++i) {
        out[width - 1 - i] = digits[(value >> (4U * i)) & 0xfU];
    }
    return "0x" + out;
}

std::string format_suite(std::uint64_t raw) {
    // "00-0f-ac:4"
    return std::format("{:02x}-{:02x}-{:02x}:{}", (raw >> 24U) & 0xffU, (raw >> 16U) & 0xffU,
                       (raw >> 8U) & 0xffU, raw & 0xffU);
}

std::string format_double(double value) {
    // Up to one decimal, trailing ".0" removed: 5.5, 286.8, 6.
    const double rounded = std::round(value * 10.0) / 10.0;
    return rounded == std::floor(rounded) ? std::format("{:.0f}", rounded)
                                          : std::format("{:.1f}", rounded);
}

void append_unit(std::string& out, Unit unit) {
    const auto symbol = unit_symbol(unit);
    if (!symbol.empty()) {
        if (unit != Unit::percent) {
            out.push_back(' ');
        }
        out += symbol;
    }
}

} // namespace

std::string_view Text::render(const Localizer& localizer) const noexcept {
    if (const auto* id = message()) {
        return localizer.text(*id);
    }
    if (const auto* lit = literal()) {
        return *lit;
    }
    return {};
}

std::string_view unit_symbol(Unit unit) noexcept {
    switch (unit) {
    case Unit::none:
        return {};
    case Unit::dbm:
        return "dBm";
    case Unit::db:
        return "dB";
    case Unit::dbm_per_mhz:
        return "dBm/MHz";
    case Unit::mhz:
        return "MHz";
    case Unit::mbps:
        return "Mbit/s";
    case Unit::kbps:
        return "kbit/s";
    case Unit::tu:
        return "TU";
    case Unit::microseconds:
        return "µs";
    case Unit::milliseconds:
        return "ms";
    case Unit::percent:
        return "%";
    case Unit::octets:
        return "octets";
    }
    return {};
}

std::string format_value(const TreeNode& node, const Localizer& localizer) {
    const std::size_t octets = node.bits ? 0 : (node.bytes ? node.bytes->length : 0);
    std::string out;
    std::visit(
        [&](const auto& v) {
            using T = std::decay_t<decltype(v)>;
            if constexpr (std::is_same_v<T, std::monostate>) {
                return;
            } else if constexpr (std::is_same_v<T, bool>) {
                out = localizer.text(v ? msg::yes : msg::no);
                return;
            } else if constexpr (std::is_same_v<T, std::int64_t>) {
                out = std::to_string(v);
            } else if constexpr (std::is_same_v<T, std::uint64_t>) {
                out = node.display == Display::hex ? format_hex(v, octets) : std::to_string(v);
            } else if constexpr (std::is_same_v<T, double>) {
                out = format_double(v);
            } else if constexpr (std::is_same_v<T, std::string>) {
                out = v;
            } else if constexpr (std::is_same_v<T, std::vector<std::uint8_t>>) {
                out = v.empty() ? std::string{localizer.text(msg::none)} : to_hex(v);
                return;
            } else if constexpr (std::is_same_v<T, EnumValue>) {
                const auto name = v.name.render(localizer);
                std::string raw;
                switch (node.display) {
                case Display::hex:
                    raw = format_hex(v.raw, octets);
                    break;
                case Display::suite:
                    raw = format_suite(v.raw);
                    break;
                case Display::decimal:
                case Display::name_only:
                    raw = std::to_string(v.raw);
                    break;
                }
                if (name.empty()) {
                    out = raw;
                } else if (node.display == Display::name_only) {
                    out = name;
                } else {
                    out = std::string{name} + " (" + raw + ")";
                }
                return;
            }
            append_unit(out, node.unit);
        },
        node.value);
    return out;
}

void shift_bytes(TreeNode& node, std::size_t offset) {
    if (node.bytes) {
        node.bytes->offset += offset;
    }
    for (auto& child : node.children) {
        shift_bytes(child, offset);
    }
}

} // namespace wifi_analyze
