// SPDX-License-Identifier: MIT
#include <array>
#include <optional>
#include <string>

#include <wifi_analyze/hex.hpp>

namespace wifi_analyze {
namespace {

constexpr std::optional<std::uint8_t> nibble(char c) noexcept {
    if (c >= '0' && c <= '9') {
        return static_cast<std::uint8_t>(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return static_cast<std::uint8_t>(c - 'a' + 10);
    }
    if (c >= 'A' && c <= 'F') {
        return static_cast<std::uint8_t>(c - 'A' + 10);
    }
    return std::nullopt;
}

constexpr bool is_separator(char c) noexcept {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f' || c == ':' ||
           c == '-';
}

std::string printable(char c) {
    const auto u = static_cast<unsigned char>(c);
    if (u >= 0x20 && u < 0x7f) {
        return {c};
    }
    constexpr std::string_view digits = "0123456789abcdef";
    return {'\\', 'x', digits[u >> 4U], digits[u & 0x0fU]};
}

} // namespace

std::expected<std::vector<std::uint8_t>, Diagnostic> parse_hex(std::string_view text) {
    std::size_t start = 0;
    while (start < text.size() && is_separator(text[start])) {
        ++start;
    }
    if (text.substr(start, 2) == "0x" || text.substr(start, 2) == "0X") {
        start += 2;
    }

    std::vector<std::uint8_t> bytes;
    bytes.reserve((text.size() - start) / 2);
    std::optional<std::uint8_t> high;
    std::size_t digit_count = 0;

    for (std::size_t i = start; i < text.size(); ++i) {
        const char c = text[i];
        if (is_separator(c)) {
            continue;
        }
        const auto value = nibble(c);
        if (!value) {
            return std::unexpected(Diagnostic{
                .severity = Severity::error,
                .message = MessageId::hex_invalid_character,
                .args = {printable(c), std::to_string(i)},
                .bytes = ByteRange{.offset = i, .length = 1},
            });
        }
        ++digit_count;
        if (high) {
            bytes.push_back(
                static_cast<std::uint8_t>((static_cast<unsigned>(*high) << 4U) | *value));
            high.reset();
        } else {
            high = value;
        }
    }

    if (high) {
        return std::unexpected(Diagnostic{
            .severity = Severity::error,
            .message = MessageId::hex_odd_length,
            .args = {std::to_string(digit_count)},
            .bytes = std::nullopt,
        });
    }
    return bytes;
}

std::string to_hex(std::span<const std::uint8_t> bytes) {
    constexpr std::string_view digits = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const auto b : bytes) {
        out.push_back(digits[b >> 4U]);
        out.push_back(digits[b & 0x0fU]);
    }
    return out;
}

} // namespace wifi_analyze
