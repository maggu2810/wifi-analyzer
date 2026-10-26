// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <wifi_analyze/diagnostic.hpp>

namespace wifi_analyze {

/// Parses hex text into bytes. Tolerates an optional "0x" prefix, ASCII whitespace and the
/// separators ':' and '-' anywhere; digits may be upper or lower case.
/// Errors: hex_invalid_character (with position in `text`), hex_odd_length.
[[nodiscard]] std::expected<std::vector<std::uint8_t>, Diagnostic> parse_hex(std::string_view text);

/// Lower-case hex without separators.
[[nodiscard]] std::string to_hex(std::span<const std::uint8_t> bytes);

} // namespace wifi_analyze
