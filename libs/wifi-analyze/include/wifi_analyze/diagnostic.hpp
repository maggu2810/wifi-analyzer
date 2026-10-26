// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <wifi_analyze/common.hpp>
#include <wifi_analyze/message_id.hpp>

namespace wifi_analyze {

enum class Severity : std::uint8_t {
    info,    ///< noteworthy, not a problem (e.g. element was fragmented)
    warning, ///< unusual or non-conformant, but decoding continued
    error,   ///< data could not be (fully) decoded
};

/// A localizable finding about the input. Render with Localizer::format(message, args).
struct Diagnostic {
    Severity severity{Severity::error};
    MessageId message{};
    std::vector<std::string> args;
    std::optional<ByteRange> bytes; ///< affected bytes, relative to the decoded input

    friend bool operator==(const Diagnostic&, const Diagnostic&) = default;
};

} // namespace wifi_analyze
