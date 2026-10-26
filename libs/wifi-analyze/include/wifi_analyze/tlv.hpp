// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include <wifi_analyze/common.hpp>
#include <wifi_analyze/diagnostic.hpp>

namespace wifi_analyze {

/// Element IDs with structural meaning for the TLV layer (IEEE 802.11-2024 §9.4.2.1).
inline constexpr std::uint8_t element_id_vendor_specific = 221;
inline constexpr std::uint8_t element_id_fragment = 242;
inline constexpr std::uint8_t element_id_extension = 255;

/// Maximum length of one element's information field.
inline constexpr std::size_t element_max_length = 255;

/// One element of an IE stream, before element-specific decoding.
struct RawElement {
    std::uint8_t id{0};
    /// Element ID Extension, present for id 255 with a non-empty information field.
    std::optional<std::uint8_t> ext_id;
    /// All stream bytes belonging to this element, including headers and Fragment elements.
    ByteRange stream_range;
    /// Stream ranges of the information-field bytes, one per (fragment) element.
    std::vector<ByteRange> payload_segments;
    /// Information field (reassembled if fragmented). For extension elements this still starts
    /// with the Element ID Extension byte; see content().
    std::vector<std::uint8_t> payload;
    /// The stream ended before the declared length; payload holds the available bytes.
    bool truncated{false};
    std::vector<Diagnostic> diagnostics;

    [[nodiscard]] bool fragmented() const noexcept { return payload_segments.size() > 1; }

    /// Information field without the Element ID Extension byte.
    [[nodiscard]] std::span<const std::uint8_t> content() const noexcept {
        const std::span<const std::uint8_t> all{payload};
        return ext_id ? all.subspan(1) : all;
    }
};

struct ElementStream {
    std::vector<RawElement> elements;
    /// Findings not attributable to one element (e.g. a dangling header byte).
    std::vector<Diagnostic> diagnostics;
    /// Bytes at the end that do not form an element header.
    std::optional<ByteRange> trailing;
};

/// Splits an IE byte stream into elements. Never fails: malformed input is reported via
/// diagnostics and every input byte is accounted for by exactly one element or `trailing`.
/// Elements of length 255 followed by Fragment elements (id 242) are reassembled
/// (IEEE 802.11-2024, subclause "Element fragmentation").
[[nodiscard]] ElementStream split_elements(std::span<const std::uint8_t> ies);

} // namespace wifi_analyze
