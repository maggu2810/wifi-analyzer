// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include <wifi_analyze/elements.hpp>
#include <wifi_analyze/message_id.hpp>

namespace wifi_analyze::core {

class Decoder;
using DecodeFn = ElementValue (*)(Decoder&);

/// Standard (id) or extension (ext_id) element entry. fn == nullptr: named only.
struct ElementEntry {
    std::uint8_t id;
    std::string_view type;
    MessageId name;
    std::string_view spec;
    DecodeFn fn;
};

/// Vendor-specific entry, selected by OUI and (optionally) the vendor type octet.
/// The decoder is called with the reader positioned after the OUI.
struct VendorEntry {
    Oui oui;
    std::optional<std::uint8_t> vendor_type;
    std::string_view type;
    MessageId name;
    std::string_view spec;
    DecodeFn fn;
};

[[nodiscard]] const ElementEntry* find_standard(std::uint8_t id) noexcept;
[[nodiscard]] const ElementEntry* find_extension(std::uint8_t ext_id) noexcept;
[[nodiscard]] const VendorEntry* find_vendor(const Oui& oui,
                                             std::optional<std::uint8_t> vendor_type) noexcept;

[[nodiscard]] std::span<const ElementEntry> standard_entries() noexcept;
[[nodiscard]] std::span<const ElementEntry> extension_entries() noexcept;
[[nodiscard]] std::span<const VendorEntry> vendor_entries() noexcept;

} // namespace wifi_analyze::core
