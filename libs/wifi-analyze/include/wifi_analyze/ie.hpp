// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include <wifi_analyze/diagnostic.hpp>
#include <wifi_analyze/elements.hpp>
#include <wifi_analyze/tlv.hpp>
#include <wifi_analyze/tree.hpp>

namespace wifi_analyze {

class OuiDatabase;

enum class FrameSource : std::uint8_t {
    unknown,
    beacon,
    probe_response,
};

/// Facts not contained in the IE stream that improve decoding and summary.
struct DecodeContext {
    std::optional<std::uint32_t> frequency_mhz;
    /// Privacy bit of the Capability Information field (distinguishes WEP from open).
    std::optional<bool> privacy;
    FrameSource source{FrameSource::unknown};
    /// Full vendor database; nullptr = built-in subset only.
    const OuiDatabase* oui_database{nullptr};
    /// Maximum nesting depth for elements containing elements (Multiple BSSID, ...).
    unsigned max_depth{4};
};

/// Identity of an element.
struct ElementKey {
    std::uint8_t id{0};
    std::optional<std::uint8_t> ext_id;      ///< for id 255
    std::optional<Oui> oui;                  ///< for id 221
    std::optional<std::uint8_t> vendor_type; ///< first octet after the OUI, for id 221
    friend bool operator==(const ElementKey&, const ElementKey&) = default;
};

enum class DecodeStatus : std::uint8_t {
    ok,        ///< fully decoded
    unknown,   ///< no decoder; content kept raw
    malformed, ///< content shorter than required or inconsistent; partially decoded
    truncated, ///< the IE stream ended inside this element
};

struct DecodedElement {
    RawElement raw;
    ElementKey key;
    /// Stable type key, e.g. "rsn", "he_operation", "vendor.microsoft.wmm", "unknown".
    std::string_view type;
    MessageId name{};
    DecodeStatus status{DecodeStatus::ok};
    /// TLV and decoding diagnostics.
    std::vector<Diagnostic> diagnostics;
    ElementValue value;
    /// Root node (label = element name); children are the fields. Byte ranges are relative to
    /// content().
    TreeNode tree;

    [[nodiscard]] std::span<const std::uint8_t> content() const noexcept { return raw.content(); }
};

struct DecodedIes {
    std::vector<DecodedElement> elements;
    std::vector<Diagnostic> diagnostics;
    std::optional<ByteRange> trailing;

    template <class T>
    [[nodiscard]] const T* first() const noexcept {
        for (const auto& e : elements) {
            if (const auto* v = std::get_if<T>(&e.value)) {
                return v;
            }
        }
        return nullptr;
    }

    template <class T>
    [[nodiscard]] std::vector<const T*> all() const {
        std::vector<const T*> result;
        for (const auto& e : elements) {
            if (const auto* v = std::get_if<T>(&e.value)) {
                result.push_back(v);
            }
        }
        return result;
    }
};

/// Decodes an IE stream. Never fails; problems are reported in diagnostics/status.
[[nodiscard]] DecodedIes decode(std::span<const std::uint8_t> ies,
                                const DecodeContext& context = {});

/// Information about a known element type.
struct ElementInfo {
    ElementKey key;
    std::string_view type;
    MessageId name{};
    std::string_view spec_reference;
    bool decoded{false}; ///< false: only named, content shown raw
};

/// All known element types (decoded and named-only), sorted by key.
[[nodiscard]] std::vector<ElementInfo> known_elements();

} // namespace wifi_analyze
