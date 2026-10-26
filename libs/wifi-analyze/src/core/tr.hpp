// SPDX-License-Identifier: MIT
#pragma once

#include <wifi_analyze/message_id.hpp>

/// Defines/uses a translatable domain message: WA_TR(key, "English text").
/// tools/gen_i18n_catalog.py extracts all uses from the sources; the macro itself only yields
/// the MessageId. Use the same text for every use of a key.
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define WA_TR(key, text) (::wifi_analyze::MessageId::key)

namespace wifi_analyze::msg {

// Messages used in many places.
inline constexpr MessageId yes = WA_TR(common_yes, "yes");
inline constexpr MessageId no = WA_TR(common_no, "no");
inline constexpr MessageId reserved = WA_TR(common_reserved, "Reserved");
inline constexpr MessageId unknown = WA_TR(common_unknown, "Unknown");
inline constexpr MessageId data = WA_TR(common_data, "Data");
inline constexpr MessageId item = WA_TR(common_item, "Item");
inline constexpr MessageId count = WA_TR(common_count, "Count");
inline constexpr MessageId length = WA_TR(common_length, "Length");
inline constexpr MessageId version = WA_TR(common_version, "Version");
inline constexpr MessageId none = WA_TR(common_none, "None");
inline constexpr MessageId not_supported = WA_TR(common_not_supported, "Not supported");
inline constexpr MessageId supported = WA_TR(common_supported, "Supported");

} // namespace wifi_analyze::msg
