// SPDX-License-Identifier: MIT
#pragma once

#include <string>

#include <wifi_analyze/i18n.hpp>
#include <wifi_analyze/ie.hpp>
#include <wifi_analyze/summary.hpp>

namespace wifi_analyze {

/// Schema identifier and version of the decoded-output JSON (docs/data-formats.md).
inline constexpr std::string_view json_schema = "wifi-analyze.decoded";
inline constexpr int json_schema_version = 1;

struct JsonOptions {
    bool pretty{false};
    bool include_payload{true}; ///< element payload hex
    bool include_tree{true};    ///< element trees (false: summary and element headers only)
    bool include_detail{true};  ///< nodes with Significance::detail
};

/// Decoded IEs + summary as one JSON document with localized labels.
[[nodiscard]] std::string to_json(const DecodedIes& ies, const BssSummary& summary,
                                  const Localizer& localizer, const JsonOptions& options = {});

} // namespace wifi_analyze
