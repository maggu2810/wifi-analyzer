// SPDX-License-Identifier: MIT
#pragma once

#include <ostream>
#include <string>
#include <vector>

#include <wifi_analyze/i18n.hpp>
#include <wifi_analyze/ie.hpp>
#include <wifi_analyze/summary.hpp>

#include "input.hpp"

namespace wifi_analyze_cli {

struct RenderOptions {
    bool color{false};
    unsigned width{100}; ///< terminal width
    bool verbose{false}; ///< detail nodes, info diagnostics, byte ranges
    bool raw{false};     ///< payload hex per element
    bool hexdump{false}; ///< hex dump of each element's content
    bool summary_only{false};
};

/// A decoded BSS ready for rendering.
struct DecodedBss {
    const InputBss* input{nullptr};
    wifi_analyze::DecodedIes ies;
    wifi_analyze::BssSummary summary;
    std::optional<wifi_analyze::DecodedIes> beacon_ies;
};

class TextRenderer {
public:
    TextRenderer(std::ostream& out, RenderOptions options, wifi_analyze::Localizer localizer)
        : out_{out}, options_{options}, loc_{localizer} {}

    /// Full detail: header, summary overview, elements.
    void bss(const DecodedBss& bss);
    /// Table of many BSSs (already sorted/filtered).
    void table(const std::vector<const DecodedBss*>& rows);
    /// Known element types.
    void elements(const std::vector<wifi_analyze::ElementInfo>& infos);

private:
    void header(const DecodedBss& bss);
    void section(std::string_view title);
    void tree(const wifi_analyze::TreeNode& node, unsigned depth);
    void element(const wifi_analyze::DecodedElement& e, std::size_t index);
    void element_list(const wifi_analyze::DecodedIes& ies);
    void diagnostics(const std::vector<wifi_analyze::Diagnostic>& list, unsigned depth);
    void hexdump(std::span<const std::uint8_t> data, unsigned depth);

    [[nodiscard]] std::string style(std::string_view text, std::string_view code) const;

    std::ostream& out_;
    RenderOptions options_;
    wifi_analyze::Localizer loc_;
};

/// Signal quality 0..4 from dBm.
[[nodiscard]] int signal_level(int dbm) noexcept;
/// Number of terminal columns of a UTF-8 string (code points; no wide-character handling).
[[nodiscard]] std::size_t display_width(std::string_view s) noexcept;

} // namespace wifi_analyze_cli
