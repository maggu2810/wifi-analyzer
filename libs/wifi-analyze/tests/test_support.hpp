// SPDX-License-Identifier: MIT
#pragma once

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <wifi_analyze/hex.hpp>
#include <wifi_analyze/ie.hpp>

namespace test_support {

inline std::string read_file(const std::string& path) {
    const std::ifstream in{path, std::ios::binary};
    if (!in) {
        throw std::runtime_error("cannot open " + path);
    }
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

inline std::string testdata(const std::string& relative) {
    return std::string{WIFI_TESTDATA_DIR} + "/" + relative;
}

inline std::vector<std::uint8_t> capture(const std::string& name) {
    return wifi_analyze::parse_hex(read_file(testdata("captures/synthetic/" + name + ".hex")))
        .value();
}

inline std::vector<std::uint8_t> hex(std::string_view text) {
    return wifi_analyze::parse_hex(text).value();
}

inline const wifi_analyze::DecodedElement* find(const wifi_analyze::DecodedIes& ies,
                                                std::string_view type) {
    const auto it = std::ranges::find(ies.elements, type, &wifi_analyze::DecodedElement::type);
    return it == ies.elements.end() ? nullptr : &*it;
}

inline bool has_diagnostic(const std::vector<wifi_analyze::Diagnostic>& list,
                           wifi_analyze::MessageId id) {
    return std::ranges::any_of(list, [id](const auto& d) { return d.message == id; });
}

/// Depth-first search for a node by label.
inline const wifi_analyze::TreeNode* node(const wifi_analyze::TreeNode& root,
                                          wifi_analyze::MessageId label) {
    if (root.label == label) {
        return &root;
    }
    for (const auto& c : root.children) {
        if (const auto* n = node(c, label)) {
            return n;
        }
    }
    return nullptr;
}

} // namespace test_support
