// SPDX-License-Identifier: MIT
#pragma once

#include <string_view>

namespace wifi_analyze {

/// Library version, e.g. "0.1.0".
[[nodiscard]] std::string_view version() noexcept;

} // namespace wifi_analyze
