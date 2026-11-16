// SPDX-License-Identifier: MIT
#pragma once

#include <string_view>

namespace wifi_analyze {

/// Library version with build identity: "0.4.0" for a release build (at tag lib-v0.4.0),
/// otherwise e.g. "0.5.0-dev.3+g1a2b3c4" or "0.5.0-dev.3+g1a2b3c4.dirty"
/// (docs/decisions/0008-versioning-from-git.md).
[[nodiscard]] std::string_view version() noexcept;

} // namespace wifi_analyze
