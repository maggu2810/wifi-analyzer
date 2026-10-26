// SPDX-License-Identifier: MIT
#include <wifi_analyze/version.hpp>

#include "version_config.hpp"

namespace wifi_analyze {

std::string_view version() noexcept {
    return WIFI_ANALYZE_VERSION_STRING;
}

} // namespace wifi_analyze
