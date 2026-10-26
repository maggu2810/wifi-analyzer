// SPDX-License-Identifier: MIT
#include <wifi_analyze/version.hpp>

#include "version_config.hpp"

namespace wifi_analyze {

std::string_view version() noexcept {
    return config::version;
}

} // namespace wifi_analyze
