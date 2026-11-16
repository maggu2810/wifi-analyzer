// SPDX-License-Identifier: MIT
#include <wifi_analyze/version.hpp>

#include "version_stamp.hpp"

namespace wifi_analyze {

std::string_view version() noexcept {
    return config::version_stamp;
}

} // namespace wifi_analyze
