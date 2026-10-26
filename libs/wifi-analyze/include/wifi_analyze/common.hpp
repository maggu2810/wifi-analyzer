// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>

namespace wifi_analyze {

/// A contiguous range of bytes, relative to a context given by the owner
/// (e.g. the IE stream or an element payload).
struct ByteRange {
    std::size_t offset{0};
    std::size_t length{0};

    [[nodiscard]] constexpr std::size_t end() const noexcept { return offset + length; }
    friend constexpr bool operator==(const ByteRange&, const ByteRange&) = default;
};

} // namespace wifi_analyze
