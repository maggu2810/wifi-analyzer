// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

namespace wifi_analyze {

enum class Band : std::uint8_t {
    unknown,
    ghz_2_4,
    ghz_5,
    ghz_6,
    ghz_60,
};

struct ChannelInfo {
    Band band{Band::unknown};
    std::uint16_t channel{0};
    friend constexpr bool operator==(const ChannelInfo&, const ChannelInfo&) = default;
};

/// Channel number for a center frequency of a 20 MHz channel (IEEE 802.11-2020 Annex E).
[[nodiscard]] std::optional<ChannelInfo> channel_from_frequency(std::uint32_t mhz) noexcept;

/// Center frequency of a channel number in a band.
[[nodiscard]] std::optional<std::uint32_t> frequency_from_channel(Band band,
                                                                  std::uint16_t channel) noexcept;

/// Band of a global operating class (IEEE 802.11-2020 Table E-4).
[[nodiscard]] Band band_from_operating_class(std::uint8_t operating_class) noexcept;

/// "2.4 GHz", "5 GHz", "6 GHz", "60 GHz" or empty.
[[nodiscard]] std::string_view band_name(Band band) noexcept;

} // namespace wifi_analyze
