// SPDX-License-Identifier: MIT
#pragma once

#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace wifi_analyze::core {

/// Bounds-checked cursor over untrusted bytes.
///
/// Every read is fallible and returns std::nullopt if not enough bytes remain; a failed read
/// does not consume anything. Decoders must use this instead of raw pointer arithmetic.
class ByteReader {
    // Helpers first: Clang cannot constant-evaluate member templates used before their
    // definition inside the class.
    template <std::unsigned_integral T, std::size_t N>
        requires(N <= sizeof(T))
    constexpr std::optional<T> read_le() noexcept {
        if (N > remaining()) {
            return std::nullopt;
        }
        T value{};
        for (std::size_t i = 0; i < N; ++i) {
            value =
                static_cast<T>(value | static_cast<T>(static_cast<T>(data_[pos_ + i]) << (8U * i)));
        }
        pos_ += N;
        return value;
    }

    template <std::unsigned_integral T, std::size_t N>
        requires(N <= sizeof(T))
    constexpr std::optional<T> read_be() noexcept {
        if (N > remaining()) {
            return std::nullopt;
        }
        T value{};
        for (std::size_t i = 0; i < N; ++i) {
            value = static_cast<T>(static_cast<T>(value << 8U) | static_cast<T>(data_[pos_ + i]));
        }
        pos_ += N;
        return value;
    }

public:
    constexpr ByteReader() noexcept = default;
    constexpr explicit ByteReader(std::span<const std::uint8_t> data) noexcept : data_{data} {}

    /// Bytes consumed so far (offset relative to the start of this reader).
    [[nodiscard]] constexpr std::size_t offset() const noexcept { return pos_; }
    [[nodiscard]] constexpr std::size_t size() const noexcept { return data_.size(); }
    [[nodiscard]] constexpr std::size_t remaining() const noexcept { return data_.size() - pos_; }
    [[nodiscard]] constexpr bool empty() const noexcept { return remaining() == 0; }

    [[nodiscard]] constexpr std::optional<std::uint8_t> peek_u8() const noexcept {
        if (empty()) {
            return std::nullopt;
        }
        return data_[pos_];
    }

    constexpr std::optional<std::uint8_t> u8() noexcept { return read_le<std::uint8_t, 1>(); }
    constexpr std::optional<std::uint16_t> u16le() noexcept { return read_le<std::uint16_t, 2>(); }
    constexpr std::optional<std::uint32_t> u24le() noexcept { return read_le<std::uint32_t, 3>(); }
    constexpr std::optional<std::uint32_t> u32le() noexcept { return read_le<std::uint32_t, 4>(); }
    constexpr std::optional<std::uint64_t> u64le() noexcept { return read_le<std::uint64_t, 8>(); }
    constexpr std::optional<std::uint16_t> u16be() noexcept { return read_be<std::uint16_t, 2>(); }
    constexpr std::optional<std::uint32_t> u24be() noexcept { return read_be<std::uint32_t, 3>(); }
    constexpr std::optional<std::uint32_t> u32be() noexcept { return read_be<std::uint32_t, 4>(); }

    /// Reads exactly n bytes.
    constexpr std::optional<std::span<const std::uint8_t>> bytes(std::size_t n) noexcept {
        if (n > remaining()) {
            return std::nullopt;
        }
        const auto result = data_.subspan(pos_, n);
        pos_ += n;
        return result;
    }

    /// Reads exactly N bytes into an array (e.g. OUIs, MAC addresses).
    template <std::size_t N>
    constexpr std::optional<std::array<std::uint8_t, N>> array() noexcept {
        if (N > remaining()) {
            return std::nullopt;
        }
        std::array<std::uint8_t, N> result{};
        for (std::size_t i = 0; i < N; ++i) {
            result[i] = data_[pos_ + i];
        }
        pos_ += N;
        return result;
    }

    /// Consumes and returns all remaining bytes (possibly empty).
    constexpr std::span<const std::uint8_t> rest() noexcept {
        const auto result = data_.subspan(pos_);
        pos_ = data_.size();
        return result;
    }

    /// Returns a reader over the next n bytes and consumes them from this reader.
    constexpr std::optional<ByteReader> sub(std::size_t n) noexcept {
        const auto span = bytes(n);
        if (!span) {
            return std::nullopt;
        }
        return ByteReader{*span};
    }

    constexpr bool skip(std::size_t n) noexcept { return bytes(n).has_value(); }

private:
    std::span<const std::uint8_t> data_{};
    std::size_t pos_{0};
};

} // namespace wifi_analyze::core
