/*
 * Copyright (c) 2020 Masashi Fujita.
 */

#pragma once

#include <array>
#include <cstdint>

namespace ChaCha::detail {
    using mask_t = std::array<uint8_t, 64>;
    constexpr size_t offset_to_sequence (size_t offset) { return offset / std::tuple_size<mask_t>::value; }
    // NOLINTNEXTLINE: cppcoreguidelines-avoid-magic-numbers
    mask_t create_mask (const std::array<uint32_t, 16> &state);

    inline uint32_t asUInt32 (const void *data) {
        // clang-format off
        auto const *p = static_cast<const uint8_t *> (data);
        return ((static_cast<uint32_t> (p[0]) <<  0u) |
                (static_cast<uint32_t> (p[1]) <<  8u) |
                (static_cast<uint32_t> (p[2]) << 16u) |
                (static_cast<uint32_t> (p[3]) << 24u));
        // clang-format on
    }

    inline uint64_t asUInt64 (const void *data) {
        // clang-format off
        auto const *p = static_cast<const uint8_t *> (data);
        return ((static_cast<uint64_t> (p[0]) <<  0u) |
                (static_cast<uint64_t> (p[1]) <<  8u) |
                (static_cast<uint64_t> (p[2]) << 16u) |
                (static_cast<uint64_t> (p[3]) << 24u) |
                (static_cast<uint64_t> (p[4]) << 32u) |
                (static_cast<uint64_t> (p[5]) << 40u) |
                (static_cast<uint64_t> (p[6]) << 48u) |
                (static_cast<uint64_t> (p[7]) << 56u));
        // clang-format on
    }
}  // namespace ChaCha20::detail
