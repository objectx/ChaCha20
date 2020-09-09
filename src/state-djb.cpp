//
// Copyright (c) 2020 Masashi Fujita.
//
#include <chacha20/detail.hpp>
#include <chacha20/state-djb.hpp>

#include <array>
#include <cstdint>

namespace ChaCha {
#pragma clang diagnostic push
#pragma ide diagnostic ignored "cppcoreguidelines-pro-type-member-init"
#pragma ide diagnostic ignored "modernize-avoid-c-arrays"
#pragma ide diagnostic ignored "readability-magic-numbers"

    const char sigma[] = "expand 32-byte k";
    const char tau[]   = "expand 16-byte k";

    using namespace detail;
    State &State::setKey (const void *key, size_t size) {
        std::array<uint8_t, 32> K;
        if (K.size () < size) {
            size = K.size ();
        }
        K.fill (0);
        ::memcpy (K.data (), key, size);
        auto const *k = K.data ();
        if (size <= 16) {
            state_[0]  = asUInt32 (&tau[0]);
            state_[1]  = asUInt32 (&tau[4]);
            state_[2]  = asUInt32 (&tau[8]);
            state_[3]  = asUInt32 (&tau[12]);
            state_[4]  = asUInt32 (k + 0);
            state_[5]  = asUInt32 (k + 4);
            state_[6]  = asUInt32 (k + 8);
            state_[7]  = asUInt32 (k + 12);
            state_[8]  = asUInt32 (k + 0);
            state_[9]  = asUInt32 (k + 4);
            state_[10] = asUInt32 (k + 8);
            state_[11] = asUInt32 (k + 12);
        }
        else {
            state_[0]  = asUInt32 (&sigma[0]);
            state_[1]  = asUInt32 (&sigma[4]);
            state_[2]  = asUInt32 (&sigma[8]);
            state_[3]  = asUInt32 (&sigma[12]);
            state_[4]  = asUInt32 (k + 0);
            state_[5]  = asUInt32 (k + 4);
            state_[6]  = asUInt32 (k + 8);
            state_[7]  = asUInt32 (k + 12);
            state_[8]  = asUInt32 (k + 16);
            state_[9]  = asUInt32 (k + 20);
            state_[10] = asUInt32 (k + 24);
            state_[11] = asUInt32 (k + 28);
        }
        return *this;
    }
#pragma clang diagnostic pop
}  // namespace ChaCha
