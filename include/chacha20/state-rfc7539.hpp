/*
 * Copyright (c) 2020 Masashi Fujita
 */
#pragma once

#include "detail.hpp"

#include <cstddef>
#include <cstdint>

namespace ChaCha { inline namespace RFC7539 {

    /// @brief [RFC7539](https://tools.ietf.org/html/rfc7539#ref-ChaCha) version of ChaCha20.
    class State final {
    private:
        // NOLINTNEXTLINE: cppcoreguidelines-avoid-magic-numbers
        std::array<uint32_t, 16> state_;

    public:
        ~State ()                 = default;
        State (const State &)     = default;
        State (State &&) noexcept = default;
#pragma clang diagnostic push
#pragma ide diagnostic ignored "cppcoreguidelines-pro-type-member-init"
        State () { state_.fill (0); }

        State (const void *key, size_t size, const void *nonce, size_t nonce_size) {
            state_.fill (0);
            this->setKey (key, size);
            this->setNonce (nonce, nonce_size);
        }

        State (const void *key, size_t size) {
            state_.fill (0);
            this->setKey (key, size);
        }
#pragma clang diagnostic pop

        State &setKey (const void *key, size_t size) {
            using namespace ChaCha::detail;
            // NOLINTNEXTLINE: cppcoreguidelines-pro-member-init
            std::array<uint8_t, 32> K;
            K.fill (0);
            if (K.size () < size) {
                size = K.size ();
            }
            ::memcpy (K.data (), key, size);
            auto const *k = K.data ();

            state_[0]  = 0x61707865u;
            state_[1]  = 0x3320646eu;
            state_[2]  = 0x79622d32u;
            state_[3]  = 0x6b206574u;
            state_[4]  = asUInt32 (k + 0u);
            state_[5]  = asUInt32 (k + 4u);
            state_[6]  = asUInt32 (k + 8u);
            state_[7]  = asUInt32 (k + 12u);
            state_[8]  = asUInt32 (k + 16u);
            state_[9]  = asUInt32 (k + 20u);
            state_[10] = asUInt32 (k + 24u);
            state_[11] = asUInt32 (k + 28u);

            return *this;
        }

        State &setNonce (const void *nonce, size_t size) {
            using namespace ChaCha::detail;
            // NOLINTNEXTLINE: cppcoreguidelines-pro-member-init
            std::array<uint8_t, 4 * 3> N;
            N.fill (0);
            // NOLINTNEXTLINE: bugprone-sizeof-container
            ::memcpy (N.data (), nonce, std::min<size_t> (size, sizeof (N)));
            state_[12] = 0;
            state_[13] = asUInt32 (&N[0]);
            state_[14] = asUInt32 (&N[4]);
            state_[15] = asUInt32 (&N[8]);
            return *this;
        }

        [[nodiscard]] uint32_t getSequence () const { return state_[12]; }

        State &setSequence (uint32_t value) {
            state_[12] = value;
            return *this;
        }

        State &incrementSequence () {
            state_[12] += 1;
            /* stopping at 2^(32 + 6) bytes per (key, nonce) pair is user's responsibility */
            return *this;
        }

        State &assign (const State &src) { return this->operator= (src); }

        State &assign (State &&src) { return this->operator= (src); }

        State &operator= (const State &) = default;
        State &operator= (State &&) = default;

        [[nodiscard]] auto const &state () const { return state_; }
    };
}}  // namespace ChaCha::RFC7539
