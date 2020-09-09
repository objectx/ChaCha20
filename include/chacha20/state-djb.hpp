/*
 * Copyright (c) 2020 Masashi Fujita.
 */
#pragma once

#include "detail.hpp"

#include <cstddef>
#include <cstdint>

namespace ChaCha { namespace DJB {

    /// @brief Original version of ChaCha20 state definition.
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

        State (const void *key, size_t size, uint64_t iv) {
            state_.fill (0);
            this->setKey (key, size);
            this->setInitialVector (iv);
        }

        State (const void *key, size_t size) {
            state_.fill (0);
            this->setKey (key, size);
        }
#pragma clang diagnostic pop

        State &setKey (const void *key, size_t size) {
            using namespace detail;

            const char sigma[] = "expand 32-byte k";
            const char tau[]   = "expand 16-byte k";

            std::array<uint8_t, 32> K {};
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

        State &setInitialVector (uint64_t iv) {
            state_[12] = 0;
            state_[13] = 0;
            state_[14] = static_cast<uint32_t> (iv >> 0u);
            state_[15] = static_cast<uint32_t> (iv >> 32u);
            return *this;
        }

        [[nodiscard]] uint64_t getSequence () const {
            return ((static_cast<uint64_t> (state_[12]) << 0u) | (static_cast<uint64_t> (state_[13]) << 32u));
        }

        State &setSequence (uint64_t value) {
            state_[12] = static_cast<uint32_t> (value >> 0u);
            state_[13] = static_cast<uint32_t> (value >> 32u);
            return *this;
        }

        State &incrementSequence () {
            if ((state_[12] += 1) == 0) {
                state_[13] += 1;
                /* stopping at 2^70 bytes per nonce is user's responsibility */
            }
            return *this;
        }

        State &assign (const State &src) { return this->operator= (src); }

        State &assign (State &&src) { return this->operator= (src); }

        State &operator= (const State &) = default;
        State &operator= (State &&) = default;

        [[nodiscard]] auto const &state () const { return state_; }
    };
}}  // namespace ChaCha::DJB
