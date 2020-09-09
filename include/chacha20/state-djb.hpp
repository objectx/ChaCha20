/*
 * Copyright (c) 2020 Masashi Fujita.
 */
#pragma once

#include "detail.hpp"

#include <cstddef>
#include <cstdint>

namespace ChaCha { inline namespace DJB {

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

        State &setKey (const void *key, size_t size);

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
