/*
 * Copyright (c) 2020 Masashi Fujita.
 */
#pragma once

#include "detail.hpp"

#include <cstdint>
#include <cstddef>
#include <array>
#include <type_traits>

namespace ChaCha {

    /// @brief Applies ChaCha20.
    /// @tparam State_ The state type.
    /// @param state The chacha state
    /// @param result
    /// @param msg
    /// @param msg_size
    template<typename State_>
    void apply (State_ &state, void *result, const void *msg, size_t msg_size) {
        if (msg == nullptr || msg_size == 0) {
            return;
        }
        auto *out = static_cast<uint8_t *> (result);
        auto *in  = static_cast<const uint8_t *> (msg);

        size_t cnt = msg_size / std::tuple_size<detail::mask_t>::value;
        for (size_t i = 0; i < cnt; ++i) {
            auto const &mask = detail::create_mask (state.state ());
            state.incrementSequence ();

            for (size_t j = 0; j < mask.size (); ++j) {
                out[j] = in[j] ^ mask[j];
            }
            out += mask.size ();
            in += mask.size ();
        }

        size_t remain = msg_size - (cnt * std::tuple_size<detail::mask_t>::value);
        if (0 < remain) {
            auto const &mask = detail::create_mask (state.state ());
            state.incrementSequence ();

            for (size_t i = 0; i < remain; ++i) {
                out[i] = in[i] ^ mask[i];
            }
        }
    }

    /// @brief Applies ChaCha20 (in place).
    /// @tparam State_ The state type
    /// @param state ChaCha20 state
    /// @param msg
    /// @param msg_size
    template<typename State_>
    void apply (State_ &state, void *msg, size_t msg_size) {
        if (msg == nullptr || msg_size == 0) {
            return;
        }
        auto *m = static_cast<uint8_t *> (msg);

        size_t cnt = msg_size / std::tuple_size<detail::mask_t>::value;
        for (size_t i = 0; i < cnt; ++i) {
            auto const &mask = detail::create_mask (state.state ());
            state.incrementSequence ();

            for (size_t j = 0; j < mask.size (); ++j) {
                m[j] ^= mask[j];
            }
            m += mask.size ();
        }

        size_t remain = msg_size - (cnt * std::tuple_size<detail::mask_t>::value);
        if (0 < remain) {
            auto const &mask = detail::create_mask (state.state ());
            state.incrementSequence ();

            for (size_t i = 0; i < remain; ++i) {
                m[i] ^= mask[i];
            }
        }
    }

    /// @brief Applies ChaCha20.
    /// @tparam State_ The state type
    /// @param state
    /// @param result
    /// @param msg
    /// @param msg_size
    /// @param offset
    template<typename State_>
    void apply (State_ &state, void *result, const void *msg, size_t msg_size, size_t offset) {
        auto out = static_cast<uint8_t *> (result);
        auto in  = static_cast<const uint8_t *> (msg);
        auto end = in + msg_size;

        state.setSequence (detail::offset_to_sequence (offset));

        auto mask = detail::create_mask (state.state ());

        auto i = static_cast<size_t> (offset % mask.size ());
        while (in < end) {
            *out++ = *in++ ^ mask[i++];
            if (mask.size () <= i) {
                state.incrementSequence ();
                mask = detail::create_mask (state.state ());
                i    = 0;
            }
        }
    }

    /// @brief Applies ChaCha20.
    /// @tparam State_ The state type
    /// @param state
    /// @param msg
    /// @param msg_size
    /// @param offset
    template<typename State_>
    void apply (State_ &state, void *msg, size_t msg_size, size_t offset) {
        auto *m   = static_cast<uint8_t *> (msg);
        auto *end = m + msg_size;

        state.setSequence (detail::offset_to_sequence (offset));

        auto mask = create_mask (state.state ());

        auto i = static_cast<size_t> (offset % mask.size ());
        while (m < end) {
            *m++ ^= mask[i++];
            if (mask.size () <= i) {
                state.incrementSequence ();
                mask = detail::create_mask (state.state ());
                i    = 0;
            }
        }
    }
}  // namespace ChaCha
