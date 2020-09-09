/* -*- mode: C++; coding: utf-8 -*- */
/*
 * chacha20.hpp
 *
 * Copyright (c) 2016 Masashi Fujita
 */
#pragma once
#ifndef chacha20_hpp__EEC06027_E536_4F54_A7C7_1EA72ADB4A38
#define chacha20_hpp__EEC06027_E536_4F54_A7C7_1EA72ADB4A38  1

#include <sys/types.h>
#include <cstdint>
#include <array>

namespace ChaCha {

    class State final {
    private:
        static const std::array<uint32_t, 4>    sigma_ ;
        static const std::array<uint32_t, 4>    tau_ ;
    private:
        std::array<uint32_t, 16>    state_ ;
    public:
#pragma clang diagnostic push
#pragma ide diagnostic ignored "cppcoreguidelines-pro-type-member-init"
        State () {
            state_.fill (0) ;
        }

        State (const void *key, size_t size, uint64_t iv) {
            state_.fill (0) ;
            this->setKey (key, size) ;
            this->setInitialVector (iv) ;
        }

        State (const void *key, size_t size) {
            state_.fill (0) ;
            this->setKey (key, size) ;
        }

        State (const State &src) = default;
#pragma clang diagnostic pop

        State &     setKey (const void *key, size_t size) ;

        State &     setInitialVector (uint64_t iv) {
            state_ [12] = 0 ;
            state_ [13] = 0 ;
            state_ [14] = static_cast<uint32_t> (iv >>  0u) ;
            state_ [15] = static_cast<uint32_t> (iv >> 32u) ;
            return *this ;
        }

        [[nodiscard]] uint64_t    getSequence () const {
            return ( (static_cast<uint64_t> (state_ [12]) <<  0u)
                   | (static_cast<uint64_t> (state_ [13]) << 32u)) ;
        }

        State &     setSequence (uint64_t value) {
            state_ [12] = static_cast<uint32_t> (value >>  0u) ;
            state_ [13] = static_cast<uint32_t> (value >> 32u) ;
            return *this ;
        }

        State &     incrementSequence () {
            if ((state_ [12] += 1) == 0) {
                state_ [13] += 1 ;
                /* stopping at 2^70 bytes per nonce is user's responsibility */
            }
            return *this ;
        }

        State & assign (const State &src) {
            state_ = src.state_ ;
            return *this ;
        }

        State & operator = (const State &src) {
            state_ = src.state_ ;
            return *this ;
        }

        [[nodiscard]] auto const &    state () const {
            return state_ ;
        }
    } ;

    /**
     * Applies ChaCha20.
     */
    void apply (State &state, void *result, const void *msg, size_t msg_size) ;
    /**
     * Applies ChaCha20 (in place).
     */
    void apply (State &state, void *msg, size_t msg_size) ;

    /**
     * Applies ChaCha20.
     */
    void apply (State &state, void *result, const void *msg, size_t msg_size, size_t offset) ;
    /**
     * Applies ChaCha20 (in place).
     */
    void apply (State &state, void *msg, size_t msg_size, size_t offset) ;
}

#endif /* chacha20_hpp__EEC06027_E536_4F54_A7C7_1EA72ADB4A38 */
