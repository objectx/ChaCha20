/* -*- mode: c++; coding: utf-8 -*- */
/*
 * chacha20.cpp:
 *
 * Copyright (c) 2016 Masashi Fujita
 */
#include <sys/types.h>
#include <stdint.h>
#include <chacha20.hpp>

namespace {
    constexpr uint32_t asUInt32 (const void *data) {
        const uint8_t * p = static_cast<const uint8_t *> (data) ;
        return ( (static_cast<uint32_t> (p [0]) <<  0)
               | (static_cast<uint32_t> (p [1]) <<  8)
               | (static_cast<uint32_t> (p [2]) << 16)
               | (static_cast<uint32_t> (p [3]) << 24)) ;
    }

    constexpr uint64_t asUInt64 (const void *data) {
        const uint8_t * p = static_cast<const uint8_t *> (data) ;
        return ( (static_cast<uint64_t> (p [0]) <<  0)
               | (static_cast<uint64_t> (p [1]) <<  8)
               | (static_cast<uint64_t> (p [2]) << 16)
               | (static_cast<uint64_t> (p [3]) << 24)
               | (static_cast<uint64_t> (p [4]) << 32)
               | (static_cast<uint64_t> (p [5]) << 40)
               | (static_cast<uint64_t> (p [6]) << 48)
               | (static_cast<uint64_t> (p [7]) << 56)) ;
    }

    template <size_t N_>
        constexpr uint32_t rot (uint32_t v) {
            return (v << N_) | (v >> (32 - N_)) ;
        }

#define QUARTERROUND(a,b,c,d) \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]),16); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]),12); \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]), 8); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]), 7);

    const char sigma [] = "expand 32-byte k" ;
    const char tau   [] = "expand 16-byte k" ;

    using mask_t = std::array<uint8_t, 64> ;

    mask_t  create_mask (const std::array<uint32_t, 16> &state) {
        std::array<uint32_t, 16>    x { state } ;
        const int32_t   NUM_ROUNDS = 8 ;

        auto quarter_round = [&x](uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
            x [a] += x [b] ; x [d] = rot<16> (x [d] ^ x [a]) ;
            x [c] += x [d] ; x [b] = rot<12> (x [b] ^ x [c]) ;
            x [a] += x [b] ; x [d] = rot< 8> (x [d] ^ x [a]) ;
            x [c] += x [d] ; x [b] = rot< 7> (x [b] ^ x [c]) ;
        } ;

        for (int_fast32_t i = 0 ; i < NUM_ROUNDS ; i += 2) {
            quarter_round (0, 4,  8, 12);
            quarter_round (1, 5,  9, 13);
            quarter_round (2, 6, 10, 14);
            quarter_round (3, 7, 11, 15);
            quarter_round (0, 5, 10, 15);
            quarter_round (1, 6, 11, 12);
            quarter_round (2, 7,  8, 13);
            quarter_round (3, 4,  9, 14);
        }
        for (int_fast32_t i = 0 ; i < x.size () ; ++i) {
            x [i] += state [i] ;
        }

        mask_t  result ;
        for (int_fast32_t i = 0 ; i < x.size () ; ++i) {
            auto v = x [i] ;
            result [4 * i + 0] = static_cast<uint8_t> (v >>  0) ;
            result [4 * i + 1] = static_cast<uint8_t> (v >>  8) ;
            result [4 * i + 2] = static_cast<uint8_t> (v >> 16) ;
            result [4 * i + 3] = static_cast<uint8_t> (v >> 24) ;
        }
        return result ;
    }
}

namespace ChaCha {

    State & State::setKey (const void *key, size_t size) {
        std::array<uint8_t, 32> K ;
        if (K.size () < size) {
            size = K.size () ;
        }
        K.fill (0) ;
        ::memcpy (K.data (), key, size) ;
        auto const *    k = K.data () ;
        if (size <= 16) {
            state_ [ 0] = asUInt32 (tau +  0) ;
            state_ [ 1] = asUInt32 (tau +  4) ;
            state_ [ 2] = asUInt32 (tau +  8) ;
            state_ [ 3] = asUInt32 (tau + 12) ;
            state_ [ 4] = asUInt32 (k +  0) ;
            state_ [ 5] = asUInt32 (k +  4) ;
            state_ [ 6] = asUInt32 (k +  8) ;
            state_ [ 7] = asUInt32 (k + 12) ;
            state_ [ 8] = asUInt32 (k +  0) ;
            state_ [ 9] = asUInt32 (k +  4) ;
            state_ [10] = asUInt32 (k +  8) ;
            state_ [11] = asUInt32 (k + 12) ;
        }
        else {
            state_ [ 0] = asUInt32 (sigma +  0) ;
            state_ [ 1] = asUInt32 (sigma +  4) ;
            state_ [ 2] = asUInt32 (sigma +  8) ;
            state_ [ 3] = asUInt32 (sigma + 12) ;
            state_ [ 4] = asUInt32 (k +  0) ;
            state_ [ 5] = asUInt32 (k +  4) ;
            state_ [ 6] = asUInt32 (k +  8) ;
            state_ [ 7] = asUInt32 (k + 12) ;
            state_ [ 8] = asUInt32 (k + 16) ;
            state_ [ 9] = asUInt32 (k + 20) ;
            state_ [10] = asUInt32 (k + 24) ;
            state_ [11] = asUInt32 (k + 28) ;
        }
        return *this ;
    }


    void apply (ChaCha::State &state, void *result, const void *msg, size_t msglen) {
        if (msg == nullptr || msglen == 0) {
            return ;
        }
        auto    out = static_cast<uint8_t *> (result) ;
        auto    in = static_cast<const uint8_t *> (msg) ;

        while (true) {
            auto const &    mask = create_mask (state.state ()) ;
            state.incrementSequence () ;
            if (msglen <= mask.size ()) {
                for (size_t i = 0 ; i < msglen ; ++i) {
                    out [i] = in [i] ^ mask [i] ;
                }
                return ;
            }
            for (size_t i = 0 ; i < mask.size () ; ++i) {
                out [i] = in [i] ^ mask [i] ;
            }
            in += mask.size () ;
            out += mask.size () ;
            msglen -= mask.size () ;
        }
    }
}
