/* -*- mode: c++; coding: utf-8 -*- */
/*
 * chacha20.cpp:
 *
 * Copyright (c) 2016 Masashi Fujita
 */
#include <sys/types.h>
#include <stdint.h>
#include <chacha20.hpp>

#ifdef HAVE_CONFIG_HPP
#   include "config.hpp"
#endif

#ifdef HAVE_SSE3
#   include <xmmintrin.h>
#   include <emmintrin.h>
#endif

namespace {
    inline uint32_t asUInt32 (const void *data) {
        const uint8_t * p = static_cast<const uint8_t *> (data) ;
        return ( (static_cast<uint32_t> (p [0]) <<  0)
               | (static_cast<uint32_t> (p [1]) <<  8)
               | (static_cast<uint32_t> (p [2]) << 16)
               | (static_cast<uint32_t> (p [3]) << 24)) ;
    }

    inline uint64_t asUInt64 (const void *data) {
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
        uint32_t rot (uint32_t v) {
            return (v << N_) | (v >> (32 - N_)) ;
        }

#ifdef HAVE_SSE3

    template <size_t N_>
        __m128i vrot (__m128i v) {
            __m128i t0 = _mm_slli_epi32 (v, N_) ;
            __m128i t1 = _mm_srli_epi32 (v, 32 - N_) ;
            return _mm_or_si128 (t0, t1) ;
        }

    template <>
        __m128i vrot<16> (__m128i v) {
            return _mm_shufflehi_epi16 ( _mm_shufflelo_epi16 (v, _MM_SHUFFLE (2, 3, 0, 1))
                                       , _MM_SHUFFLE (2, 3, 0, 1)) ;
        }
#endif

    const char sigma [] = "expand 32-byte k" ;
    const char tau   [] = "expand 16-byte k" ;

    using mask_t = std::array<uint8_t, 64> ;

    constexpr size_t offset_to_sequence (size_t offset) {
        return offset / std::tuple_size<mask_t>::value ;
    }

    mask_t  create_mask (const std::array<uint32_t, 16> &state) {
        std::array<uint32_t, 16>    x { state } ;
        const int32_t   NUM_ROUNDS = 20 ;
        static_assert ((NUM_ROUNDS % 2) == 0, "# of ROUNDS should be a multiple of 2.") ;

#ifdef HAVE_SSE3
        __m128i     v0orig = _mm_loadu_si128 ((const __m128i *)&state [ 0]) ;
        __m128i     v1orig = _mm_loadu_si128 ((const __m128i *)&state [ 4]) ;
        __m128i     v2orig = _mm_loadu_si128 ((const __m128i *)&state [ 8]) ;
        __m128i     v3orig = _mm_loadu_si128 ((const __m128i *)&state [12]) ;

        __m128i     v0 = v0orig ;
        __m128i     v1 = v1orig ;
        __m128i     v2 = v2orig ;
        __m128i     v3 = v3orig ;

        for (int_fast32_t i = 0 ; i < (NUM_ROUNDS / 2) ; ++i) {
            //  3  2  1  0
            //  7  6  5  4
            // 11 10  9  8
            // 15 14 13 12
            v0 = _mm_add_epi32 (v0, v1) ; v3 = vrot<16> (_mm_xor_si128 (v3, v0)) ;
            v2 = _mm_add_epi32 (v2, v3) ; v1 = vrot<12> (_mm_xor_si128 (v1, v2)) ;
            v0 = _mm_add_epi32 (v0, v1) ; v3 = vrot< 8> (_mm_xor_si128 (v3, v0)) ;
            v2 = _mm_add_epi32 (v2, v3) ; v1 = vrot< 7> (_mm_xor_si128 (v1, v2)) ;

            v1 = _mm_shuffle_epi32 (v1, _MM_SHUFFLE (0, 3, 2, 1)) ;
            v2 = _mm_shuffle_epi32 (v2, _MM_SHUFFLE (1, 0, 3, 2)) ;
            v3 = _mm_shuffle_epi32 (v3, _MM_SHUFFLE (2, 1, 0, 3)) ;
            //  3  2  1  0
            //  4  7  6  5
            //  9  8 11 10
            // 14 13 12 15

            v0 = _mm_add_epi32 (v0, v1) ; v3 = vrot<16> (_mm_xor_si128 (v3, v0)) ;
            v2 = _mm_add_epi32 (v2, v3) ; v1 = vrot<12> (_mm_xor_si128 (v1, v2)) ;
            v0 = _mm_add_epi32 (v0, v1) ; v3 = vrot< 8> (_mm_xor_si128 (v3, v0)) ;
            v2 = _mm_add_epi32 (v2, v3) ; v1 = vrot< 7> (_mm_xor_si128 (v1, v2)) ;

            v1 = _mm_shuffle_epi32 (v1, _MM_SHUFFLE (2, 1, 0, 3)) ;
            v2 = _mm_shuffle_epi32 (v2, _MM_SHUFFLE (1, 0, 3, 2)) ;
            v3 = _mm_shuffle_epi32 (v3, _MM_SHUFFLE (0, 3, 2, 1)) ;
            //  3  2  1  0
            //  7  6  5  4
            // 11 10  9  8
            // 15 14 13 12
        }
        v0 = _mm_add_epi32 (v0, v0orig) ;
        v1 = _mm_add_epi32 (v1, v1orig) ;
        v2 = _mm_add_epi32 (v2, v2orig) ;
        v3 = _mm_add_epi32 (v3, v3orig) ;

        mask_t result ;
        {
            _mm_storeu_si128 ((__m128i *)&result [ 0], v0) ;
            _mm_storeu_si128 ((__m128i *)&result [16], v1) ;
            _mm_storeu_si128 ((__m128i *)&result [32], v2) ;
            _mm_storeu_si128 ((__m128i *)&result [48], v3) ;
        }
        return result ;

#else   /* not HAVE_SSE3 */
        auto quarter_round = [&x](uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
            x [a] += x [b] ; x [d] = rot<16> (x [d] ^ x [a]) ;
            x [c] += x [d] ; x [b] = rot<12> (x [b] ^ x [c]) ;
            x [a] += x [b] ; x [d] = rot< 8> (x [d] ^ x [a]) ;
            x [c] += x [d] ; x [b] = rot< 7> (x [b] ^ x [c]) ;
        } ;

        for (int_fast32_t i = 0 ; i < (NUM_ROUNDS / 2) ; ++i) {
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
#endif  /* not HAVE_SSE3 */
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

        size_t cnt = msglen / std::tuple_size<mask_t>::value ;
        for (size_t i = 0 ; i < cnt ; ++i) {
            auto const &    mask = create_mask (state.state ()) ;
            state.incrementSequence () ;

            for (size_t i = 0 ; i < mask.size () ; ++i) {
                out [i] = in [i] ^ mask [i] ;
            }
            out += mask.size () ;
            in += mask.size () ;
        }
        size_t remain = msglen - (cnt * std::tuple_size<mask_t>::value) ;
        if (0 < remain) {
            auto const &    mask = create_mask (state.state ()) ;
            state.incrementSequence () ;

            for (size_t i = 0 ; i < remain ; ++i) {
                out [i] = in [i] ^ mask [i] ;
            }
        }
    }

    void apply (ChaCha::State &state, void *msg, size_t msglen) {
        if (msg == nullptr || msglen == 0) {
            return ;
        }
        auto    m = static_cast<uint8_t *> (msg) ;

        size_t cnt = msglen / std::tuple_size<mask_t>::value ;
        for (size_t i = 0 ; i < cnt ; ++i) {
            auto const &    mask = create_mask (state.state ()) ;
            state.incrementSequence () ;

            for (size_t i = 0 ; i < mask.size () ; ++i) {
                m [i] ^= mask [i] ;
            }
            m += mask.size () ;
        }
        size_t remain = msglen - (cnt * std::tuple_size<mask_t>::value) ;
        if (0 < remain) {
            auto const &    mask = create_mask (state.state ()) ;
            state.incrementSequence () ;

            for (size_t i = 0 ; i < remain ; ++i) {
                m [i] ^= mask [i] ;
            }
        }
    }

    void apply (State &state, void *result, const void *msg, size_t msglen, size_t offset) {
        auto out = static_cast<uint8_t *> (result) ;
        auto in = static_cast<const uint8_t *> (msg) ;
        auto end = in + msglen ;

        state.setSequence (offset_to_sequence (offset)) ;

        auto mask = create_mask (state.state ()) ;

        size_t i = static_cast<size_t> (offset % mask.size ()) ;
        while (in < end) {
            *out++ = *in++ ^ mask [i++] ;
            if (mask.size () <= i) {
                state.incrementSequence () ;
                mask = create_mask (state.state ()) ;
                i = 0 ;
            }
        }
    }

    void apply (State &state, void *msg, size_t msglen, size_t offset) {
        auto m = static_cast<uint8_t *> (msg) ;
        auto end = m + msglen ;

        state.setSequence (offset_to_sequence (offset)) ;

        auto mask = create_mask (state.state ()) ;

        size_t i = static_cast<size_t> (offset % mask.size ()) ;
        while (m < end) {
            *m++ ^= mask [i++] ;
            if (mask.size () <= i) {
                state.incrementSequence () ;
                mask = create_mask (state.state ()) ;
                i = 0 ;
            }
        }
    }
}
