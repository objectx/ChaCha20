/* -*- mode: c++; coding: utf-8 -*- */
/*
 * chacha20.cpp:
 *
 * Copyright (c) 2016 Masashi Fujita
 */
#include <chacha20.hpp>
#include <stdint.h>
#include <sys/types.h>

#ifdef HAVE_CONFIG_HPP
#    include "config.hpp"
#endif

#ifdef HAVE_SSE3
#    include <emmintrin.h>
#    include <xmmintrin.h>
#endif

namespace ChaCha::detail {

    template<size_t N_>
    uint32_t rot (uint32_t v) {
        return (v << N_) | (v >> (32u - N_));
    }

#ifdef HAVE_SSE3

    template<size_t N_>
    __m128i vrot (__m128i v) {
        __m128i t0 = _mm_slli_epi32 (v, N_);
        __m128i t1 = _mm_srli_epi32 (v, 32 - N_);
        return _mm_or_si128 (t0, t1);
    }

    template<>
    __m128i vrot<16> (__m128i v) {
        return _mm_shufflehi_epi16 (_mm_shufflelo_epi16 (v, _MM_SHUFFLE (2, 3, 0, 1)), _MM_SHUFFLE (2, 3, 0, 1));
    }
#endif

    mask_t create_mask (const std::array<uint32_t, 16> &state) {
        std::array<uint32_t, 16> x {state};
        const int32_t            NUM_ROUNDS = 20;
        static_assert ((NUM_ROUNDS % 2) == 0, "# of ROUNDS should be a multiple of 2.");

#ifdef HAVE_SSE3
        __m128i v0orig = _mm_loadu_si128 ((const __m128i *)&state[0]);
        __m128i v1orig = _mm_loadu_si128 ((const __m128i *)&state[4]);
        __m128i v2orig = _mm_loadu_si128 ((const __m128i *)&state[8]);
        __m128i v3orig = _mm_loadu_si128 ((const __m128i *)&state[12]);

        __m128i v0 = v0orig;
        __m128i v1 = v1orig;
        __m128i v2 = v2orig;
        __m128i v3 = v3orig;

        for (int_fast32_t i = 0; i < (NUM_ROUNDS / 2); ++i) {
            //  3  2  1  0
            //  7  6  5  4
            // 11 10  9  8
            // 15 14 13 12
            v0 = _mm_add_epi32 (v0, v1);
            v3 = vrot<16> (_mm_xor_si128 (v3, v0));
            v2 = _mm_add_epi32 (v2, v3);
            v1 = vrot<12> (_mm_xor_si128 (v1, v2));
            v0 = _mm_add_epi32 (v0, v1);
            v3 = vrot<8> (_mm_xor_si128 (v3, v0));
            v2 = _mm_add_epi32 (v2, v3);
            v1 = vrot<7> (_mm_xor_si128 (v1, v2));

            v1 = _mm_shuffle_epi32 (v1, _MM_SHUFFLE (0, 3, 2, 1));
            v2 = _mm_shuffle_epi32 (v2, _MM_SHUFFLE (1, 0, 3, 2));
            v3 = _mm_shuffle_epi32 (v3, _MM_SHUFFLE (2, 1, 0, 3));
            //  3  2  1  0
            //  4  7  6  5
            //  9  8 11 10
            // 14 13 12 15

            v0 = _mm_add_epi32 (v0, v1);
            v3 = vrot<16> (_mm_xor_si128 (v3, v0));
            v2 = _mm_add_epi32 (v2, v3);
            v1 = vrot<12> (_mm_xor_si128 (v1, v2));
            v0 = _mm_add_epi32 (v0, v1);
            v3 = vrot<8> (_mm_xor_si128 (v3, v0));
            v2 = _mm_add_epi32 (v2, v3);
            v1 = vrot<7> (_mm_xor_si128 (v1, v2));

            v1 = _mm_shuffle_epi32 (v1, _MM_SHUFFLE (2, 1, 0, 3));
            v2 = _mm_shuffle_epi32 (v2, _MM_SHUFFLE (1, 0, 3, 2));
            v3 = _mm_shuffle_epi32 (v3, _MM_SHUFFLE (0, 3, 2, 1));
            //  3  2  1  0
            //  7  6  5  4
            // 11 10  9  8
            // 15 14 13 12
        }
        v0 = _mm_add_epi32 (v0, v0orig);
        v1 = _mm_add_epi32 (v1, v1orig);
        v2 = _mm_add_epi32 (v2, v2orig);
        v3 = _mm_add_epi32 (v3, v3orig);

        mask_t result;
        {
            _mm_storeu_si128 ((__m128i *)&result[0], v0);
            _mm_storeu_si128 ((__m128i *)&result[16], v1);
            _mm_storeu_si128 ((__m128i *)&result[32], v2);
            _mm_storeu_si128 ((__m128i *)&result[48], v3);
        }
        return result;

#else /* not HAVE_SSE3 */
        auto quarter_round = [&x] (uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
            x[a] += x[b];
            x[d] = rot<16> (x[d] ^ x[a]);
            x[c] += x[d];
            x[b] = rot<12> (x[b] ^ x[c]);
            x[a] += x[b];
            x[d] = rot<8> (x[d] ^ x[a]);
            x[c] += x[d];
            x[b] = rot<7> (x[b] ^ x[c]);
        };

        for (int_fast32_t i = 0; i < (NUM_ROUNDS / 2); ++i) {
            quarter_round (0, 4, 8, 12);
            quarter_round (1, 5, 9, 13);
            quarter_round (2, 6, 10, 14);
            quarter_round (3, 7, 11, 15);
            quarter_round (0, 5, 10, 15);
            quarter_round (1, 6, 11, 12);
            quarter_round (2, 7, 8, 13);
            quarter_round (3, 4, 9, 14);
        }
        for (int_fast32_t i = 0; i < x.size (); ++i) {
            x[i] += state[i];
        }

        mask_t result;
        for (int_fast32_t i = 0; i < x.size (); ++i) {
            auto v            = x[i];
            result[4 * i + 0] = static_cast<uint8_t> (v >> 0);
            result[4 * i + 1] = static_cast<uint8_t> (v >> 8);
            result[4 * i + 2] = static_cast<uint8_t> (v >> 16);
            result[4 * i + 3] = static_cast<uint8_t> (v >> 24);
        }
        return result;
#endif /* not HAVE_SSE3 */
    }
}  // namespace ChaCha::detail

  // namespace ChaCha
