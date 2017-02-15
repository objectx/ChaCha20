//
// Created by Masashi Fujita on 2016/05/06.
//
// Copyright (c) 2016 Polyphony Digital Inc.
//

#include <array>
#include "catch.hpp"
#include "chacha20.hpp"

extern "C" {
#include "ecrypt-sync.h"
}

namespace {
    std::vector<uint8_t>    encode (ECRYPT_ctx &ctx, const std::string &s) {
        std::vector<uint8_t>    result ;
        result.resize (s.size ()) ;
        ECRYPT_encrypt_bytes (&ctx, (const u8 *)s.data (), (u8 *)result.data (), s.size ()) ;
        return result ;
    }

    std::vector<uint8_t>    encode (ChaCha::State &state, const std::string &s) {
        std::vector<uint8_t>    result ;
        result.resize (s.size ()) ;
        ChaCha::apply (state, result.data (), s.data (), s.size ()) ;
        return result ;
    }

    std::vector<uint8_t>    encode (ChaCha::State &state, const std::string &s, size_t offset) {
        std::vector<uint8_t>    result ;
        result.resize (s.size ()) ;
        ChaCha::apply (state, result.data (), s.data (), s.size (), offset) ;
        return result ;
    }
}

TEST_CASE ("Encrypt empty bytes", "[chacha]") {
    SECTION ("with small key") {
        ECRYPT_ctx  ctx ;
        memset (&ctx, 0, sizeof (ctx)) ;
        const std::string key { "0123456789abcdef" };
        REQUIRE (8 * key.size () == 128) ;
        ECRYPT_keysetup (&ctx, reinterpret_cast<const u8 *> (key.data ()), 128, 0) ;
        std::array<uint8_t, 8>  iv ;
        iv.fill (0) ;
        ECRYPT_ivsetup (&ctx, static_cast<const u8 *> (iv.data ())) ;
        ChaCha::State   S { key.data (), key.size (), 0 } ;

        auto const &    state = S.state () ;
        for (int_fast32_t i = 0 ; i < state.size () ; ++i) {
            CAPTURE (i) ;
            REQUIRE (state [i] == ctx.input [i]) ;
        }
        SECTION ("Encrypt strings") {
            SECTION ("Encrypt \"A\"") {
                auto const &    expected = encode (ctx, "A") ;
                auto const &    actual = encode (S, "A") ;
                REQUIRE (expected.size () == actual.size ()) ;
                REQUIRE (expected == actual) ;
            }
            SECTION ("Encrypt \"The ninja warrior are the immortal murder machines.\"") {
                const std::string   src { "The ninja warrior are the immortal murder machines." };
                auto const &    expected = encode (ctx, src) ;
                auto const &    actual = encode (S, src) ;
                REQUIRE (expected.size () == actual.size ()) ;
                REQUIRE (expected == actual) ;
            }
            SECTION ("Encrypt \"The ninja warrior are the immortal murder machines.\" (splitted)") {
                const std::string   src { "The ninja warrior are the immortal murder machines." };
                auto off = src.size () / 2 ;
                auto const &    expected = encode (ctx, src) ;
                auto &&    a0 = encode (S, src.substr (0, off), 0) ;
                auto const &    a1 = encode (S, src.substr (off), off) ;
                a0.insert (a0.end (), a1.cbegin (), a1.cend ()) ;
                REQUIRE (expected.size () == a0.size ()) ;
                REQUIRE (expected == a0) ;
            }
        }
    }
    SECTION ("with large key") {
        ECRYPT_ctx  ctx ;
        memset (&ctx, 0, sizeof (ctx)) ;
        std::string key { "0123456789abcdef0123456789abcdef" };
        REQUIRE (8 * key.size () == 256) ;
        ECRYPT_keysetup (&ctx, reinterpret_cast<const u8 *> (key.data ()), 256, 0) ;
        std::array<uint8_t, 8>  iv ;
        iv.fill (0) ;
        ECRYPT_ivsetup (&ctx, static_cast<const u8 *> (iv.data ())) ;
        ChaCha::State   S { key.data (), key.size (), 0 } ;

        auto const &    state = S.state () ;
        for (int_fast32_t i = 0 ; i < state.size () ; ++i) {
            CAPTURE (i) ;
            REQUIRE (state [i] == ctx.input [i]) ;
        }
        SECTION ("Encrypt strings") {
            SECTION ("Encrypt \"A\"") {
                auto const &    expected = encode (ctx, "A") ;
                auto const &    actual = encode (S, "A") ;
                REQUIRE (expected.size () == actual.size ()) ;
                REQUIRE (expected == actual) ;
            }
            SECTION ("Encrypt \"The ninja warrior are the immortal murder machines.\"") {
                const std::string   src { "The ninja warrior are the immortal murder machines." };
                auto const &    expected = encode (ctx, src) ;
                auto const &    actual = encode (S, src) ;
                REQUIRE (expected.size () == actual.size ()) ;
                REQUIRE (expected == actual) ;
            }
            SECTION ("Encrypt \"The ninja warrior are the immortal murder machines.\" (splitted)") {
                const std::string   src { "The ninja warrior are the immortal murder machines." };
                auto off = src.size () / 2 ;
                auto const &    expected = encode (ctx, src) ;
                auto &&    a0 = encode (S, src.substr (0, off), 0) ;
                auto const &    a1 = encode (S, src.substr (off), off) ;
                a0.insert (a0.end (), a1.cbegin (), a1.cend ()) ;
                REQUIRE (expected.size () == a0.size ()) ;
                REQUIRE (expected == a0) ;
            }
        }
    }
}
