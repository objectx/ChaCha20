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
                const auto &    expected = encode (ctx, "A") ;
                const auto &    actual = encode (S, "A") ;
                REQUIRE (expected.size () == actual.size ()) ;
                REQUIRE (expected == actual) ;
            }
            SECTION ("Encrypt \"The ninja warrior are the immoratal murder machines.\"") {
                const std::string   src { "The ninja warrior are the immoratal murder machines." };
                const auto &    expected = encode (ctx, src) ;
                const auto &    actual = encode (S, src) ;
                REQUIRE (expected.size () == actual.size ()) ;
                REQUIRE (expected == actual) ;
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
                const auto &    expected = encode (ctx, "A") ;
                const auto &    actual = encode (S, "A") ;
                REQUIRE (expected.size () == actual.size ()) ;
                REQUIRE (expected == actual) ;
            }
            SECTION ("Encrypt \"The ninja warrior are the immoratal murder machines.\"") {
                const std::string   src { "The ninja warrior are the immoratal murder machines." };
                const auto &    expected = encode (ctx, src) ;
                const auto &    actual = encode (S, src) ;
                REQUIRE (expected.size () == actual.size ()) ;
                REQUIRE (expected == actual) ;
            }
        }
    }
}
