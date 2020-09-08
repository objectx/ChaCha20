//
// Created by Masashi Fujita on 2016/05/06.
//
// Copyright (c) 2016 Masashi Fujita.
//

#include "chacha20.hpp"

#include "doctest-rapidcheck.hpp"

#include <array>
#include <vector>
#include <string>

#include <doctest/doctest.h>

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
    template <typename It_>
        std::string concat (It_ b, It_ e) {
            size_t sz = 0;
            for (auto it = b; it != e; ++it) {
                sz += it->size ();
            }
            std::string result;
            result.reserve (sz);
            for (auto it = b; it != e; ++it) {
                result += *it;
            }
            return result;
        }
}

TEST_CASE ("Test with small key") {
    SUBCASE ("with small key") {
        ECRYPT_ctx ctx;
        memset (&ctx, 0, sizeof (ctx));
        const std::string key { "0123456789abcdef" };
        REQUIRE (8 * key.size () == 128);
        ECRYPT_keysetup (&ctx, reinterpret_cast<const u8 *> (key.data ()), 128, 0);
        std::array<uint8_t, 8> iv;
        iv.fill (0);
        ECRYPT_ivsetup (&ctx, static_cast<const u8 *> (iv.data ()));
        ChaCha::State S { key.data (), key.size (), 0 };

        SUBCASE ("Compare states") {
            auto const        &state = S.state ();
            for (int_fast32_t i = 0 ; i < state.size () ; ++i) {
                CAPTURE (i);
                REQUIRE (state[i] == ctx.input[i]);
            }
        }
        SUBCASE ("Encrypt strings") {
            SUBCASE ("Encrypt \"A\"") {
                auto const &expected = encode (ctx, "A");
                auto const &actual   = encode (S, "A");
                REQUIRE (expected.size () == actual.size ());
                REQUIRE (expected == actual);
            }
            SUBCASE ("Encrypt \"The ninja warrior are the immortal murder machines.\"") {
                const std::string src { "The ninja warrior are the immortal murder machines." };
                auto const &expected = encode (ctx, src);
                auto const &actual   = encode (S, src);
                REQUIRE (expected.size () == actual.size ());
                REQUIRE (expected == actual);
            }
            SUBCASE ("Encrypt \"The ninja warrior are the immortal murder machines.\" (splitted)") {
                const std::string src { "The ninja warrior are the immortal murder machines." };
                auto              off = src.size () / 2;
                auto const &expected = encode (ctx, src);
                auto       &&a0      = encode (S, src.substr (0, off), 0);
                auto const &a1       = encode (S, src.substr (off), off);
                a0.insert (a0.end (), a1.cbegin (), a1.cend ());
                REQUIRE (expected.size () == a0.size ());
                REQUIRE (expected == a0);
            }
        }
    }
}

TEST_CASE ("Test with large key") {
    SUBCASE ("with large key") {
        ECRYPT_ctx  ctx ;
        memset (&ctx, 0, sizeof (ctx)) ;
        std::string key { "0123456789abcdef0123456789abcdef" };
        REQUIRE (8 * key.size () == 256) ;
        ECRYPT_keysetup (&ctx, reinterpret_cast<const u8 *> (key.data ()), 256, 0) ;
        std::array<uint8_t, 8>  iv ;
        iv.fill (0) ;
        ECRYPT_ivsetup (&ctx, static_cast<const u8 *> (iv.data ())) ;
        ChaCha::State   S { key.data (), key.size (), 0 } ;

        SUBCASE ("Compare states") {
            auto const &    state = S.state () ;
            for (int_fast32_t i = 0 ; i < state.size () ; ++i) {
                CAPTURE (i) ;
                REQUIRE (state [i] == ctx.input [i]) ;
            }
        }
        SUBCASE ("Encrypt strings") {
            SUBCASE ("Encrypt \"A\"") {
                auto const &    expected = encode (ctx, "A") ;
                auto const &    actual = encode (S, "A") ;
                REQUIRE (expected.size () == actual.size ()) ;
                REQUIRE (expected == actual) ;
            }
            SUBCASE ("Encrypt \"The ninja warrior are the immortal murder machines.\"") {
                const std::string   src { "The ninja warrior are the immortal murder machines." };
                auto const &    expected = encode (ctx, src) ;
                auto const &    actual = encode (S, src) ;
                REQUIRE (expected.size () == actual.size ()) ;
                REQUIRE (expected == actual) ;
            }
            SUBCASE ("Encrypt \"The ninja warrior are the immortal murder machines.\" (splitted)") {
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

TEST_CASE ("property") {
    rc::prop("roundtrip", [](){
        auto const key_size = *rc::gen::element(16, 32);
        auto const &key = *rc::gen::container<std::vector<char>> (key_size, rc::gen::arbitrary<char>());
        auto const &plain = *rc::gen::scale(128, rc::gen::arbitrary<std::string>());

        RC_ASSERT (key.size () == 16 || key.size () == 32);
        ECRYPT_ctx  ctx ;
        memset (&ctx, 0, sizeof (ctx)) ;

        ECRYPT_keysetup (&ctx, reinterpret_cast<const u8 *> (key.data ()), 8u * key.size (), 0) ;
        std::array<uint8_t, 8>  iv ;
        iv.fill (0) ;
        ECRYPT_ivsetup (&ctx, static_cast<const u8 *> (iv.data ())) ;
        ChaCha::State   S { key.data (), key.size (), 0 } ;

        auto const &    state = S.state () ;
        for (int_fast32_t i = 0 ; i < state.size () ; ++i) {
            RC_ASSERT (state [i] == ctx.input [i]) ;
        }
        auto const &expected = encode(ctx, plain);
        auto const &actual = encode(S, plain);
        RC_ASSERT (std::equal(expected.begin (), expected.end (), actual.begin(), actual.end(),
                              [](auto a, auto b) { return a == b; }));
    });
    rc::prop ("splitted inputs", [](){
        auto const    key_size = *rc::gen::element (16, 32).as ("key_size");
        auto const    &key     = *rc::gen::container<std::vector<char>> (key_size, rc::gen::arbitrary<char> ()).as ("key");
        ChaCha::State S { key.data (), key.size () };
        auto const    &inputs  = *rc::gen::container<std::vector<std::string>> (rc::gen::string<std::string> ()).as ("inputs");
        auto const &plain = concat (inputs.begin (), inputs.end ());
        std::string expected;
        expected.reserve (plain.size ());
        {
            auto const &e = encode (S, plain);
            std::copy (e.begin (), e.end (), std::back_inserter (expected));
        }
        std::string actual;
        actual.reserve (plain.size ());
        size_t          off = 0;
        for (auto const &s : inputs) {
            auto const &e = encode (S, s, off);
            off += s.size ();

            std::copy (e.begin (), e.end (), std::back_inserter (actual));
        }
        RC_TAG(inputs.size (), plain.size ());
        RC_ASSERT (expected.size () == actual.size ());
        RC_ASSERT (expected == actual);
    });
}
