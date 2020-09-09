/*
 * Copyright (c) 2020 Masashi Fujita
 */

#include <chacha20/apply.hpp>
#include <chacha20/detail.hpp>
#include <chacha20/state-rfc7539.hpp>

#include "doctest-rapidcheck.hpp"

#include <array>
#include <string>
#include <vector>

#include <doctest/doctest.h>
#include <fmt/format.h>

namespace {
    std::vector<uint8_t> encode (ChaCha::RFC7539::State &state, const std::string &s) {
        std::vector<uint8_t> result;
        result.resize (s.size ());
        ChaCha::apply (state, result.data (), s.data (), s.size ());
        return result;
    }

    std::vector<uint8_t> encode (ChaCha::RFC7539::State &state, const std::string &s, size_t offset) {
        std::vector<uint8_t> result;
        result.resize (s.size ());
        ChaCha::apply (state, result.data (), s.data (), s.size (), offset);
        return result;
    }

    template<typename It_>
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
}  // namespace

#pragma clang diagnostic push
#pragma ide diagnostic ignored "readability-magic-numbers"
TEST_CASE ("Test ChaCha::RFC7539 with test vector") {
    SUBCASE ("check state") {
        std::string key;
        key.reserve (32);
        for (size_t i = 0; i < 32; ++i) {
            key.push_back (static_cast<char> (i));
        }
        std::string            nonce {0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4A, 0x00, 0x00, 0x00, 0x00};
        ChaCha::RFC7539::State S {key.data (), key.size (), nonce.data (), nonce.size ()};
        S.setSequence (1);
        auto const &state = S.state ();
        REQUIRE_EQ (state[0], 0x61707865u);
        REQUIRE_EQ (state[1], 0x3320646Eu);
        REQUIRE_EQ (state[2], 0x79622d32u);
        REQUIRE_EQ (state[3], 0x6B206574u);
        REQUIRE_EQ (state[4], 0x03020100u);
        REQUIRE_EQ (state[5], 0x07060504u);
        REQUIRE_EQ (state[6], 0x0B0A0908u);
        REQUIRE_EQ (state[7], 0x0F0E0D0Cu);
        REQUIRE_EQ (state[8], 0x13121110u);
        REQUIRE_EQ (state[9], 0x17161514u);
        REQUIRE_EQ (state[10], 0x1B1A1918u);
        REQUIRE_EQ (state[11], 0x1F1E1D1Cu);
        REQUIRE_EQ (state[12], 0x00000001u);
        REQUIRE_EQ (state[13], 0x09000000u);
        REQUIRE_EQ (state[14], 0x4A000000u);
        REQUIRE_EQ (state[15], 0x00000000u);
    }
    SUBCASE ("encode test vector") {
        std::string key;
        key.reserve (32);
        for (size_t i = 0; i < 32; ++i) {
            key.push_back (static_cast<char> (i));
        }
        std::string            nonce {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4A, 0x00, 0x00, 0x00, 0x00};
        ChaCha::RFC7539::State S {key.data (), key.size (), nonce.data (), nonce.size ()};
        S.setSequence (1);
        const std::array<uint8_t, 114> plain {
            /* 000 */ 0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
            /* 016 */ 0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
            /* 032 */ 0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
            /* 048 */ 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
            /* 064 */ 0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
            /* 080 */ 0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
            /* 096 */ 0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
            /* 112 */ 0x74, 0x2e};

        std::array<uint8_t, 114> expected {
            /* 0x00 */ 0x6E, 0x2E, 0x35, 0x9A, 0x25, 0x68, 0xF9, 0x80, 0x41, 0xBA, 0x07, 0x28, 0xDD, 0x0D, 0x69, 0x81,
            /* 0x10 */ 0xE9, 0x7E, 0x7A, 0xEC, 0x1D, 0x43, 0x60, 0xC2, 0x0A, 0x27, 0xAF, 0xCC, 0xFD, 0x9F, 0xAE, 0x0B,
            /* 0x20 */ 0xF9, 0x1B, 0x65, 0xC5, 0x52, 0x47, 0x33, 0xAB, 0x8F, 0x59, 0x3D, 0xAB, 0xCD, 0x62, 0xB3, 0x57,
            /* 0x30 */ 0x16, 0x39, 0xD6, 0x24, 0xE6, 0x51, 0x52, 0xAB, 0x8F, 0x53, 0x0C, 0x35, 0x9F, 0x08, 0x61, 0xD8,
            /* 0x40 */ 0x07, 0xCA, 0x0D, 0xBF, 0x50, 0x0D, 0x6A, 0x61, 0x56, 0xA3, 0x8E, 0x08, 0x8A, 0x22, 0xB6, 0x5E,
            /* 0x50 */ 0x52, 0xBC, 0x51, 0x4D, 0x16, 0xCC, 0xF8, 0x06, 0x81, 0x8C, 0xE9, 0x1A, 0xB7, 0x79, 0x37, 0x36,
            /* 0x60 */ 0x5A, 0xF9, 0x0B, 0xBF, 0x74, 0xA3, 0x5B, 0xE6, 0xB4, 0x0B, 0x8E, 0xED, 0xF2, 0x78, 0x5E, 0x42,
            /* 0x70 */ 0x87, 0x4D};
        std::array<uint8_t, 114> actual {};
        ChaCha::apply (S, actual.data (), plain.data (), plain.size ());
        for (size_t i = 0; i < actual.size (); ++i) {
            if (actual.at (i) != expected.at (i)) {
                FAIL (fmt::format (FMT_STRING ("mismatched at {0} ({1:#04x} vs {2:#04x})"), i, actual.at (i), expected.at (i)));
            }
        }
    }
}
#pragma clang diagnostic pop

TEST_CASE ("Test ChaCha::RFC7539 properties") {
    rc::prop ("splitted inputs", [] () {
        auto const  key_size = *rc::gen::element (16, 32).as ("key_size");
        auto const &key      = *rc::gen::container<std::vector<char>> (key_size, rc::gen::arbitrary<char> ()).as ("key");

        ChaCha::RFC7539::State S {key.data (), key.size ()};

        auto const &inputs = *rc::gen::container<std::vector<std::string>> (rc::gen::string<std::string> ()).as ("inputs");
        auto const &plain  = concat (inputs.begin (), inputs.end ());
        std::string expected;
        expected.reserve (plain.size ());
        {
            auto const &e = encode (S, plain);
            std::copy (e.begin (), e.end (), std::back_inserter (expected));
        }
        std::string actual;
        actual.reserve (plain.size ());
        size_t off = 0;
        for (auto const &s : inputs) {
            auto const &e = encode (S, s, off);
            off += s.size ();

            std::copy (e.begin (), e.end (), std::back_inserter (actual));
        }
        RC_TAG (inputs.size (), plain.size ());
        RC_ASSERT (expected.size () == actual.size ());
        RC_ASSERT (expected == actual);
    });
}
