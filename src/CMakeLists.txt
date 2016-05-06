
cmake_minimum_required (VERSION 3.5)

include (TestBigEndian)
include (CheckCXXSourceRuns)
include (CheckCXXCompilerFlag)

set (SOURCE_FILES chacha20.cpp)
set (HEADER_FILES ${CHACHA20_SOURCE_DIR}/include/chacha20.hpp)

if (NOT ${CMAKE_CROSSCOMPILING})
    TEST_BIG_ENDIAN (IS_BIG_ENDIAN)
    if (NOT ${IS_BIG_ENDIAN})
        set (TARGET_LITTLE_ENDIAN 0x1)
    endif ()
    check_cxx_source_runs ([=[
        #include <cstdint>
        int main () {
            char tmp [] = { 0, 4, 3, 2, 1 } ;
            int32_t v = *((const int32_t *)(&tmp [1])) ;
            if (v == 0x01020304u) {
                return 0 ;
            }
            return 1 ;
        }
        ]=] TARGET_ALLOWS_UNALIGNED_ACCESS)
    set (HAVE_CONFIG_H 1)
    if (${WIN32})
        CHECK_CXX_COMPILER_FLAG ("/arch:AVX" HAVE_SSE3)
    else ()
        CHECK_CXX_COMPILER_FLAG ("-msse3" HAVE_SSE3)
    endif ()
    configure_file (${CMAKE_CURRENT_SOURCE_DIR}/config.hpp.in ${CMAKE_CURRENT_BINARY_DIR}/config.hpp)
    add_definitions ("-DHAVE_CONFIG_HPP")
endif ()

add_library (chacha20 ${SOURCE_FILES} ${HEADER_FILES})
    target_compile_features (chacha20 PUBLIC cxx_auto_type
                                      PRIVATE cxx_constexpr cxx_relaxed_constexpr)
    target_include_directories (chacha20 PUBLIC ${CHACHA20_SOURCE_DIR}/include
                                         PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
