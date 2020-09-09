
cmake_minimum_required (VERSION 3.16)

include (TestBigEndian)
include (CheckCXXSourceRuns)
include (CheckCXXCompilerFlag)

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

set (lib_ chacha20)
    add_library (${lib_})
    target_compile_features (${lib_} PUBLIC cxx_std_17)
    target_include_directories (${lib_} PUBLIC ${CHACHA20_SOURCE_DIR}/include
                                        PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
    target_sources (${lib_} PRIVATE ${CHACHA20_SOURCE_DIR}/include/chacha20.hpp chacha20.cpp state-djb.cpp)
    if (TARGET chacha20-build-options)
        target_link_libraries (${lib_} PRIVATE chacha20-build-options)
    endif ()
