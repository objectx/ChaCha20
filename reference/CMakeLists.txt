
cmake_minimum_required (VERSION 3.5)

enable_language (C)

set (SOURCE_FILES chacha.c)
set (HEADER_FILES ecrypt-sync.h ecrypt-portable.h ecrypt-config.h ecrypt-machine.h)

add_library (chacha20-ref ${SOURCE_FILES} ${HEADER_FILES})
    target_include_directories (chacha20-ref PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
