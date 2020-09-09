#
# Copyright (c) 2006 Masashi Fujita
#

cmake_minimum_required (VERSION 3.16)

project (CHACHA20
         LANGUAGES CXX C
         VERSION 1.0.0.0)

option (CHACHA20_ENABLE_SANITIZERS "Enable sanitizers" NO)
option (CHACHA20_ENABLE_PROFILING "Enable profiling" NO)

include (${CMAKE_BINARY_DIR}/conan_paths.cmake)

function (setvar_default var_)
    if (NOT DEFINED ${var_})
        set (${var_} ${ARGN} PARENT_SCOPE)
    endif ()
endfunction ()

setvar_default (CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
setvar_default (CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
setvar_default (CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

set (CMAKE_CXX_STANDARD 17)

find_package (doctest)
find_package (rapidcheck)

set (t_ chacha20-build-options)
    add_library (${t_} INTERFACE)
    target_compile_features (${t_} INTERFACE cxx_std_17)
    if (CHACHA20_ENABLE_SANITIZERS)
        target_compile_options (${t_} INTERFACE -fsanitize=address,undefined)
        target_link_options (${t_} INTERFACE -fsanitize=address,undefined)
    endif ()
    if (CHACHA20_ENABLE_PROFILING)
        target_compile_options (${t_} INTERFACE -fprofile-instr-generate -fcoverage-mapping)
        target_link_options (${t_} INTERFACE -fprofile-instr-generate -fcoverage-mapping)
    endif ()

include_directories (${CMAKE_CURRENT_BINARY_DIR})

enable_testing ()

add_subdirectory (reference)
add_subdirectory (src)
add_subdirectory (test)
