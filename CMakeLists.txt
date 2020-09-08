#
# Copyright (c) 2006 Masashi Fujita
#

cmake_minimum_required (VERSION 3.16)

project (CHACHA20
         LANGUAGES CXX C
         VERSION 1.0.0.0)

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

include_directories (${CMAKE_CURRENT_BINARY_DIR})

enable_testing ()

add_subdirectory (reference)
add_subdirectory (src)
add_subdirectory (test)
