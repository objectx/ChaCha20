#
# Copyright (c) 2006 Masashi Fujita
#

cmake_minimum_required (VERSION 3.5)

project (CHACHA20
         LANGUAGES CXX C
         VERSION 1.0.0.0)

list (INSERT CMAKE_MODULE_PATH 0 "${CMAKE_CURRENT_SOURCE_DIR}/CMake")

function (setvar_default var_)
    if (NOT DEFINED ${var_})
        set (${var_} ${ARGN} PARENT_SCOPE)
    endif ()
endfunction ()

setvar_default (CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
setvar_default (CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
setvar_default (CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

include (cotire OPTIONAL)

include_directories (${CMAKE_CURRENT_BINARY_DIR})

enable_testing ()

add_subdirectory (reference)
add_subdirectory (src)
add_subdirectory (test)
