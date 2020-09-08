
cmake_minimum_required (VERSION 3.16)

set (SOURCE_FILES chacha.cpp)
set (HEADER_FILES catch.hpp)

set (app_ test-chacha20)
    add_executable (${app_})
    target_compile_features (${app_} PRIVATE cxx_std_17)
    target_link_libraries (${app_} PRIVATE chacha20-ref chacha20 doctest::doctest rapidcheck::rapidcheck)
    target_sources (${app_} PRIVATE main.cpp chacha.cpp doctest-rapidcheck.hpp)
    target_precompile_headers (${app_} PRIVATE
                               <doctest/doctest.h>
                               <rapidcheck.h>
                               <vector>
                               <utility>)
    set_source_files_properties (main.cpp PROPERTIES SKIP_PRECOMPILE_HEADERS YES)
add_test (NAME test-chacha20
          COMMAND test-chacha20 -r compact)
