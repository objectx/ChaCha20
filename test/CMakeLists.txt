
cmake_minimum_required (VERSION 3.5)

set (SOURCE_FILES chacha.cpp)
set (HEADER_FILES catch.hpp)

set_property (SOURCE main.cpp
              PROPERTY COMPILE_DEFINITIONS "CATCH_CONFIG_MAIN")

add_executable (test-chacha20 ${SOURCE_FILES} ${HEADER_FILES} main.cpp)
    target_compile_features (test-chacha20 PRIVATE cxx_auto_type)
    target_link_libraries (test-chacha20 PRIVATE chacha20-ref chacha20)

if (COMMAND cotire)
    cotire (test-cacha20)
endif ()

add_test (NAME test-chacha20
          COMMAND test-chacha20 -r compact)
