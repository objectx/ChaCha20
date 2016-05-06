
cmake_minimum_required (VERSION 3.5)

set (SOURCE_FILES chacha20.cpp)
set (HEADER_FILES ${CHACHA20_SOURCE_DIR}/include/chacha20.hpp)

add_library (chacha20 ${SOURCE_FILES} ${HEADER_FILES})
    target_compile_features (chacha20 PUBLIC cxx_auto_type
                                      PRIVATE cxx_constexpr cxx_relaxed_constexpr)
    target_include_directories (chacha20 PUBLIC ${CHACHA20_SOURCE_DIR}/include)
