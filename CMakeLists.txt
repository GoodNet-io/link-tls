cmake_minimum_required(VERSION 3.22)

if(NOT TARGET GoodNet::sdk)
    project(goodnet_link_tls
        VERSION   0.1.0
        LANGUAGES CXX)
    find_package(GoodNet REQUIRED)
    goodnet_standalone_plugin_includes()
    include(CTest)
    if(BUILD_TESTING)
        find_package(GTest      REQUIRED)
        find_package(rapidcheck QUIET)
        goodnet_patch_rapidcheck_targets()
        set(GOODNET_BUILD_TESTS ON)
    endif()
endif()

# TLS transport plugin — Apache 2.0 (original implementation).
# OBJECT lib for in-tree tests + SHARED plugin entry. Links OpenSSL
# transitively through Asio's <asio/ssl.hpp> headers.

add_library(goodnet_tls_objects OBJECT
    tls.cpp
)
target_link_libraries(goodnet_tls_objects PUBLIC
    GoodNet::sdk asio::asio Threads::Threads
    OpenSSL::SSL OpenSSL::Crypto)
target_compile_features(goodnet_tls_objects PUBLIC cxx_std_23)
target_compile_options(goodnet_tls_objects PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter)
target_include_directories(goodnet_tls_objects PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR})
set_target_properties(goodnet_tls_objects PROPERTIES
    POSITION_INDEPENDENT_CODE ON)

add_plugin(goodnet_link_tls
    plugin_entry.cpp
)
target_link_libraries(goodnet_link_tls
    PRIVATE goodnet_tls_objects asio::asio Threads::Threads
            OpenSSL::SSL OpenSSL::Crypto)

if(GOODNET_BUILD_TESTS)
    add_subdirectory(tests)
endif()
