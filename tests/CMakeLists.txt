# TLS link plugin unit tests — Apache 2.0.
include(GoogleTest)

add_executable(test_tls test_tls.cpp)
target_link_libraries(test_tls PRIVATE
    GoodNet::sdk
    goodnet_tls_objects
    asio::asio
    Threads::Threads
    OpenSSL::SSL
    OpenSSL::Crypto
    PkgConfig::SODIUM
    GTest::gtest
    GTest::gtest_main)
target_compile_features(test_tls PRIVATE cxx_std_23)
if(COMMAND goodnet_apply_pch)
    goodnet_apply_pch(test_tls)
endif()
gtest_discover_tests(test_tls
    DISCOVERY_TIMEOUT 30
    PROPERTIES TIMEOUT 60)
