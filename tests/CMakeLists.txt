# TLS link plugin unit tests — Apache 2.0.
include(GoogleTest)

add_executable(test_tls
    test_tls.cpp
    test_tls_conformance.cpp
    test_composer.cpp)
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

# DTLS-over-UDP composer end-to-end. The UDP plugin's composer
# surface is a runtime dependency, so this test only builds when
# the UDP plugin's object library is in tree.
if(TARGET goodnet_udp_objects)
    add_executable(test_dtls test_dtls.cpp)
    target_link_libraries(test_dtls PRIVATE
        GoodNet::sdk
        goodnet_tls_objects
        goodnet_udp_objects
        asio::asio
        Threads::Threads
        OpenSSL::SSL
        OpenSSL::Crypto
        PkgConfig::SODIUM
        GTest::gtest
        GTest::gtest_main)
    target_compile_features(test_dtls PRIVATE cxx_std_23)
    if(COMMAND goodnet_apply_pch)
        goodnet_apply_pch(test_dtls)
    endif()
    gtest_discover_tests(test_dtls
        DISCOVERY_TIMEOUT 30
        PROPERTIES TIMEOUT 60)
endif()
