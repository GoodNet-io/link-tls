// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/links/tls/tests/test_tls_conformance.cpp
/// @brief  Instantiates the SDK link teardown conformance suite
///         against `gn::link::tls::TlsLink`. Self-signed loopback
///         cert via the bundled `tests/support` helper.

#include <sdk/test/conformance/link_teardown.hpp>
#include <tls.hpp>
#include <tests/support/test_self_signed_cert.hpp>

#include <memory>
#include <string>

namespace gn::test::link::conformance {

template <>
struct LinkTraits<gn::link::tls::TlsLink> {
    static constexpr const char* scheme = "tls";
    static std::shared_ptr<gn::link::tls::TlsLink> make() {
        return std::make_shared<gn::link::tls::TlsLink>();
    }
    static std::string listen_uri() { return "tls://127.0.0.1:0"; }
    static std::string connect_uri(std::uint16_t port) {
        return "tls://127.0.0.1:" + std::to_string(port);
    }
    /// Self-signed loopback cert; client opts out of peer-cert
    /// verification — same shape as the TLS unit test, matching the
    /// production "TLS as link encryption beneath Noise" path.
    static bool wire_credentials(gn::link::tls::TlsLink& server,
                                  gn::link::tls::TlsLink& client) {
        std::string cert, key;
        if (!gn::tests::support::generate_self_signed(cert, key)) {
            return false;
        }
        server.set_server_credentials(cert, key);
        client.set_verify_peer(false);
        return true;
    }
};

INSTANTIATE_TYPED_TEST_SUITE_P(
    TlsLink,
    LinkTeardownConformance,
    ::testing::Types<gn::link::tls::TlsLink>);

}  // namespace gn::test::link::conformance
