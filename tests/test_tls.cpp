/// @file   plugins/links/tls/tests/test_tls.cpp
/// @brief  Loopback TLS handshake + payload round-trip.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include <plugins/links/tls/tls.hpp>

#include <tests/support/test_self_signed_cert.hpp>

#include <sdk/host_api.h>
#include <sdk/types.h>

namespace {

using gn::tests::support::generate_self_signed;

struct TlsHarness {
    std::mutex                                  mu;
    std::vector<gn_conn_id_t>                   connects;
    std::vector<gn_handshake_role_t>            roles;
    std::vector<std::vector<std::uint8_t>>      inbound;

    /// Caller-thread pin for the `link.md` §9 regression. Set
    /// `main_tid` to `std::this_thread::get_id()` from the test
    /// before invoking `shutdown()`; `s_notify_disconnect`
    /// increments `on_main_disconnects` only when the call lands
    /// on the pinned thread. Lets a count-based assert be
    /// deterministic where the worker thread might race the
    /// main thread to fire the async-path notify first.
    std::thread::id                              main_tid{};
    std::atomic<int>                             disconnects{0};
    std::atomic<int>                             on_main_disconnects{0};

    static gn_result_t s_notify_connect(void* host_ctx,
                                         const std::uint8_t* /*remote_pk*/,
                                         const char* /*uri*/,
                                         gn_trust_class_t /*trust*/,
                                         gn_handshake_role_t role,
                                         gn_conn_id_t* out_conn) {
        auto* h = static_cast<TlsHarness*>(host_ctx);
        std::lock_guard lk(h->mu);
        const auto id = static_cast<gn_conn_id_t>(h->connects.size() + 1);
        h->connects.push_back(id);
        h->roles.push_back(role);
        *out_conn = id;
        return GN_OK;
    }
    static gn_result_t s_notify_inbound(void* host_ctx, gn_conn_id_t,
                                         const std::uint8_t* bytes,
                                         std::size_t size) {
        auto* h = static_cast<TlsHarness*>(host_ctx);
        std::lock_guard lk(h->mu);
        h->inbound.emplace_back(bytes, bytes + size);
        return GN_OK;
    }
    static gn_result_t s_notify_disconnect(void* host_ctx, gn_conn_id_t,
                                            gn_result_t) {
        auto* h = static_cast<TlsHarness*>(host_ctx);
        if (!h) return GN_OK;
        h->disconnects.fetch_add(1);
        if (h->main_tid != std::thread::id{} &&
            std::this_thread::get_id() == h->main_tid) {
            h->on_main_disconnects.fetch_add(1);
        }
        return GN_OK;
    }
    static gn_result_t s_kick(void*, gn_conn_id_t) { return GN_OK; }

    host_api_t make_api() {
        host_api_t api{};
        api.api_size             = sizeof(host_api_t);
        api.host_ctx             = this;
        api.notify_connect       = &s_notify_connect;
        api.notify_inbound_bytes = &s_notify_inbound;
        api.notify_disconnect    = &s_notify_disconnect;
        api.kick_handshake       = &s_kick;
        return api;
    }
};

bool wait_for(auto&& predicate,
              std::chrono::milliseconds timeout = std::chrono::seconds{4}) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }
    return predicate();
}

} // namespace

TEST(TlsLink_Capabilities, AdvertisesEncryptedPath) {
    const auto caps = gn::link::tls::TlsLink::capabilities();
    EXPECT_TRUE(caps.flags & GN_LINK_CAP_STREAM);
    EXPECT_TRUE(caps.flags & GN_LINK_CAP_RELIABLE);
    EXPECT_TRUE(caps.flags & GN_LINK_CAP_ORDERED);
    EXPECT_TRUE(caps.flags & GN_LINK_CAP_ENCRYPTED_PATH);
}

TEST(TlsLink, RejectsListenWithoutCredentials) {
    auto t = std::make_shared<gn::link::tls::TlsLink>();
    /// No credentials wired and no host_api / config bound — the
    /// listen path must refuse rather than silently accept and fail
    /// every TLS handshake later.
    EXPECT_EQ(t->listen("tls://127.0.0.1:0"), GN_ERR_NOT_IMPLEMENTED);
    t->shutdown();
}

TEST(TlsLink_VerifyDefault, ClientRejectsUntrustedCertWithoutOptOut) {
    /// Default-secure: a fresh `TlsLink` client verifies the
    /// peer cert against OpenSSL's default trust store. A self-
    /// signed loopback cert chains to nothing trusted, so the
    /// handshake fails and `notify_connect` never publishes the
    /// initiator side. The harness records the responder-side
    /// connect from `accept` but no initiator-side completion.
    std::string cert, key;
    ASSERT_TRUE(generate_self_signed(cert, key));

    TlsHarness harness;
    auto api = harness.make_api();

    auto server = std::make_shared<gn::link::tls::TlsLink>();
    auto client = std::make_shared<gn::link::tls::TlsLink>();
    server->set_host_api(&api);
    client->set_host_api(&api);
    server->set_server_credentials(cert, key);
    /// Note: no `client->set_verify_peer(false)` — default verify
    /// stays on; this is the regression scenario.

    ASSERT_EQ(server->listen("tls://127.0.0.1:0"), GN_OK);
    const auto port = server->listen_port();
    ASSERT_GT(port, 0u);

    const std::string uri =
        "tls://127.0.0.1:" + std::to_string(port);
    /// `connect` returns GN_OK on enqueue — the failure surfaces
    /// asynchronously inside the handshake, not on the call.
    ASSERT_EQ(client->connect(uri), GN_OK);

    /// Wait for any handshake completion. With verify_peer on and
    /// no trust store match, the initiator side never publishes
    /// `notify_connect`. A two-second window catches a successful
    /// handshake on the pre-fix path.
    const bool any_initiator = wait_for([&] {
        std::lock_guard lk(harness.mu);
        for (auto role : harness.roles) {
            if (role == GN_ROLE_INITIATOR) return true;
        }
        return false;
    }, std::chrono::seconds{2});

    EXPECT_FALSE(any_initiator);

    client->shutdown();
    server->shutdown();
}

namespace {

/// Test harness variant that exposes a `links.tls.verify_peer`
/// config bool. The caller sets `verify_peer_value` before binding
/// the api; an unbound variant leaves `config_get` returning
/// `GN_ERR_NOT_FOUND` for the key.
struct TlsConfigHarness : TlsHarness {
    std::optional<int32_t> verify_peer_value;

    static gn_result_t s_config_get(void* host_ctx,
                                     const char* key,
                                     gn_config_value_type_t type,
                                     std::size_t index,
                                     void* out_value,
                                     void** out_user_data,
                                     void (**out_free)(void*, void*)) {
        auto* h = static_cast<TlsConfigHarness*>(host_ctx);
        if (!h || !key || !out_value) return GN_ERR_NULL_ARG;
        if (out_free || out_user_data) return GN_ERR_NULL_ARG;
        if (type != GN_CONFIG_VALUE_BOOL) return GN_ERR_NOT_FOUND;
        if (index != GN_CONFIG_NO_INDEX) return GN_ERR_OUT_OF_RANGE;
        if (std::string_view{key} == "links.tls.verify_peer"
            && h->verify_peer_value) {
            *static_cast<int32_t*>(out_value) = *h->verify_peer_value;
            return GN_OK;
        }
        return GN_ERR_NOT_FOUND;
    }

    host_api_t make_api() {
        host_api_t api = TlsHarness::make_api();
        api.config_get = &s_config_get;
        return api;
    }
};

} // namespace

TEST(TlsLink_VerifyDefault, ConfigOptOutLetsHandshakeSucceed) {
    /// `links.tls.verify_peer = false` on the config flips the
    /// client to verify_none, matching the API opt-out.
    std::string cert, key;
    ASSERT_TRUE(generate_self_signed(cert, key));

    TlsConfigHarness harness;
    harness.verify_peer_value = 0;
    auto api = harness.make_api();

    auto server = std::make_shared<gn::link::tls::TlsLink>();
    auto client = std::make_shared<gn::link::tls::TlsLink>();
    server->set_host_api(&api);
    client->set_host_api(&api);
    server->set_server_credentials(cert, key);

    ASSERT_EQ(server->listen("tls://127.0.0.1:0"), GN_OK);
    const auto port = server->listen_port();
    const std::string uri =
        "tls://127.0.0.1:" + std::to_string(port);
    ASSERT_EQ(client->connect(uri), GN_OK);

    ASSERT_TRUE(wait_for([&] {
        std::lock_guard lk(harness.mu);
        return harness.connects.size() >= 2;
    }));

    client->shutdown();
    server->shutdown();
}

TEST(TlsLink_VerifyDefault, ConfigUnboundEnforcesDefault) {
    /// Without the config key bound (the verify_peer key is unbound (returns
    /// `GN_ERR_NOT_FOUND`), the client stays in verify_peer
    /// mode and refuses the self-signed loopback cert.
    std::string cert, key;
    ASSERT_TRUE(generate_self_signed(cert, key));

    TlsConfigHarness harness;
    /// verify_peer_value left unset — kernel returns NOT_FOUND.
    auto api = harness.make_api();

    auto server = std::make_shared<gn::link::tls::TlsLink>();
    auto client = std::make_shared<gn::link::tls::TlsLink>();
    server->set_host_api(&api);
    client->set_host_api(&api);
    server->set_server_credentials(cert, key);

    ASSERT_EQ(server->listen("tls://127.0.0.1:0"), GN_OK);
    const auto port = server->listen_port();
    const std::string uri =
        "tls://127.0.0.1:" + std::to_string(port);
    ASSERT_EQ(client->connect(uri), GN_OK);

    const bool any_initiator = wait_for([&] {
        std::lock_guard lk(harness.mu);
        for (auto role : harness.roles) {
            if (role == GN_ROLE_INITIATOR) return true;
        }
        return false;
    }, std::chrono::seconds{2});
    EXPECT_FALSE(any_initiator);

    client->shutdown();
    server->shutdown();
}

TEST(TlsLink_KeyHygiene, ListenZeroisesOverrideKey) {
    /// `plugins/security/noise/docs/handshake.md` §5b: once OpenSSL has copied the key
    /// bytes into its own context, the override buffer has no
    /// remaining purpose and is wiped eagerly. The observable
    /// flips from non-zero to zero across the listen call.
    std::string cert, key;
    ASSERT_TRUE(generate_self_signed(cert, key));

    auto t = std::make_shared<gn::link::tls::TlsLink>();
    t->set_server_credentials(cert, key);
    EXPECT_FALSE(t->key_pem_zeroised_for_test());

    ASSERT_EQ(t->listen("tls://127.0.0.1:0"), GN_OK);

    EXPECT_TRUE(t->key_pem_zeroised_for_test());

    t->shutdown();
}

TEST(TlsLink, LoopbackHandshakeAndPayloadRoundTrip) {
    std::string cert, key;
    ASSERT_TRUE(generate_self_signed(cert, key))
        << "ephemeral cert generation failed";

    TlsHarness harness;
    auto api = harness.make_api();

    auto server = std::make_shared<gn::link::tls::TlsLink>();
    auto client = std::make_shared<gn::link::tls::TlsLink>();
    server->set_host_api(&api);
    client->set_host_api(&api);
    server->set_server_credentials(cert, key);
    /// Self-signed cert in this loopback fixture chains to nothing;
    /// the client opts out of peer-cert verification explicitly,
    /// matching the production "TLS as link encryption beneath
    /// Noise" path.
    client->set_verify_peer(false);

    ASSERT_EQ(server->listen("tls://127.0.0.1:0"), GN_OK);
    const auto port = server->listen_port();
    ASSERT_GT(port, 0u);

    const std::string uri =
        "tls://127.0.0.1:" + std::to_string(port);
    ASSERT_EQ(client->connect(uri), GN_OK);

    ASSERT_TRUE(wait_for([&] {
        std::lock_guard lk(harness.mu);
        return harness.connects.size() >= 2;
    }));
    {
        std::lock_guard lk(harness.mu);
        EXPECT_EQ(harness.connects.size(), 2u);
        const bool roles_pair =
            (harness.roles[0] == GN_ROLE_INITIATOR &&
             harness.roles[1] == GN_ROLE_RESPONDER) ||
            (harness.roles[0] == GN_ROLE_RESPONDER &&
             harness.roles[1] == GN_ROLE_INITIATOR);
        EXPECT_TRUE(roles_pair);
    }

    gn_conn_id_t initiator_id = 0;
    {
        std::lock_guard lk(harness.mu);
        for (std::size_t i = 0; i < harness.roles.size(); ++i) {
            if (harness.roles[i] == GN_ROLE_INITIATOR) {
                initiator_id = harness.connects[i];
                break;
            }
        }
    }
    ASSERT_NE(initiator_id, 0u);

    const std::vector<std::uint8_t> payload{0x11, 0x22, 0x33, 0x44, 0x55};
    auto rc1 = client->send(initiator_id,
        std::span<const std::uint8_t>(payload));
    auto rc2 = server->send(initiator_id,
        std::span<const std::uint8_t>(payload));
    EXPECT_TRUE(rc1 == GN_OK || rc2 == GN_OK);

    ASSERT_TRUE(wait_for([&] {
        std::lock_guard lk(harness.mu);
        return !harness.inbound.empty();
    }));
    {
        std::lock_guard lk(harness.mu);
        ASSERT_FALSE(harness.inbound.empty());
        EXPECT_EQ(harness.inbound.front(), payload);
    }

    client->shutdown();
    server->shutdown();
}

TEST(TlsLink_Shutdown, SynchronousNotifyDisconnect) {
    /// `link.md` §9 — shutdown releases every kernel-observable
    /// session before the io_context tear-down. Pre-fix, TLS closed
    /// the per-session sockets and let `ioc_.stop()` drop the read-
    /// completion path that fires `notify_disconnect`; the kernel-
    /// side `ConnectionRegistry` then kept live records past
    /// shutdown and held the security plugin's lifetime anchor.
    /// Carry-over of the TCP fix in commit bda18c6.
    std::string cert, key;
    ASSERT_TRUE(generate_self_signed(cert, key));

    TlsHarness harness;
    harness.main_tid = std::this_thread::get_id();
    auto api = harness.make_api();

    auto server = std::make_shared<gn::link::tls::TlsLink>();
    auto client = std::make_shared<gn::link::tls::TlsLink>();
    server->set_host_api(&api);
    client->set_host_api(&api);
    server->set_server_credentials(cert, key);
    client->set_verify_peer(false);

    ASSERT_EQ(server->listen("tls://127.0.0.1:0"), GN_OK);
    const auto port = server->listen_port();
    ASSERT_GT(port, 0u);

    const std::string uri =
        "tls://127.0.0.1:" + std::to_string(port);
    ASSERT_EQ(client->connect(uri), GN_OK);

    ASSERT_TRUE(wait_for([&] {
        std::lock_guard lk(harness.mu);
        return harness.connects.size() >= 2;
    }));
    EXPECT_EQ(harness.disconnects.load(), 0);
    EXPECT_EQ(harness.on_main_disconnects.load(), 0);

    client->shutdown();
    server->shutdown();

    /// Caller-thread pin: pre-fix, every notify_disconnect would
    /// either be dropped (handler poisoned by `ioc_.stop()`) or
    /// run on the worker thread that drained an EOF before the
    /// stop landed; either way `on_main_disconnects` stays zero.
    /// Post-fix, both shutdown calls fire on the caller thread,
    /// matching the two observed `notify_connect` events.
    EXPECT_EQ(harness.on_main_disconnects.load(), 2)
        << "TlsLink::shutdown() must fire notify_disconnect "
           "synchronously on the caller thread for every live "
           "session before ioc_.stop() drops strand-bound "
           "continuations (link.md §9).";
}
