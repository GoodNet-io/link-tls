// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/links/tls/tests/test_dtls.cpp
/// @brief  DTLS-over-UDP composer end-to-end — exercises the
///         `dtls://` polarisation. A test harness exposes
///         `gn.link.udp` through a UdpLink-backed bridge so the TLS
///         plugin's `composer_listen("dtls://...")` resolves a real
///         datagram carrier. Server and client TlsLink instances
///         drive the OpenSSL DTLS state machine through the
///         BIO_pair pump introduced for tls:// and reused here
///         unmodified.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <tls.hpp>
#include <udp.hpp>

#include <sdk/extensions/link.h>
#include <sdk/host_api.h>
#include <sdk/types.h>

#include "support/test_self_signed_cert.hpp"

namespace {

/// Bridge a UdpLink into the `gn_link_api_t` shape so a TlsLink
/// instance can pick it up through `LinkCarrier::query(api, "udp")`.
/// UDP's composer surface accepts the same `subscribe_accept` slot
/// the TCP composer publishes; the auto-accept fires when a
/// datagram arrives from a peer endpoint the carrier has not seen
/// before.
struct UdpCarrierBridge {
    std::shared_ptr<gn::link::udp::UdpLink> udp;
    gn_link_api_t vtable{};

    UdpCarrierBridge() : udp(std::make_shared<gn::link::udp::UdpLink>()) {
        vtable.api_size             = sizeof(vtable);
        vtable.get_stats            = &s_get_stats;
        vtable.get_capabilities     = &s_get_caps;
        vtable.send                 = &s_send;
        vtable.send_batch           = &s_send_batch;
        vtable.close                = &s_close;
        vtable.listen               = &s_listen;
        vtable.connect              = &s_connect;
        vtable.subscribe_data       = &s_subscribe_data;
        vtable.unsubscribe_data     = &s_unsubscribe_data;
        vtable.subscribe_accept     = &s_subscribe_accept;
        vtable.unsubscribe_accept   = &s_unsubscribe_accept;
        vtable.composer_listen_port = &s_listen_port;
        vtable.ctx                  = this;
    }

    static gn_result_t s_get_stats(void*, gn_link_stats_t* out) {
        if (out) std::memset(out, 0, sizeof(*out));
        return GN_OK;
    }
    static gn_result_t s_get_caps(void*, gn_link_caps_t* out) {
        if (out) *out = gn::link::udp::UdpLink::capabilities();
        return GN_OK;
    }
    static gn_result_t s_send(void* ctx, gn_conn_id_t c,
                               const std::uint8_t* b, std::size_t n) {
        return static_cast<UdpCarrierBridge*>(ctx)->udp->send(
            c, std::span<const std::uint8_t>(b, n));
    }
    static gn_result_t s_send_batch(void* ctx, gn_conn_id_t c,
                                     const gn_byte_span_t* batch,
                                     std::size_t count) {
        std::vector<std::span<const std::uint8_t>> frames;
        frames.reserve(count);
        for (std::size_t i = 0; i < count; ++i) {
            frames.emplace_back(batch[i].bytes, batch[i].size);
        }
        return static_cast<UdpCarrierBridge*>(ctx)->udp->send_batch(c,
            std::span<const std::span<const std::uint8_t>>(frames));
    }
    static gn_result_t s_close(void* ctx, gn_conn_id_t c, int) {
        return static_cast<UdpCarrierBridge*>(ctx)->udp->disconnect(c);
    }
    static gn_result_t s_listen(void* ctx, const char* uri) {
        return static_cast<UdpCarrierBridge*>(ctx)
            ->udp->composer_listen(uri);
    }
    static gn_result_t s_connect(void* ctx, const char* uri,
                                  gn_conn_id_t* out) {
        return static_cast<UdpCarrierBridge*>(ctx)
            ->udp->composer_connect(uri, out);
    }
    static gn_result_t s_subscribe_data(void* ctx, gn_conn_id_t c,
                                          gn_link_data_cb_t cb, void* ud) {
        return static_cast<UdpCarrierBridge*>(ctx)
            ->udp->composer_subscribe_data(c, cb, ud);
    }
    static gn_result_t s_unsubscribe_data(void* ctx, gn_conn_id_t c) {
        return static_cast<UdpCarrierBridge*>(ctx)
            ->udp->composer_unsubscribe_data(c);
    }
    static gn_result_t s_subscribe_accept(void* ctx,
                                            gn_link_accept_cb_t cb,
                                            void* ud,
                                            gn_subscription_id_t* out) {
        return static_cast<UdpCarrierBridge*>(ctx)
            ->udp->composer_subscribe_accept(cb, ud, out);
    }
    static gn_result_t s_unsubscribe_accept(void* ctx,
                                              gn_subscription_id_t tok) {
        return static_cast<UdpCarrierBridge*>(ctx)
            ->udp->composer_unsubscribe_accept(tok);
    }
    static gn_result_t s_listen_port(void* ctx, std::uint16_t* out) {
        return static_cast<UdpCarrierBridge*>(ctx)
            ->udp->composer_listen_port(out);
    }
};

/// DTLS-only harness: a single UDP bridge that one TlsLink instance
/// queries through `gn.link.udp`. The test instantiates ONE harness
/// per side (server + client) so each TlsLink talks to its own
/// UdpLink — UDP loopback within a single FD does not deliver
/// packets back to the same socket, so the two sides must own
/// distinct sockets to exchange datagrams over 127.0.0.1.
struct DtlsHarness {
    std::mutex                              mu;
    std::atomic<gn_conn_id_t>               next_id{1};

    UdpCarrierBridge udp_bridge;

    static gn_result_t s_notify_connect(void* host_ctx,
                                         const std::uint8_t*,
                                         const char*,
                                         gn_trust_class_t,
                                         gn_handshake_role_t,
                                         gn_conn_id_t* out_conn) {
        auto* h = static_cast<DtlsHarness*>(host_ctx);
        *out_conn = h->next_id.fetch_add(1);
        return GN_OK;
    }
    static gn_result_t s_notify_inbound(void*, gn_conn_id_t,
                                         const std::uint8_t*,
                                         std::size_t) {
        return GN_OK;
    }
    static gn_result_t s_notify_disconnect(void*, gn_conn_id_t,
                                            gn_result_t) {
        return GN_OK;
    }
    static gn_result_t s_kick(void*, gn_conn_id_t) { return GN_OK; }
    static gn_result_t s_query_extension(void* host_ctx, const char* name,
                                           std::uint32_t version,
                                           const void** out) {
        if (!out) return GN_ERR_NULL_ARG;
        *out = nullptr;
        if (version != GN_EXT_LINK_VERSION) return GN_ERR_NOT_FOUND;
        auto* h = static_cast<DtlsHarness*>(host_ctx);
        if (std::string_view{name} == "gn.link.udp") {
            *out = &h->udp_bridge.vtable;
            return GN_OK;
        }
        return GN_ERR_NOT_FOUND;
    }

    host_api_t make_api() {
        host_api_t api{};
        api.api_size                 = sizeof(host_api_t);
        api.host_ctx                 = this;
        api.notify_connect           = &s_notify_connect;
        api.notify_inbound_bytes     = &s_notify_inbound;
        api.notify_disconnect        = &s_notify_disconnect;
        api.kick_handshake           = &s_kick;
        api.query_extension_checked  = &s_query_extension;
        return api;
    }
};

/// Records bytes the composer data callback receives so the test can
/// assert payload contents after handshake completion.
struct DataRecorder {
    mutable std::mutex                          mu;
    std::vector<std::vector<std::uint8_t>>      frames;
    std::vector<gn_conn_id_t>                   owners;
    std::atomic<std::size_t>                    count{0};

    static void thunk(void* user_data, gn_conn_id_t conn,
                      const std::uint8_t* bytes, std::size_t size) {
        auto* self = static_cast<DataRecorder*>(user_data);
        {
            std::lock_guard lk(self->mu);
            self->frames.emplace_back(bytes, bytes + size);
            self->owners.push_back(conn);
        }
        self->count.fetch_add(1, std::memory_order_relaxed);
    }
};

/// Captures the server-side composer id when DTLS handshake completes
/// and the TLS plugin fires the accept-bus.
struct AcceptRecorder {
    std::atomic<gn_conn_id_t>          last{GN_INVALID_ID};
    std::atomic<std::size_t>           count{0};

    static void thunk(void* user_data, gn_conn_id_t conn,
                      const char* /*peer_uri*/) {
        auto* self = static_cast<AcceptRecorder*>(user_data);
        self->last.store(conn, std::memory_order_release);
        self->count.fetch_add(1, std::memory_order_relaxed);
    }
};

bool wait_for(auto&& predicate,
              std::chrono::milliseconds timeout = std::chrono::seconds{15}) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }
    return predicate();
}

}  // namespace

TEST(DtlsComposer, HandshakeAndPayloadRoundTrip) {
    /// Two separate harnesses — one per side — so each TlsLink owns
    /// a distinct UdpLink with its own bound socket. UDP loopback
    /// over a single FD does not deliver back to the sender; the
    /// two-socket layout matches the production peer-to-peer
    /// topology DTLS is intended to serve.
    DtlsHarness server_harness;
    DtlsHarness client_harness;
    auto server_api = server_harness.make_api();
    auto client_api = client_harness.make_api();
    server_harness.udp_bridge.udp->set_host_api(&server_api);
    client_harness.udp_bridge.udp->set_host_api(&client_api);
    /// DTLS handshake records (ServerHello + cert + ...) can exceed
    /// the default UdpLink MTU of 1200 bytes. Loopback delivers up
    /// to 64 KiB cleanly; raise the cap so the BIO_read → carrier.send
    /// loop never trips PAYLOAD_TOO_LARGE on a single record. A
    /// production deployment would either rely on DTLS handshake
    /// fragmentation through SSL_set_mtu (effective post-handshake)
    /// or carry a more aggressive certificate trim.
    server_harness.udp_bridge.udp->set_mtu(65000);
    client_harness.udp_bridge.udp->set_mtu(65000);

    auto server = std::make_shared<gn::link::tls::TlsLink>();
    auto client = std::make_shared<gn::link::tls::TlsLink>();

    /// Generate a fresh self-signed cert for the server side. Client
    /// verification stays off — DTLS underneath an ICE/Noise stack
    /// is for media-channel encryption, not peer authentication.
    std::string cert_pem, key_pem;
    ASSERT_TRUE(gn::tests::support::generate_self_signed(cert_pem, key_pem));
    server->set_server_credentials(cert_pem, key_pem);
    server->set_host_api(&server_api);
    /// `set_host_api` resets verify_peer to the default-secure
    /// baseline (true); flip the opt-out AFTER binding so the test
    /// fixture does not need a config_get implementation.
    server->set_verify_peer(false);

    client->set_host_api(&client_api);
    client->set_verify_peer(false);

    /// Server side: opens UDP carrier via composer_listen("dtls://..."),
    /// subscribes to accept-bus so the test can observe the handshake-
    /// complete event surface.
    AcceptRecorder accept_rec;
    gn_subscription_id_t accept_token = GN_INVALID_SUBSCRIPTION_ID;
    ASSERT_EQ(server->composer_subscribe_accept(&AcceptRecorder::thunk,
                                                  &accept_rec,
                                                  &accept_token), GN_OK);

    ASSERT_EQ(server->composer_listen("dtls://127.0.0.1:0"), GN_OK);
    std::uint16_t server_port = 0;
    ASSERT_EQ(server->composer_listen_port(&server_port), GN_OK);
    ASSERT_GT(server_port, 0u);

    /// Client side: initiate the DTLS handshake. The TLS plugin
    /// allocates a composer conn id immediately; the actual handshake
    /// completes asynchronously through the BIO_pair pump.
    const std::string uri =
        "dtls://127.0.0.1:" + std::to_string(server_port);
    gn_conn_id_t client_conn = GN_INVALID_ID;
    ASSERT_EQ(client->composer_connect(uri, &client_conn), GN_OK);
    EXPECT_NE(client_conn, GN_INVALID_ID);
    EXPECT_TRUE(client_conn & gn::link::tls::TlsLink::kComposerIdBit);

    DataRecorder client_rec;
    ASSERT_EQ(client->composer_subscribe_data(client_conn,
                                                &DataRecorder::thunk,
                                                &client_rec), GN_OK);

    /// Wait for the server-side accept-bus to fire — that signals the
    /// DTLS handshake reached the application-data phase.
    ASSERT_TRUE(wait_for([&] {
        return accept_rec.count.load() >= 1;
    })) << "DTLS handshake did not complete within timeout";

    const gn_conn_id_t server_conn =
        accept_rec.last.load(std::memory_order_acquire);
    ASSERT_NE(server_conn, GN_INVALID_ID);
    EXPECT_TRUE(server_conn & gn::link::tls::TlsLink::kComposerIdBit);

    DataRecorder server_rec;
    ASSERT_EQ(server->composer_subscribe_data(server_conn,
                                                &DataRecorder::thunk,
                                                &server_rec), GN_OK);

    /// Payload roundtrip: bytes traverse TLS-app → SSL_write →
    /// BIO_read → UDP carrier → BIO_write → SSL_read → composer
    /// data callback.
    const std::vector<std::uint8_t> from_client{0x11, 0x22, 0x33};
    const std::vector<std::uint8_t> from_server{0xAA, 0xBB, 0xCC, 0xDD};

    ASSERT_EQ(client->send(client_conn,
        std::span<const std::uint8_t>(from_client)), GN_OK);
    ASSERT_EQ(server->send(server_conn,
        std::span<const std::uint8_t>(from_server)), GN_OK);

    ASSERT_TRUE(wait_for([&] {
        return server_rec.count.load() >= 1 &&
               client_rec.count.load() >= 1;
    })) << "DTLS payload did not surface in both directions";

    {
        std::lock_guard lk(server_rec.mu);
        ASSERT_FALSE(server_rec.frames.empty());
        EXPECT_EQ(server_rec.frames.front(), from_client);
    }
    {
        std::lock_guard lk(client_rec.mu);
        ASSERT_FALSE(client_rec.frames.empty());
        EXPECT_EQ(client_rec.frames.front(), from_server);
    }

    EXPECT_EQ(server->composer_unsubscribe_accept(accept_token), GN_OK);
    server->shutdown();
    client->shutdown();
    server_harness.udp_bridge.udp->shutdown();
    client_harness.udp_bridge.udp->shutdown();
}

TEST(DtlsComposer, BadSchemeRejected) {
    /// dtls:// + tls:// pass; anything else returns INVALID_ENVELOPE.
    /// composer_listen / composer_connect both apply the same gate so
    /// callers cannot bypass scheme polarisation by routing the URI
    /// through the connect side.
    auto t = std::make_shared<gn::link::tls::TlsLink>();
    EXPECT_EQ(t->composer_listen("udp://127.0.0.1:0"),
              GN_ERR_INVALID_ENVELOPE);
    gn_conn_id_t out = GN_INVALID_ID;
    EXPECT_EQ(t->composer_connect("dtls://127.0.0.1:1", &out),
              GN_ERR_INVALID_STATE);  // no host_api yet
    EXPECT_EQ(t->composer_connect("garbage://x", &out),
              GN_ERR_INVALID_ENVELOPE);
}

TEST(DtlsComposer, ListenPortInvalidStateBeforeBind) {
    auto t = std::make_shared<gn::link::tls::TlsLink>();
    std::uint16_t port = 0xBEEF;
    EXPECT_EQ(t->composer_listen_port(&port), GN_ERR_INVALID_STATE);
    EXPECT_EQ(port, 0u);
}
