// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/links/tls/tls.hpp
/// @brief  Asio-on-OpenSSL TLS transport (`tls://`).
///
/// TLS terminates at this transport: the kernel sees a stream of
/// already-decrypted application bytes routed by `notify_inbound_bytes`,
/// the same way it sees plain TCP. The kernel's identity / Noise
/// pipeline lives above the transport regardless of scheme; TLS
/// adds wire encryption on the link, not peer authentication for
/// the mesh.
///
/// Cert + key paths come from the kernel-owned config under
/// `links.tls.cert_path` / `links.tls.key_path`. A server
/// without both refuses to listen. A client verifies the peer
/// certificate against OpenSSL's default trust store by default;
/// operators who run TLS underneath Noise authentication opt out
/// explicitly through `links.tls.verify_peer = false` on the
/// kernel config (`security-trust.en.md` §3 single-source principle).

#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ssl.hpp>
#include <asio/strand.hpp>

#include <sdk/cpp/link_carrier.hpp>
#include <sdk/extensions/link.h>
#include <sdk/host_api.h>
#include <sdk/trust.h>
#include <sdk/types.h>

namespace gn::link::tls {

class TlsLink : public std::enable_shared_from_this<TlsLink> {
public:
    TlsLink();
    ~TlsLink();

    TlsLink(const TlsLink&)            = delete;
    TlsLink& operator=(const TlsLink&) = delete;

    [[nodiscard]] gn_result_t listen(std::string_view uri);
    [[nodiscard]] gn_result_t connect(std::string_view uri);

    [[nodiscard]] gn_result_t send(gn_conn_id_t conn,
                                    std::span<const std::uint8_t> bytes);
    [[nodiscard]] gn_result_t send_batch(
        gn_conn_id_t conn,
        std::span<const std::span<const std::uint8_t>> frames);
    [[nodiscard]] gn_result_t disconnect(gn_conn_id_t conn);

    void set_host_api(const host_api_t* api) noexcept;
    void shutdown();

    [[nodiscard]] std::uint16_t listen_port() const noexcept;
    [[nodiscard]] std::size_t   session_count() const noexcept;

    struct Stats {
        std::uint64_t bytes_in           = 0;
        std::uint64_t bytes_out          = 0;
        std::uint64_t frames_in          = 0;
        std::uint64_t frames_out         = 0;
        std::uint64_t active_connections = 0;
    };
    [[nodiscard]] Stats stats() const noexcept;

    [[nodiscard]] static gn_link_caps_t capabilities() noexcept;

    /// Composer L2 surface. TlsLink layers TLS over a lower-layer
    /// carrier (currently `gn.link.tcp`; DTLS over `gn.link.udp`
    /// lands when UdpLink composer impl arrives). Composer conn
    /// ids carry `kComposerIdBit` so `send`/`disconnect` route by
    /// range without scanning two maps — same shape as TcpLink's
    /// kernel-vs-composer split.
    [[nodiscard]] gn_result_t composer_listen(std::string_view uri);
    [[nodiscard]] gn_result_t composer_connect(std::string_view uri,
                                                gn_conn_id_t* out_conn);
    [[nodiscard]] gn_result_t composer_subscribe_data(
        gn_conn_id_t conn, ::gn_link_data_cb_t cb, void* user_data);
    [[nodiscard]] gn_result_t composer_unsubscribe_data(gn_conn_id_t conn);
    [[nodiscard]] gn_result_t composer_subscribe_accept(
        ::gn_link_accept_cb_t cb, void* user_data,
        gn_subscription_id_t* out_token);
    [[nodiscard]] gn_result_t composer_unsubscribe_accept(
        gn_subscription_id_t token);

    /// Bound L1 port of the carrier acceptor that backs the active
    /// composer-listen, propagated up so a tls:// composer caller can
    /// surface an ephemeral port that the underlying `gn.link.tcp`
    /// picked. Returns @ref GN_ERR_INVALID_STATE when the carrier is
    /// not bound or the L1 listen has not been issued yet.
    [[nodiscard]] gn_result_t composer_listen_port(
        std::uint16_t* out_port) const noexcept;

    static constexpr gn_conn_id_t kComposerIdBit =
        gn_conn_id_t{1} << 63;

    /// Direct cert + key configuration for in-tree tests that
    /// instantiate the transport without a Kernel. Production
    /// loads come through `links.tls.cert_path` /
    /// `links.tls.key_path` on the kernel-owned config. The
    /// key buffer is wiped before the new bytes overwrite it per
    /// `plugins/security/noise/docs/handshake.md` §5b.
    void set_server_credentials(std::string_view cert_pem,
                                 std::string_view key_pem);

    /// Forward-secrecy observable: the override server private key
    /// buffer is fully zero. Used by the regression suite that
    /// pins `plugins/security/noise/docs/handshake.md` §5b — production callers do not
    /// consult this.
    [[nodiscard]] bool key_pem_zeroised_for_test() const noexcept;

    /// Toggle peer-cert verification. Disabled by default — the
    /// link-layer cert is one of two credentials and the Noise
    /// handshake above is authoritative; opt-in via the kernel
    /// config to require peer-cert validation in addition.
    void set_verify_peer(bool on) noexcept;

private:
    class Session;
    class ComposerSession;

    struct ComposerDataSub {
        ::gn_link_data_cb_t cb        = nullptr;
        void*               user_data = nullptr;
    };
    struct ComposerAcceptSub {
        gn_subscription_id_t  token     = GN_INVALID_SUBSCRIPTION_ID;
        ::gn_link_accept_cb_t cb        = nullptr;
        void*                 user_data = nullptr;
    };

    void start_accept();
    void on_accept(std::shared_ptr<Session> session,
                    const std::error_code& ec);

    void register_session(gn_conn_id_t id, std::shared_ptr<Session> s);
    void erase_session(gn_conn_id_t id);
    [[nodiscard]] bool claim_disconnect(gn_conn_id_t id);
    [[nodiscard]] std::shared_ptr<Session> find_session(gn_conn_id_t id) const;

    [[nodiscard]] static gn_trust_class_t resolve_trust(
        const asio::ip::tcp::endpoint& peer) noexcept;
    [[nodiscard]] static std::string endpoint_to_uri(
        const asio::ip::tcp::endpoint& ep);

    /// Pull cert / key PEMs out of kernel config when `api_` is
    /// bound; otherwise honour the test-fixture overrides set
    /// through `set_server_credentials`. Returns false when no
    /// credentials are available (server-side `listen` then
    /// refuses).
    [[nodiscard]] bool load_server_credentials();

    asio::io_context                                                 ioc_;
    asio::executor_work_guard<asio::io_context::executor_type>       work_;
    /// Multiple workers run the same `io_context`. Per-Session
    /// strands serialise OpenSSL state per connection — `SSL*`
    /// objects are not thread-safe, but the strand keeps every
    /// `async_write_some` / `async_read_some` on a single thread
    /// at a time. Extra threads add parallelism across
    /// connections. See `docs/impl/cpp/transports.ru.md`.
    std::vector<std::thread>                                         workers_;
    asio::ssl::context                                               server_ctx_;
    asio::ssl::context                                               client_ctx_;
    /// Set true when `set_default_verify_paths()` succeeded for the
    /// client context during `set_host_api`. False after a load
    /// failure — `connect()` refuses outbound TLS in that state
    /// unless the operator explicitly turned verify-peer off through
    /// `links.tls.verify_peer = false`. Default true so an instance
    /// built without `set_host_api` (test harnesses that drive
    /// `set_verify_peer(false)` directly) keeps working.
    bool                                                              trust_store_loaded_{true};
    /// DTLS contexts mirror their TLS siblings. OpenSSL's DTLS state
    /// machine lives entirely inside `SSL*`; the BIO_pair pump from
    /// the composer path drives both protocol families identically.
    /// Initialised lazily on first dtls:// composer call so plain-TLS
    /// deployments do not pay the cost of an unused DTLS context.
    std::optional<asio::ssl::context>                                server_ctx_dtls_;
    std::optional<asio::ssl::context>                                client_ctx_dtls_;

    std::optional<asio::ip::tcp::acceptor>                           acceptor_;
    std::atomic<std::uint16_t>                                       listen_port_{0};
    std::atomic<bool>                                                shutdown_{false};

    mutable std::mutex                                                  sessions_mu_;
    std::unordered_map<gn_conn_id_t, std::shared_ptr<Session>>          sessions_;
    /// Append-only log of every conn id ever published through
    /// `notify_connect`. The worker callbacks never touch this list;
    /// only `register_session` (under `sessions_mu_`) appends and
    /// `shutdown` moves it out under the same lock. Lets the
    /// caller-thread emit on shutdown reach every conn even when a
    /// worker callback already raced ahead of shutdown and erased
    /// the live entry. The double-emit is benign: the kernel
    /// resolves the second call through `GN_ERR_NOT_FOUND` per
    /// `host_api_builder.cpp` thunk_notify_disconnect §1604.
    std::vector<gn_conn_id_t>                                           published_ids_;

    std::atomic<std::uint64_t> bytes_in_{0};
    std::atomic<std::uint64_t> bytes_out_{0};
    std::atomic<std::uint64_t> frames_in_{0};
    std::atomic<std::uint64_t> frames_out_{0};

    /// Per-connection write-queue thresholds per `backpressure.en.md` §1.
    std::uint64_t pending_queue_bytes_low_  = 0;
    std::uint64_t pending_queue_bytes_high_ = 0;
    std::uint64_t pending_queue_bytes_hard_ = 0;

    std::string                                                      override_cert_pem_;
    /// Owns the override server private key bytes. Storage is a
    /// byte vector so the destructor and the reassignment path can
    /// `sodium_memzero` the buffer per `plugins/security/noise/docs/handshake.md` §5b —
    /// `std::string` would leave libstdc++'s internal capacity
    /// buffer unmanaged.
    std::vector<std::uint8_t>                                        override_key_pem_;

    const host_api_t* api_ = nullptr;

    /// Composer-mode state. TlsLink layers TLS over a lower-layer
    /// carrier. A single instance can serve both `tls://` (over
    /// gn.link.tcp) and `dtls://` (over gn.link.udp) — the two
    /// carriers are independent optional handles initialised on demand.
    /// Composer-owned sessions live in a separate map from kernel-
    /// managed Sessions; composer conn ids carry `kComposerIdBit`.
    std::optional<gn::sdk::LinkCarrier>                              carrier_;       /// "tcp" — TLS
    std::optional<gn::sdk::LinkCarrier>                              carrier_dtls_;  /// "udp" — DTLS
    mutable std::mutex                                               composer_mu_;
    std::unordered_map<gn_conn_id_t,
                       std::shared_ptr<ComposerSession>>             composer_sessions_;
    /// Map from L1 (carrier) conn id → composer conn id, so the
    /// carrier's on_data callback can find the matching session.
    /// L1 ids from the two carriers (tcp / udp) share a single
    /// namespace at this map level because `gn_conn_id_t` is
    /// globally unique within a process and the issuing plugin's
    /// `next_composer_id_` counters do not collide.
    std::unordered_map<gn_conn_id_t, gn_conn_id_t>                   l1_to_composer_;
    /// Per composer-id flag: this session rides the DTLS carrier
    /// rather than TCP. Used by `do_close` and `do_send` so the
    /// session can `disconnect`/`send` through the right carrier
    /// without holding a pointer to it.
    std::unordered_map<gn_conn_id_t, bool>                           composer_is_dtls_;
    std::unordered_map<gn_conn_id_t, ComposerDataSub>                composer_data_subs_;
    std::vector<ComposerAcceptSub>                                   composer_accept_subs_;
    std::atomic<std::uint64_t>                                       next_composer_id_{1};
    std::atomic<std::uint64_t>                                       next_accept_token_{1};
    /// Bound name of the active TLS carrier ("tcp"). DTLS carrier
    /// is always "udp" so it doesn't need a separate slot.
    std::string                                                      carrier_scheme_;

    [[nodiscard]] gn_result_t ensure_carrier(std::string_view scheme);
    /// Lazy-init DTLS server + client contexts on first dtls:// call.
    /// Idempotent; safe to call from both composer_listen and
    /// composer_connect.
    [[nodiscard]] gn_result_t ensure_dtls_contexts();
    /// Load server certificate + key into the given context. Honours
    /// the test-fixture override and falls back to kernel config
    /// `links.tls.cert_path` / `links.tls.key_path`. Centralised so
    /// the TLS server and DTLS server contexts share one credential
    /// pipeline.
    [[nodiscard]] bool load_server_credentials_into(
        asio::ssl::context& ctx);
    void composer_on_l1_data(gn_conn_id_t l1,
                              std::span<const std::uint8_t> bytes);
    void composer_on_l1_accept(gn_conn_id_t l1,
                                std::string_view peer_uri,
                                bool             dtls = false);
    void composer_handshake_complete(gn_conn_id_t composer_id,
                                      std::string_view peer_uri);
    void composer_drop_session(gn_conn_id_t composer_id);
};

} // namespace gn::link::tls
