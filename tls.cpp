// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/links/tls/tls.cpp
/// @brief  Implementation of the TLS transport.

#include "tls.hpp"
#include "tls_composer_session.hpp"

#include <sdk/convenience.h>
#include <sdk/cpp/dns.hpp>
#include <sdk/cpp/uri.hpp>

#include <asio/bind_executor.hpp>
#include <asio/buffer.hpp>
#include <asio/dispatch.hpp>
#include <asio/ip/v6_only.hpp>
#include <asio/read.hpp>
#include <asio/write.hpp>

#include <sodium.h>

#include <array>
#include <cstring>
#include <algorithm>
#include <deque>
#include <exception>
#include <span>
#include <sstream>
#include <thread>
#include <utility>
#include <vector>

namespace gn::link::tls {

namespace {

constexpr std::size_t kReadBufferSize = std::size_t{16} * 1024;

} // namespace

// ── Session ──────────────────────────────────────────────────────────────

class TlsLink::Session : public std::enable_shared_from_this<Session> {
public:
    enum class Mode { Server, Client };

    Session(asio::ip::tcp::socket sock,
            asio::ssl::context& ctx,
            std::weak_ptr<TlsLink> transport,
            Mode mode)
        : ssl_(std::move(sock), ctx),
          strand_(ssl_.get_executor()),
          transport_(std::move(transport)),
          mode_(mode) {}

    asio::ssl::stream<asio::ip::tcp::socket>& stream() noexcept { return ssl_; }
    asio::ip::tcp::socket::lowest_layer_type& lowest_layer() noexcept {
        return ssl_.lowest_layer();
    }

    gn_conn_id_t conn_id = GN_INVALID_ID;

    void start_handshake_then(std::function<void()> after) {
        const auto side = mode_ == Mode::Server
            ? asio::ssl::stream_base::server
            : asio::ssl::stream_base::client;
        ssl_.async_handshake(side,
            asio::bind_executor(strand_,
                [self = shared_from_this(),
                 after = std::move(after)](const std::error_code& ec) {
                    if (ec) { self->fail(); return; }
                    after();
                }));
    }

    void start_read() {
        ssl_.async_read_some(
            asio::buffer(read_buf_),
            asio::bind_executor(strand_,
                [self = shared_from_this()](
                    const std::error_code& ec, std::size_t n) {
                    auto t = self->transport_.lock();
                    if (!t) return;
                    if (ec) {
                        if (t->claim_disconnect(self->conn_id) &&
                            t->api_ && t->api_->notify_disconnect) {
                            t->api_->notify_disconnect(
                                t->api_->host_ctx, self->conn_id,
                                ec == asio::error::eof ? GN_OK : GN_ERR_NULL_ARG);
                        }
                        return;
                    }
                    if (n > 0) {
                        t->bytes_in_.fetch_add(n, std::memory_order_relaxed);
                        t->frames_in_.fetch_add(1, std::memory_order_relaxed);
                        if (t->api_ && t->api_->notify_inbound_bytes) {
                            const gn_result_t rc =
                                t->api_->notify_inbound_bytes(
                                    t->api_->host_ctx, self->conn_id,
                                    self->read_buf_.data(), n);
                            if (rc == GN_OK) {
                                self->host_api_failures_.store(
                                    0, std::memory_order_relaxed);
                            } else {
                                const auto fails =
                                    self->host_api_failures_.fetch_add(
                                        1, std::memory_order_relaxed) + 1;
                                if (fails >= 16) {
                                    if (t->claim_disconnect(self->conn_id) &&
                                        t->api_->notify_disconnect) {
                                        (void)t->api_->notify_disconnect(
                                            t->api_->host_ctx,
                                            self->conn_id, GN_OK);
                                    }
                                    return;
                                }
                            }
                        }
                    }
                    self->start_read();
                }));
    }

    void do_send(std::span<const std::uint8_t> data) {
        auto buf = std::make_shared<std::vector<std::uint8_t>>(
            data.begin(), data.end());
        const auto added = buf->size();
        const auto post = bytes_buffered_.fetch_add(
            added, std::memory_order_relaxed) + added;
        maybe_signal_soft(post);
        asio::dispatch(strand_,
            [self = shared_from_this(), buf = std::move(buf)]() mutable {
                self->write_queue_.push_back(std::move(buf));
                self->maybe_start_write();
            });
    }

    void do_send_batch(std::span<const std::span<const std::uint8_t>> frames) {
        std::size_t total = 0;
        for (auto& f : frames) total += f.size();
        auto buf = std::make_shared<std::vector<std::uint8_t>>(total);
        std::size_t offset = 0;
        for (auto& f : frames) {
            std::memcpy(buf->data() + offset, f.data(), f.size());
            offset += f.size();
        }
        const auto added = buf->size();
        const auto post = bytes_buffered_.fetch_add(
            added, std::memory_order_relaxed) + added;
        maybe_signal_soft(post);
        asio::dispatch(strand_,
            [self = shared_from_this(), buf = std::move(buf)]() mutable {
                self->write_queue_.push_back(std::move(buf));
                self->maybe_start_write();
            });
    }

    [[nodiscard]] std::uint64_t bytes_buffered() const noexcept {
        return bytes_buffered_.load(std::memory_order_relaxed);
    }

    void maybe_signal_soft(std::uint64_t post) {
        auto t = transport_.lock();
        if (!t) return;
        if (t->pending_queue_bytes_high_ == 0) return;
        if (post <= t->pending_queue_bytes_high_) return;
        bool expected = false;
        if (!soft_signaled_.compare_exchange_strong(
                expected, true, std::memory_order_acq_rel)) {
            return;
        }
        if (t->api_ && t->api_->notify_backpressure) {
            (void)t->api_->notify_backpressure(
                t->api_->host_ctx, conn_id,
                GN_CONN_EVENT_BACKPRESSURE_SOFT, post);
        }
    }
    void maybe_signal_clear(std::uint64_t post) {
        auto t = transport_.lock();
        if (!t) return;
        if (t->pending_queue_bytes_low_ == 0) return;
        if (post >= t->pending_queue_bytes_low_) return;
        bool expected = true;
        if (!soft_signaled_.compare_exchange_strong(
                expected, false, std::memory_order_acq_rel)) {
            return;
        }
        if (t->api_ && t->api_->notify_backpressure) {
            (void)t->api_->notify_backpressure(
                t->api_->host_ctx, conn_id,
                GN_CONN_EVENT_BACKPRESSURE_CLEAR, post);
        }
    }

    void do_close() {
        asio::dispatch(strand_, [self = shared_from_this()] {
            /// `async_shutdown` writes the TLS close_notify alert
            /// and waits for the peer's matching alert (or the
            /// underlying transport teardown) before completing.
            /// The synchronous `shutdown()` returned immediately
            /// without flushing the alert under common asio
            /// configurations, so the peer saw a TCP RST instead
            /// of a graceful close — RFC 5246 §7.2.1 requires the
            /// alert exchange for clean session resumption.
            ///
            /// The completion handler closes the FD regardless of
            /// the alert outcome; an idempotent close is the
            /// correct shape since the strand owns the socket and
            /// no other path holds a reference past `do_close`.
            self->ssl_.async_shutdown(
                asio::bind_executor(self->strand_,
                    [self](const std::error_code& /*shutdown_ec*/) {
                        std::error_code close_ec;
                        if (self->lowest_layer().close(close_ec)) {}
                    }));
        });
    }

private:
    void maybe_start_write() {
        if (write_in_flight_ || write_queue_.empty()) return;
        write_in_flight_ = true;
        auto buf = write_queue_.front();
        const std::size_t buf_size = buf->size();
        asio::async_write(ssl_, asio::buffer(*buf),
            asio::bind_executor(strand_,
                [self = shared_from_this(), buf, buf_size](
                    const std::error_code& ec, std::size_t n) {
                    self->write_queue_.pop_front();
                    self->write_in_flight_ = false;
                    const auto post = self->bytes_buffered_.fetch_sub(
                        buf_size, std::memory_order_relaxed) - buf_size;
                    self->maybe_signal_clear(post);
                    auto t = self->transport_.lock();
                    if (!t) return;
                    if (ec) {
                        if (t->claim_disconnect(self->conn_id) &&
                            t->api_ && t->api_->notify_disconnect) {
                            t->api_->notify_disconnect(
                                t->api_->host_ctx, self->conn_id, GN_ERR_NULL_ARG);
                        }
                        return;
                    }
                    t->bytes_out_.fetch_add(n, std::memory_order_relaxed);
                    t->frames_out_.fetch_add(1, std::memory_order_relaxed);
                    self->maybe_start_write();
                }));
    }

    void fail() {
        auto t = transport_.lock();
        if (t && conn_id != GN_INVALID_ID &&
            t->claim_disconnect(conn_id) &&
            t->api_ && t->api_->notify_disconnect) {
            t->api_->notify_disconnect(t->api_->host_ctx, conn_id, GN_OK);
        }
        std::error_code ec;
        if (lowest_layer().close(ec)) {}
    }

    asio::ssl::stream<asio::ip::tcp::socket>           ssl_;
    asio::strand<asio::any_io_executor>                strand_;
    std::weak_ptr<TlsLink>                        transport_;
    Mode                                                mode_;

    std::array<std::uint8_t, kReadBufferSize>          read_buf_{};
    std::deque<std::shared_ptr<std::vector<std::uint8_t>>> write_queue_;
    bool                                                write_in_flight_ = false;
    std::atomic<std::uint64_t>                          bytes_buffered_{0};
    std::atomic<bool>                                   soft_signaled_{false};
    /// Consecutive non-OK results from `notify_inbound_bytes`;
    /// 16 in a row disconnects the conn so a peer that floods
    /// the security layer with garbage cannot keep it alive.
    std::atomic<std::uint32_t>                          host_api_failures_{0};
};

// ── TlsLink ──────────────────────────────────────────────────────────────
// `class TlsLink::ComposerSession` definition lives out-of-line so
// the BIO pump can grow without bloating this TU; declaration in
// `tls.hpp` (forward) and the body in `tls_composer_session.{hpp,cpp}`
// — included above.

TlsLink::TlsLink()
    : ioc_(),
      work_(asio::make_work_guard(ioc_)),
      server_ctx_(asio::ssl::context::tls_server),
      client_ctx_(asio::ssl::context::tls_client) {
    /// TLS 1.3 minimum on both sides — enforced by disabling every
    /// pre-1.3 protocol version explicitly. A peer that only speaks
    /// pre-1.3 fails the handshake at hello rather than silently
    /// negotiating an obsolete suite. Compression disabled (CRIME /
    /// BREAST mitigation; default at `tls_*_method` but explicit
    /// here so future context migrations don't drop it).
    server_ctx_.set_options(asio::ssl::context::default_workarounds |
                             asio::ssl::context::no_sslv2 |
                             asio::ssl::context::no_sslv3 |
                             asio::ssl::context::no_tlsv1 |
                             asio::ssl::context::no_tlsv1_1 |
                             asio::ssl::context::no_tlsv1_2 |
                             asio::ssl::context::no_compression);
    client_ctx_.set_options(asio::ssl::context::default_workarounds |
                             asio::ssl::context::no_sslv2 |
                             asio::ssl::context::no_sslv3 |
                             asio::ssl::context::no_tlsv1 |
                             asio::ssl::context::no_tlsv1_1 |
                             asio::ssl::context::no_tlsv1_2 |
                             asio::ssl::context::no_compression);
    /// Default-secure: clients verify the peer certificate against
    /// OpenSSL's default trust store. The trust store load happens
    /// in `set_host_api` so a load failure can surface through the
    /// host log; here only the verify-mode bit is set so the
    /// invariant holds even if `set_host_api` never runs.
    client_ctx_.set_verify_mode(asio::ssl::verify_peer);

    /// Worker pool sized symmetrically with the other link plugins;
    /// per-Session strands keep the per-conn `SSL*` access
    /// single-threaded.
    const unsigned hc = std::thread::hardware_concurrency();
    const unsigned n  = std::max(1u, hc / 2);
    workers_.reserve(n);
    for (unsigned i = 0; i < n; ++i) {
        workers_.emplace_back([this] { ioc_.run(); });
    }
}

TlsLink::~TlsLink() {
    try { shutdown(); }
    catch (const std::exception& e) {
        if (api_) {
            gn_log_warn(api_, "tls: shutdown threw: %s", e.what());
        }
    } catch (...) {
        if (api_) {
            gn_log_warn(api_, "tls: shutdown threw non-std exception");
        }
    }
    /// Per plugins/security/noise/docs/handshake.md §5b: the override server private key
    /// has no remaining purpose once the transport tears down.
    /// Wipe the buffer before the vector frees its storage so the
    /// freed allocation does not carry the secret into the
    /// allocator's free list.
    sodium_memzero(override_key_pem_.data(), override_key_pem_.size());
}

void TlsLink::set_host_api(const host_api_t* api) noexcept {
    api_ = api;
    if (api_ != nullptr && api_->limits != nullptr) {
        if (const auto* L = api_->limits(api_->host_ctx); L != nullptr) {
            pending_queue_bytes_low_  = L->pending_queue_bytes_low;
            pending_queue_bytes_high_ = L->pending_queue_bytes_high;
            pending_queue_bytes_hard_ = L->pending_queue_bytes_hard;
        }
    }
    /// Default-secure baseline: re-bind always restarts in
    /// verify_peer mode, then the config opt-out check may flip to
    /// verify_none. Without this reset, an api swap from a verify-
    /// none deployment to one without the config key would leave
    /// the previous opt-out in force.
    set_verify_peer(true);
    trust_store_loaded_ = true;
    try {
        client_ctx_.set_default_verify_paths();
    } catch (const std::exception& e) {
        trust_store_loaded_ = false;
        if (api_ != nullptr) {
            gn_log_warn(api_,
                "tls: default trust store load failed: %s; "
                "connect() will refuse outbound TLS until "
                "links.tls.verify_peer is set false or a "
                "trust bundle is loaded explicitly", e.what());
        }
    } catch (...) {
        trust_store_loaded_ = false;
        if (api_ != nullptr) {
            gn_log_warn(api_,
                "tls: default trust store load failed: unknown "
                "exception; connect() will refuse outbound TLS "
                "until links.tls.verify_peer is set false");
        }
    }
    /// Honour `links.tls.verify_peer` config opt-out. The flag
    /// defaults to true (verify peer cert against the OpenSSL trust
    /// store); explicit `false` switches to verify_none for the
    /// TLS-as-link-encryption-beneath-Noise stack.
    if (api_ != nullptr && api_->config_get != nullptr) {
        std::int32_t v = 1;
        if (gn_config_get_bool(api_, "links.tls.verify_peer", &v) == GN_OK) {
            set_verify_peer(v != 0);
        }
    }
}
void TlsLink::set_server_credentials(std::string_view cert_pem,
                                           std::string_view key_pem) {
    override_cert_pem_.assign(cert_pem.begin(), cert_pem.end());
    /// Per plugins/security/noise/docs/handshake.md §5b: zeroise the previous key bytes
    /// before the new bytes overwrite them. A shorter replacement
    /// would otherwise leave a tail of the old secret in process
    /// memory.
    sodium_memzero(override_key_pem_.data(), override_key_pem_.size());
    override_key_pem_.assign(
        reinterpret_cast<const std::uint8_t*>(key_pem.data()),
        reinterpret_cast<const std::uint8_t*>(key_pem.data() + key_pem.size()));
}

bool TlsLink::key_pem_zeroised_for_test() const noexcept {
    if (override_key_pem_.empty()) return true;
    return sodium_is_zero(override_key_pem_.data(),
                           override_key_pem_.size()) != 0;
}
void TlsLink::set_verify_peer(bool on) noexcept {
    /// `set_verify_mode` is `noexcept`-incompatible in older asio
    /// builds; swallow any throw rather than propagate, since the
    /// caller's intent is "best-effort policy update".
    try {
        client_ctx_.set_verify_mode(
            on ? asio::ssl::verify_peer : asio::ssl::verify_none);
    } catch (const std::exception& e) {
        if (api_) {
            gn_log_warn(api_, "tls: set_verify_mode threw: %s", e.what());
        }
    }
}

std::uint16_t TlsLink::listen_port() const noexcept {
    return listen_port_.load(std::memory_order_acquire);
}

std::size_t TlsLink::session_count() const noexcept {
    std::lock_guard lk(sessions_mu_);
    return sessions_.size();
}

TlsLink::Stats TlsLink::stats() const noexcept {
    Stats s{};
    s.bytes_in           = bytes_in_.load(std::memory_order_relaxed);
    s.bytes_out          = bytes_out_.load(std::memory_order_relaxed);
    s.frames_in          = frames_in_.load(std::memory_order_relaxed);
    s.frames_out         = frames_out_.load(std::memory_order_relaxed);
    s.active_connections = session_count();
    return s;
}

gn_link_caps_t TlsLink::capabilities() noexcept {
    gn_link_caps_t c{};
    c.flags       = GN_LINK_CAP_STREAM
                  | GN_LINK_CAP_RELIABLE
                  | GN_LINK_CAP_ORDERED
                  | GN_LINK_CAP_ENCRYPTED_PATH;
    c.max_payload = 0;
    return c;
}

gn_trust_class_t TlsLink::resolve_trust(
    const asio::ip::tcp::endpoint& peer) noexcept {
    if (peer.address().is_loopback()) return GN_TRUST_LOOPBACK;
    return GN_TRUST_UNTRUSTED;
}

std::string TlsLink::endpoint_to_uri(
    const asio::ip::tcp::endpoint& ep) {
    std::ostringstream s;
    s << "tls://";
    if (ep.address().is_v6()) {
        s << '[' << ep.address().to_string() << ']';
    } else {
        s << ep.address().to_string();
    }
    s << ':' << ep.port();
    return s.str();
}

bool TlsLink::load_server_credentials_into(asio::ssl::context& ctx) {
    /// Test-fixture override wins so unit tests stay independent
    /// of the kernel config. Production paths flow through
    /// `host_api->config_get` with `GN_CONFIG_VALUE_STRING`.
    if (!override_cert_pem_.empty() && !override_key_pem_.empty()) {
        try {
            ctx.use_certificate_chain(
                asio::buffer(override_cert_pem_));
            ctx.use_private_key(
                asio::buffer(override_key_pem_.data(),
                              override_key_pem_.size()),
                asio::ssl::context::pem);
            return true;
        } catch (...) {
            return false;
        }
    }
    if (!api_ || !api_->config_get) return false;

    char* cert_path = nullptr;
    void* cert_user_data = nullptr;
    void (*cert_free)(void*, void*) = nullptr;
    if (gn_config_get_string(api_, "links.tls.cert_path",
                              &cert_path, &cert_user_data,
                              &cert_free) != GN_OK ||
        !cert_path) {
        return false;
    }
    char* key_path = nullptr;
    void* key_user_data = nullptr;
    void (*key_free)(void*, void*) = nullptr;
    if (gn_config_get_string(api_, "links.tls.key_path",
                              &key_path, &key_user_data,
                              &key_free) != GN_OK ||
        !key_path) {
        if (cert_free) cert_free(cert_user_data, cert_path);
        return false;
    }
    bool ok = false;
    try {
        ctx.use_certificate_chain_file(cert_path);
        ctx.use_private_key_file(key_path,
            asio::ssl::context::pem);
        ok = true;
    } catch (...) {
        ok = false;
    }
    if (cert_free) cert_free(cert_user_data, cert_path);
    if (key_free)  key_free(key_user_data, key_path);
    return ok;
}

bool TlsLink::load_server_credentials() {
    /// TLS-side credential load. Honours the eager-wipe contract per
    /// `plugins/security/noise/docs/handshake.md` §5b: once OpenSSL
    /// has copied the override key into the context, wipe the
    /// override buffer so the secret does not linger in process
    /// memory. Callers that also need DTLS credentials must re-set
    /// the override through `set_server_credentials` before the
    /// dtls:// path triggers `load_server_credentials_into`.
    if (!load_server_credentials_into(server_ctx_)) return false;
    if (!override_key_pem_.empty()) {
        sodium_memzero(override_key_pem_.data(),
                        override_key_pem_.size());
        override_key_pem_.clear();
    }
    return true;
}

gn_result_t TlsLink::listen(std::string_view uri) {
    if (shutdown_.load(std::memory_order_acquire)) return GN_ERR_NULL_ARG;

    /// Server cert + key must be loadable before bind; otherwise a
    /// peer's TLS handshake fails after socket connect, which is a
    /// noisier failure than refusing to bind.
    if (!load_server_credentials()) return GN_ERR_NOT_IMPLEMENTED;

    const auto parts = ::gn::parse_uri(uri);
    if (!parts || parts->scheme != "tls" || parts->is_path_style()) {
        return GN_ERR_INVALID_ENVELOPE;
    }
    if (parts->host.empty()) return GN_ERR_INVALID_ENVELOPE;

    asio::ip::tcp::endpoint ep;
    try {
        ep = asio::ip::tcp::endpoint(asio::ip::make_address(parts->host),
                                      parts->port);
    } catch (const std::exception&) {
        return GN_ERR_INVALID_ENVELOPE;
    }

    std::error_code ec;
    asio::ip::tcp::acceptor acc(ioc_);
    if (acc.open(ep.protocol(), ec)) return GN_ERR_NULL_ARG;
    /// IPv6 wildcard `::` — disable `IPV6_V6ONLY` so dual-stack
    /// listens accept v4-mapped clients on Linux. set_option is
    /// best-effort: pre-Linux-3.x kernels lack the option and a
    /// v4-only fallback is the documented behaviour. Specific v6
    /// literals stay v6-only by default.
    if (ep.address().is_v6() && ep.address().is_unspecified()) {
        std::error_code v6_ec;
        // NOLINTNEXTLINE(bugprone-unused-return-value,cert-err33-c)
        acc.set_option(asio::ip::v6_only(false), v6_ec);
        if (v6_ec && api_) {
            gn_log_debug(api_, "tls: v6_only(false) failed: %s",
                         v6_ec.message().c_str());
        }
    }
    if (acc.set_option(asio::ip::tcp::acceptor::reuse_address(true), ec)) {
        return GN_ERR_LIMIT_REACHED;
    }
    if (acc.bind(ep, ec)) return GN_ERR_LIMIT_REACHED;
    if (acc.listen(asio::socket_base::max_listen_connections, ec)) {
        return GN_ERR_LIMIT_REACHED;
    }
    listen_port_.store(acc.local_endpoint().port(),
                        std::memory_order_release);
    acceptor_.emplace(std::move(acc));
    start_accept();
    return GN_OK;
}

void TlsLink::start_accept() {
    if (shutdown_.load(std::memory_order_acquire) || !acceptor_) return;

    auto session = std::make_shared<Session>(
        asio::ip::tcp::socket(ioc_),
        server_ctx_,
        weak_from_this(),
        Session::Mode::Server);
    if (!acceptor_.has_value()) return;
    auto& sock = session->lowest_layer();
    acceptor_->async_accept(sock,
        [weak = weak_from_this(),
         session = std::move(session)](const std::error_code& ec) mutable {
            if (auto t = weak.lock()) t->on_accept(std::move(session), ec);
        });
}

void TlsLink::on_accept(std::shared_ptr<Session> session,
                              const std::error_code& ec) {
    if (ec || shutdown_.load(std::memory_order_acquire)) return;

    std::error_code re_ec;
    const auto remote = session->lowest_layer().remote_endpoint(re_ec);
    if (re_ec) {
        session->do_close();
        start_accept();
        return;
    }

    /// Disable Nagle on the underlying TCP socket before the TLS
    /// handshake runs. Small framed messages must not wait on the
    /// kernel's coalescing timer; the LAN baseline depends on
    /// every frame leaving immediately. Best-effort.
    std::error_code nodelay_ec;
    // NOLINTNEXTLINE(bugprone-unused-return-value,cert-err33-c)
    session->lowest_layer().set_option(
        asio::ip::tcp::no_delay{true}, nodelay_ec);
    if (nodelay_ec && api_) {
        gn_log_debug(api_, "tls: TCP_NODELAY refused: %s",
                     nodelay_ec.message().c_str());
    }

    session->start_handshake_then([weak = weak_from_this(),
                                    session = std::move(session), remote] {
        auto t = weak.lock();
        if (!t || !t->api_ || !t->api_->notify_connect) {
            session->do_close();
            return;
        }
        std::uint8_t remote_pk[GN_PUBLIC_KEY_BYTES] = {};
        gn_conn_id_t conn = GN_INVALID_ID;
        const std::string uri = TlsLink::endpoint_to_uri(remote);
        const gn_result_t rc = t->api_->notify_connect(
            t->api_->host_ctx, remote_pk, uri.c_str(),
            TlsLink::resolve_trust(remote),
            GN_ROLE_RESPONDER, &conn);
        if (rc == GN_OK && conn != GN_INVALID_ID) {
            session->conn_id = conn;
            t->register_session(conn, session);
            session->start_read();
        } else {
            session->do_close();
        }
    });
    start_accept();
}

gn_result_t TlsLink::connect(std::string_view uri) {
    if (shutdown_.load(std::memory_order_acquire)) return GN_ERR_NULL_ARG;

    /// Fail-closed: if the default trust store could not be loaded
    /// during `set_host_api` and the operator did not opt out of
    /// peer verification through `links.tls.verify_peer = false`,
    /// refuse the connect up front rather than queue an
    /// `SSL_VERIFY_PEER` handshake that will fail at the OpenSSL
    /// layer with a generic certificate-verify error.
    if (!trust_store_loaded_) {
        const int vm = SSL_CTX_get_verify_mode(client_ctx_.native_handle());
        if ((vm & SSL_VERIFY_PEER) != 0) {
            if (api_) {
                gn_log_error(api_,
                    "tls: refusing connect — no trust store loaded "
                    "and verify_peer is on; set "
                    "links.tls.verify_peer = false to override");
            }
            return GN_ERR_INVALID_STATE;
        }
    }

    /// Hostname → IP literal up-front per `dns.md` §1; the rest of
    /// the connect path expects a literal-host URI so the OpenSSL
    /// certificate-name match (when enabled) sees the same identity
    /// the connection registry will key on.
    auto resolved = ::gn::sdk::resolve_uri_host(ioc_, uri);
    if (!resolved) return GN_ERR_INVALID_ENVELOPE;

    const auto parts = ::gn::parse_uri(*resolved);
    if (!parts || parts->scheme != "tls" || parts->is_path_style()) {
        return GN_ERR_INVALID_ENVELOPE;
    }
    if (parts->host.empty()) return GN_ERR_INVALID_ENVELOPE;
    if (parts->port == 0) return GN_ERR_INVALID_ENVELOPE;

    asio::ip::tcp::endpoint ep;
    try {
        ep = asio::ip::tcp::endpoint(asio::ip::make_address(parts->host),
                                      parts->port);
    } catch (const std::exception&) {
        return GN_ERR_INVALID_ENVELOPE;
    }

    auto session = std::make_shared<Session>(
        asio::ip::tcp::socket(ioc_),
        client_ctx_,
        weak_from_this(),
        Session::Mode::Client);
    auto& sock = session->lowest_layer();
    std::error_code open_ec;
    if (sock.open(ep.protocol(), open_ec)) return GN_ERR_NULL_ARG;
    sock.async_connect(ep,
        [weak = weak_from_this(),
         session, ep](const std::error_code& cec) mutable {
            if (cec) {
                /// Connect failed before any `notify_connect` —
                /// kernel has no record to release. Operator
                /// diagnostic only; per `link.md` §9 a connect
                /// failure is not a session release event but
                /// still must be observable.
                if (auto t = weak.lock(); t && t->api_) {
                    gn_log_warn(t->api_,
                        "tls: connect to %s failed: %s",
                        TlsLink::endpoint_to_uri(ep).c_str(),
                        cec.message().c_str());
                }
                return;
            }
            auto t = weak.lock();
            if (!t || t->shutdown_.load(std::memory_order_acquire)) {
                session->do_close();
                return;
            }
            /// Disable Nagle on the outbound side, mirroring the
            /// accept path. Best-effort.
            std::error_code nodelay_ec;
            // NOLINTNEXTLINE(bugprone-unused-return-value,cert-err33-c)
            session->lowest_layer().set_option(
                asio::ip::tcp::no_delay{true}, nodelay_ec);
            if (nodelay_ec && t->api_) {
                gn_log_debug(t->api_, "tls: TCP_NODELAY refused: %s",
                             nodelay_ec.message().c_str());
            }
            session->start_handshake_then(
                [weak, session, ep]() mutable {
                    auto tr = weak.lock();
                    if (!tr || !tr->api_ || !tr->api_->notify_connect) {
                        session->do_close();
                        return;
                    }
                    std::uint8_t remote_pk[GN_PUBLIC_KEY_BYTES] = {};
                    gn_conn_id_t conn = GN_INVALID_ID;
                    const std::string peer_uri = TlsLink::endpoint_to_uri(ep);
                    const gn_result_t rc = tr->api_->notify_connect(
                        tr->api_->host_ctx, remote_pk, peer_uri.c_str(),
                        TlsLink::resolve_trust(ep),
                        GN_ROLE_INITIATOR, &conn);
                    if (rc != GN_OK || conn == GN_INVALID_ID) {
                        session->do_close();
                        return;
                    }
                    session->conn_id = conn;
                    tr->register_session(conn, session);
                    session->start_read();
                    if (tr->api_->kick_handshake) {
                        (void)tr->api_->kick_handshake(
                            tr->api_->host_ctx, conn);
                    }
                });
        });
    return GN_OK;
}

gn_result_t TlsLink::send(gn_conn_id_t conn,
                                std::span<const std::uint8_t> bytes) {
    if (conn & kComposerIdBit) {
        std::shared_ptr<ComposerSession> cs;
        {
            std::lock_guard lk(composer_mu_);
            auto it = composer_sessions_.find(conn);
            if (it == composer_sessions_.end()) return GN_ERR_NOT_FOUND;
            cs = it->second;
        }
        return cs->do_send(bytes);
    }
    auto session = find_session(conn);
    if (!session) return GN_ERR_NOT_FOUND;
    if (pending_queue_bytes_hard_ != 0 &&
        session->bytes_buffered() + bytes.size() >
            pending_queue_bytes_hard_) {
        if (api_) {
            if (api_->emit_counter) {
                api_->emit_counter(api_->host_ctx, "drop.queue_hard_cap");
            }
            gn_log_warn(api_,
                "tls.send: queue hard cap — conn=%llu buffered=%zu add=%zu hard=%zu",
                static_cast<unsigned long long>(conn),
                session->bytes_buffered(),
                bytes.size(),
                pending_queue_bytes_hard_);
        }
        return GN_ERR_LIMIT_REACHED;
    }
    session->do_send(bytes);
    return GN_OK;
}

gn_result_t TlsLink::send_batch(
    gn_conn_id_t conn,
    std::span<const std::span<const std::uint8_t>> frames) {
    if (frames.empty()) return GN_OK;
    if (frames.size() == 1) return send(conn, frames[0]);
    if (conn & kComposerIdBit) {
        // Composer path coalesces the batch into one SSL_write —
        // the consumer (WSS, ICE, ...) applies its own framing.
        std::vector<std::uint8_t> flat;
        std::size_t total = 0;
        for (const auto& f : frames) total += f.size();
        flat.reserve(total);
        for (const auto& f : frames) flat.insert(flat.end(), f.begin(), f.end());
        return send(conn, std::span<const std::uint8_t>(flat));
    }
    auto session = find_session(conn);
    if (!session) return GN_ERR_NOT_FOUND;
    std::size_t total = 0;
    for (const auto& f : frames) total += f.size();
    if (pending_queue_bytes_hard_ != 0 &&
        session->bytes_buffered() + total > pending_queue_bytes_hard_) {
        if (api_) {
            if (api_->emit_counter) {
                api_->emit_counter(api_->host_ctx, "drop.queue_hard_cap");
            }
            gn_log_warn(api_,
                "tls.send_batch: queue hard cap — conn=%llu buffered=%zu add=%zu hard=%zu",
                static_cast<unsigned long long>(conn),
                session->bytes_buffered(),
                total,
                pending_queue_bytes_hard_);
        }
        return GN_ERR_LIMIT_REACHED;
    }
    session->do_send_batch(frames);
    return GN_OK;
}

gn_result_t TlsLink::disconnect(gn_conn_id_t conn) {
    if (conn & kComposerIdBit) {
        std::shared_ptr<ComposerSession> cs;
        {
            std::lock_guard lk(composer_mu_);
            auto it = composer_sessions_.find(conn);
            if (it == composer_sessions_.end()) return GN_OK;
            cs = std::move(it->second);
            l1_to_composer_.erase(cs->l1_id());
            composer_sessions_.erase(it);
            composer_data_subs_.erase(conn);
        }
        cs->do_close();
        return GN_OK;
    }
    std::shared_ptr<Session> session;
    {
        std::lock_guard lk(sessions_mu_);
        auto it = sessions_.find(conn);
        if (it == sessions_.end()) return GN_OK;
        session = std::move(it->second);
        sessions_.erase(it);
    }
    session->do_close();
    return GN_OK;
}

// ── Composer L2 surface ─────────────────────────────────────────────────

gn_result_t TlsLink::composer_listen_port(
    std::uint16_t* out_port) const noexcept {
    if (!out_port) return GN_ERR_NULL_ARG;
    *out_port = 0;
    /// Prefer the TLS carrier port when both are bound (legacy
    /// single-scheme deployments); DTLS-only deployments fall through
    /// to the UDP carrier. The two never collide because a TlsLink
    /// instance that serves both protocols binds two independent
    /// ephemeral ports — callers that need to distinguish should
    /// query the right carrier explicitly through the SDK helper.
    if (carrier_) {
        const auto port = carrier_->listen_port();
        if (port != 0) { *out_port = port; return GN_OK; }
    }
    if (carrier_dtls_) {
        const auto port = carrier_dtls_->listen_port();
        if (port != 0) { *out_port = port; return GN_OK; }
    }
    return GN_ERR_INVALID_STATE;
}

gn_result_t TlsLink::ensure_carrier(std::string_view scheme) {
    /// DTLS rides the `udp` carrier; TLS rides `tcp`. The two are
    /// independent optional handles so a single TlsLink instance can
    /// concurrently serve `tls://` and `dtls://` sessions without
    /// rebinding either carrier.
    if (scheme == "udp") {
        if (carrier_dtls_) return GN_OK;
        if (!api_) return GN_ERR_INVALID_STATE;
        auto opt = gn::sdk::LinkCarrier::query(api_, "udp");
        if (!opt) return GN_ERR_NOT_FOUND;
        carrier_dtls_.emplace(std::move(*opt));
        return GN_OK;
    }

    if (carrier_) {
        if (!carrier_scheme_.empty() && carrier_scheme_ != scheme) {
            return GN_ERR_INVALID_STATE;
        }
        return GN_OK;
    }
    if (!api_) return GN_ERR_INVALID_STATE;
    auto opt = gn::sdk::LinkCarrier::query(api_, scheme);
    if (!opt) return GN_ERR_NOT_FOUND;
    carrier_.emplace(std::move(*opt));
    carrier_scheme_ = std::string(scheme);
    return GN_OK;
}

namespace {

void apply_protocol_options(asio::ssl::context& ctx, bool dtls) noexcept {
    /// Family-aware option mask: TLS contexts disable every pre-1.3
    /// version explicitly. DTLS contexts only have DTLS 1.0 / 1.2 /
    /// (1.3 in OpenSSL 3.2+) to choose from — the no_tlsv* flags are
    /// no-ops on DTLS contexts and the no_compression flag is still
    /// meaningful (CRIME class mitigations still apply).
    auto opts = asio::ssl::context::default_workarounds |
                asio::ssl::context::no_sslv2 |
                asio::ssl::context::no_sslv3 |
                asio::ssl::context::no_compression;
    if (!dtls) {
        opts |= asio::ssl::context::no_tlsv1 |
                asio::ssl::context::no_tlsv1_1 |
                asio::ssl::context::no_tlsv1_2;
    }
    ctx.set_options(opts);
}

}  // namespace

gn_result_t TlsLink::ensure_dtls_contexts() {
    /// Lazy init: zero allocation cost for TLS-only deployments,
    /// constructed on the first dtls:// composer call. asio 1.36
    /// does not expose a `dtls_*` enum on `context::method`; we
    /// construct the OpenSSL `SSL_CTX*` directly via `DTLS_method()`
    /// and hand it to asio's native-handle constructor, which takes
    /// ownership and free's it through `SSL_CTX_free` in the
    /// context dtor.
    if (!server_ctx_dtls_) {
        SSL_CTX* raw = SSL_CTX_new(DTLS_method());
        if (!raw) return GN_ERR_NULL_ARG;
        try {
            server_ctx_dtls_.emplace(raw);  // takes ownership
            apply_protocol_options(*server_ctx_dtls_, /*dtls=*/true);
        } catch (...) {
            /// asio's ctor `free`s the handle on throw; emplace
            /// failure leaves the optional empty.
            server_ctx_dtls_.reset();
            return GN_ERR_NULL_ARG;
        }
    }
    if (!client_ctx_dtls_) {
        SSL_CTX* raw = SSL_CTX_new(DTLS_method());
        if (!raw) return GN_ERR_NULL_ARG;
        try {
            client_ctx_dtls_.emplace(raw);  // takes ownership
            apply_protocol_options(*client_ctx_dtls_, /*dtls=*/true);
            /// Mirror the verify-mode of the TLS client side so a
            /// deployment that flipped `links.tls.verify_peer` to
            /// false picks up the same opt-out for DTLS without a
            /// second config key. asio 1.36 has `set_verify_mode`
            /// but no `get_verify_mode`; read directly from the
            /// OpenSSL handle.
            const int vm = SSL_CTX_get_verify_mode(
                client_ctx_.native_handle());
            asio::ssl::verify_mode vmask =
                static_cast<asio::ssl::verify_mode>(vm);
            client_ctx_dtls_->set_verify_mode(vmask);
            try {
                client_ctx_dtls_->set_default_verify_paths();
            } catch (...) {
                /// Mirror the TLS-side behaviour: load failure is
                /// logged but does not block context construction —
                /// peers may opt out of verify_peer through config.
            }
        } catch (...) {
            client_ctx_dtls_.reset();
            return GN_ERR_NULL_ARG;
        }
    }
    return GN_OK;
}

gn_result_t TlsLink::composer_listen(std::string_view uri) {
    if (shutdown_.load(std::memory_order_acquire)) {
        return GN_ERR_INVALID_STATE;
    }
    const bool dtls = uri.starts_with("dtls://");
    const bool tls  = uri.starts_with("tls://");
    if (!tls && !dtls) return GN_ERR_INVALID_ENVELOPE;

    const std::string_view scheme       = dtls ? "udp" : "tcp";
    const std::size_t      prefix_len   = dtls ? 7 : 6;
    const std::string      l1_prefix    = dtls ? "udp://" : "tcp://";

    if (const auto rc = ensure_carrier(scheme); rc != GN_OK) return rc;
    if (dtls) {
        if (const auto rc = ensure_dtls_contexts(); rc != GN_OK) return rc;
        if (!load_server_credentials_into(*server_ctx_dtls_)) {
            return GN_ERR_NULL_ARG;
        }
        if (!override_key_pem_.empty()) {
            sodium_memzero(override_key_pem_.data(),
                            override_key_pem_.size());
            override_key_pem_.clear();
        }
    } else {
        if (!load_server_credentials()) return GN_ERR_NULL_ARG;
    }

    const std::string l1_uri =
        l1_prefix + std::string(uri.substr(prefix_len));

    auto& carrier = dtls ? *carrier_dtls_ : *carrier_;
    auto self_weak = weak_from_this();
    /// Capture by-value so the accept callback dispatches against
    /// the right family even if a later composer_listen flips the
    /// active carrier scheme.
    const auto rc = carrier.on_accept(
        [self_weak, dtls](gn_conn_id_t l1, std::string_view peer_uri) {
            if (auto t = self_weak.lock()) {
                t->composer_on_l1_accept(l1, peer_uri, dtls);
            }
        });
    if (rc != GN_OK) return rc;
    return carrier.listen(l1_uri);
}

gn_result_t TlsLink::composer_connect(std::string_view uri,
                                       gn_conn_id_t* out_conn) {
    if (!out_conn) return GN_ERR_NULL_ARG;
    *out_conn = GN_INVALID_ID;
    if (shutdown_.load(std::memory_order_acquire)) {
        return GN_ERR_INVALID_STATE;
    }
    const bool dtls = uri.starts_with("dtls://");
    const bool tls  = uri.starts_with("tls://");
    if (!tls && !dtls) return GN_ERR_INVALID_ENVELOPE;

    const std::string_view scheme     = dtls ? "udp" : "tcp";
    const std::size_t      prefix_len = dtls ? 7 : 6;
    const std::string      l1_prefix  = dtls ? "udp://" : "tcp://";

    if (const auto rc = ensure_carrier(scheme); rc != GN_OK) return rc;
    if (dtls) {
        if (const auto rc = ensure_dtls_contexts(); rc != GN_OK) return rc;
    }

    const std::string l1_uri =
        l1_prefix + std::string(uri.substr(prefix_len));

    auto& carrier = dtls ? *carrier_dtls_ : *carrier_;

    gn_conn_id_t l1 = GN_INVALID_ID;
    const auto rc = carrier.connect(l1_uri, &l1);
    if (rc != GN_OK) return rc;

    SSL_CTX* ctx = dtls ? client_ctx_dtls_->native_handle()
                        : client_ctx_.native_handle();

    const gn_conn_id_t composer_id =
        next_composer_id_.fetch_add(1, std::memory_order_relaxed) |
        kComposerIdBit;
    auto cs = std::make_shared<ComposerSession>(
        ctx, ComposerSession::Mode::Client,
        l1, composer_id, weak_from_this(), dtls);
    {
        std::lock_guard lk(composer_mu_);
        composer_sessions_[composer_id] = cs;
        l1_to_composer_[l1] = composer_id;
        composer_is_dtls_[composer_id] = dtls;
    }
    auto self_weak = weak_from_this();
    (void)carrier.on_data(
        l1,
        [self_weak](gn_conn_id_t lid,
                    std::span<const std::uint8_t> bytes) {
            if (auto t = self_weak.lock()) {
                t->composer_on_l1_data(lid, bytes);
            }
        });
    cs->kick_client_handshake(std::string(uri));
    *out_conn = composer_id;
    return GN_OK;
}

gn_result_t TlsLink::composer_subscribe_data(gn_conn_id_t conn,
                                              ::gn_link_data_cb_t cb,
                                              void* user_data) {
    if (!cb) return GN_ERR_NULL_ARG;
    if (!(conn & kComposerIdBit)) return GN_ERR_NOT_FOUND;
    std::lock_guard lk(composer_mu_);
    if (composer_sessions_.find(conn) == composer_sessions_.end()) {
        return GN_ERR_NOT_FOUND;
    }
    composer_data_subs_[conn] = ComposerDataSub{cb, user_data};
    return GN_OK;
}

gn_result_t TlsLink::composer_unsubscribe_data(gn_conn_id_t conn) {
    if (!(conn & kComposerIdBit)) return GN_OK;
    std::lock_guard lk(composer_mu_);
    composer_data_subs_.erase(conn);
    return GN_OK;
}

gn_result_t TlsLink::composer_subscribe_accept(
    ::gn_link_accept_cb_t cb,
    void* user_data,
    gn_subscription_id_t* out_token) {
    if (!cb || !out_token) return GN_ERR_NULL_ARG;
    const gn_subscription_id_t token =
        next_accept_token_.fetch_add(1, std::memory_order_relaxed);
    std::lock_guard lk(composer_mu_);
    composer_accept_subs_.push_back(
        ComposerAcceptSub{token, cb, user_data});
    *out_token = token;
    return GN_OK;
}

gn_result_t TlsLink::composer_unsubscribe_accept(
    gn_subscription_id_t token) {
    std::lock_guard lk(composer_mu_);
    auto it = std::remove_if(
        composer_accept_subs_.begin(), composer_accept_subs_.end(),
        [token](const ComposerAcceptSub& s) { return s.token == token; });
    composer_accept_subs_.erase(it, composer_accept_subs_.end());
    return GN_OK;
}

void TlsLink::composer_on_l1_accept(gn_conn_id_t l1,
                                     std::string_view peer_uri,
                                     bool             dtls) {
    SSL_CTX* ctx = dtls ? server_ctx_dtls_->native_handle()
                        : server_ctx_.native_handle();
    const gn_conn_id_t composer_id =
        next_composer_id_.fetch_add(1, std::memory_order_relaxed) |
        kComposerIdBit;
    auto cs = std::make_shared<ComposerSession>(
        ctx, ComposerSession::Mode::Server,
        l1, composer_id, weak_from_this(), dtls);
    {
        std::lock_guard lk(composer_mu_);
        composer_sessions_[composer_id] = cs;
        l1_to_composer_[l1] = composer_id;
        composer_is_dtls_[composer_id] = dtls;
    }
    auto self_weak = weak_from_this();
    auto* carrier_ptr = dtls ? (carrier_dtls_ ? &*carrier_dtls_ : nullptr)
                              : (carrier_     ? &*carrier_     : nullptr);
    if (carrier_ptr) {
        (void)carrier_ptr->on_data(
            l1,
            [self_weak](gn_conn_id_t lid,
                        std::span<const std::uint8_t> bytes) {
                if (auto t = self_weak.lock()) {
                    t->composer_on_l1_data(lid, bytes);
                }
            });
    }
    // Stash peer_uri on the session so handshake-complete carries it
    // through to accept-bus subscribers.
    cs->feed_inbound({}, std::string(peer_uri));
}

void TlsLink::composer_on_l1_data(gn_conn_id_t l1,
                                   std::span<const std::uint8_t> bytes) {
    std::shared_ptr<ComposerSession> cs;
    {
        std::lock_guard lk(composer_mu_);
        auto it = l1_to_composer_.find(l1);
        if (it == l1_to_composer_.end()) return;
        auto sit = composer_sessions_.find(it->second);
        if (sit == composer_sessions_.end()) return;
        cs = sit->second;
    }
    cs->feed_inbound(bytes, {});
}

void TlsLink::composer_handshake_complete(gn_conn_id_t composer_id,
                                            std::string_view peer_uri) {
    std::vector<ComposerAcceptSub> snapshot;
    {
        std::lock_guard lk(composer_mu_);
        snapshot = composer_accept_subs_;
    }
    const std::string peer(peer_uri);
    for (const auto& s : snapshot) {
        if (s.cb) s.cb(s.user_data, composer_id, peer.c_str());
    }
}

void TlsLink::composer_drop_session(gn_conn_id_t composer_id) {
    std::shared_ptr<ComposerSession> cs;
    {
        std::lock_guard lk(composer_mu_);
        auto it = composer_sessions_.find(composer_id);
        if (it == composer_sessions_.end()) return;
        cs = std::move(it->second);
        l1_to_composer_.erase(cs->l1_id());
        composer_sessions_.erase(it);
        composer_data_subs_.erase(composer_id);
        composer_is_dtls_.erase(composer_id);
    }
}

void TlsLink::register_session(gn_conn_id_t id,
                                     std::shared_ptr<Session> s) {
    std::lock_guard lk(sessions_mu_);
    sessions_[id] = std::move(s);
    /// `published_ids_` mirrors every successful `notify_connect` so
    /// shutdown's caller-thread emit reaches the conn even when a
    /// worker callback already erased the live entry between the
    /// callback's `claim_disconnect` and shutdown's snapshot. Append
    /// is under the same lock as the live-map insert so the two
    /// stay coherent.
    published_ids_.push_back(id);
}

void TlsLink::erase_session(gn_conn_id_t id) {
    std::lock_guard lk(sessions_mu_);
    sessions_.erase(id);
}

bool TlsLink::claim_disconnect(gn_conn_id_t id) {
    std::lock_guard lk(sessions_mu_);
    if (shutdown_.load(std::memory_order_acquire)) return false;
    return sessions_.erase(id) > 0;
}

std::shared_ptr<TlsLink::Session>
TlsLink::find_session(gn_conn_id_t id) const {
    std::lock_guard lk(sessions_mu_);
    auto it = sessions_.find(id);
    return it == sessions_.end() ? nullptr : it->second;
}

void TlsLink::shutdown() {
    /// Snapshot conn ids under the lock, close each session's
    /// socket synchronously, then notify the kernel side
    /// SYNCHRONOUSLY for each session before stopping the
    /// io_context. `ioc_.stop()` would otherwise drop pending
    /// strand-bound continuations — including the read-completion
    /// path that normally fires `notify_disconnect`. Without sync
    /// notification, kernel-side `ConnectionRegistry` keeps live
    /// records past tls shutdown, which in turn keeps the security
    /// plugin's lifetime anchor alive past the PluginManager drain
    /// budget. Per `link.md` §9.
    bool first_call = false;
    std::vector<gn_conn_id_t> ids_to_emit;
    {
        /// `shutdown_`'s atomic exchange is published under
        /// `sessions_mu_` so a worker-thread `claim_disconnect`
        /// that races with shutdown observes the flag under the
        /// same lock and skips its own emit. Without the lock-
        /// bracketed publish, the worker could erase a session
        /// between shutdown's exchange and snapshot, dropping the
        /// kernel's only release event for that conn (link.md §9
        /// step 3).
        std::lock_guard lk(sessions_mu_);
        if (!shutdown_.exchange(true, std::memory_order_acq_rel)) {
            first_call = true;
            for (auto& [id, s] : sessions_) {
                s->do_close();
            }
            sessions_.clear();
            /// Move `published_ids_` out — caller-thread emit walks
            /// every conn ever notify_connect'd, not just the conns
            /// still live at shutdown. A worker callback that ran
            /// just before shutdown's lock acquisition (Case A) had
            /// already erased its session and emitted its own
            /// notify_disconnect; the second emit on the caller
            /// thread is harmless because the kernel resolves it
            /// through `GN_ERR_NOT_FOUND` and does not re-fire the
            /// DISCONNECTED conn-event.
            ids_to_emit = std::move(published_ids_);
        }
    }

    if (!first_call) return;

    if (acceptor_) {
        std::error_code ec;
        if (acceptor_->close(ec) && api_) {
            gn_log_debug(api_, "tls: acceptor close failed: %s",
                         ec.message().c_str());
        }
        acceptor_.reset();
    }

    // Composer-mode teardown: drop both LinkCarriers (their dtors
    // unsubscribe accept-bus + per-conn data subs), close every
    // composer session.
    {
        std::vector<std::shared_ptr<ComposerSession>> composer_drain;
        {
            std::lock_guard lk(composer_mu_);
            composer_drain.reserve(composer_sessions_.size());
            for (auto& [_, cs] : composer_sessions_) {
                composer_drain.push_back(cs);
            }
            composer_sessions_.clear();
            l1_to_composer_.clear();
            composer_is_dtls_.clear();
            composer_data_subs_.clear();
            composer_accept_subs_.clear();
        }
        for (auto& cs : composer_drain) cs->do_close();
        carrier_.reset();
        carrier_dtls_.reset();
    }

    if (api_ && api_->notify_disconnect) {
        for (const auto id : ids_to_emit) {
            (void)api_->notify_disconnect(api_->host_ctx, id, GN_OK);
        }
    }

    work_.reset();
    ioc_.stop();
    for (auto& w : workers_) {
        if (w.joinable()) w.join();
    }
    workers_.clear();
}

} // namespace gn::link::tls
