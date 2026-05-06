// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/links/tls/tls.cpp
/// @brief  Implementation of the TLS transport.

#include "tls.hpp"

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
#include <deque>
#include <exception>
#include <span>
#include <sstream>
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
                        if (t->api_ && t->api_->notify_disconnect) {
                            t->api_->notify_disconnect(
                                t->api_->host_ctx, self->conn_id,
                                ec == asio::error::eof ? GN_OK : GN_ERR_NULL_ARG);
                        }
                        t->erase_session(self->conn_id);
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
                                    if (t->api_->notify_disconnect) {
                                        (void)t->api_->notify_disconnect(
                                            t->api_->host_ctx,
                                            self->conn_id, GN_OK);
                                    }
                                    t->erase_session(self->conn_id);
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
                        if (t->api_ && t->api_->notify_disconnect) {
                            t->api_->notify_disconnect(
                                t->api_->host_ctx, self->conn_id, GN_ERR_NULL_ARG);
                        }
                        t->erase_session(self->conn_id);
                        return;
                    }
                    t->bytes_out_.fetch_add(n, std::memory_order_relaxed);
                    t->frames_out_.fetch_add(1, std::memory_order_relaxed);
                    self->maybe_start_write();
                }));
    }

    void fail() {
        auto t = transport_.lock();
        if (t && t->api_ && t->api_->notify_disconnect &&
            conn_id != GN_INVALID_ID) {
            t->api_->notify_disconnect(t->api_->host_ctx, conn_id, GN_OK);
        }
        if (t && conn_id != GN_INVALID_ID) t->erase_session(conn_id);
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

    worker_ = std::thread([this] { ioc_.run(); });
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
    bool trust_store_loaded = true;
    try {
        client_ctx_.set_default_verify_paths();
    } catch (const std::exception& e) {
        trust_store_loaded = false;
        if (api_ != nullptr) {
            gn_log_warn(api_,
                "tls: default trust store load failed: %s; "
                "verify_peer handshakes will fail until "
                "links.tls.verify_peer is set false or a "
                "trust bundle is loaded explicitly", e.what());
        }
    } catch (...) {
        trust_store_loaded = false;
        if (api_ != nullptr) {
            gn_log_warn(api_,
                "tls: default trust store load failed: unknown "
                "exception; verify_peer handshakes will fail until "
                "links.tls.verify_peer is set false");
        }
    }
    (void)trust_store_loaded;
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

bool TlsLink::load_server_credentials() {
    /// Test-fixture override wins so unit tests stay independent
    /// of the kernel config. Production paths flow through
    /// `host_api->config_get` with `GN_CONFIG_VALUE_STRING`.
    if (!override_cert_pem_.empty() && !override_key_pem_.empty()) {
        try {
            server_ctx_.use_certificate_chain(
                asio::buffer(override_cert_pem_));
            server_ctx_.use_private_key(
                asio::buffer(override_key_pem_.data(),
                              override_key_pem_.size()),
                asio::ssl::context::pem);
            /// Per plugins/security/noise/docs/handshake.md §5b: OpenSSL has copied the
            /// key bytes into its own context; the override buffer
            /// has no remaining purpose. Wipe it eagerly so the
            /// secret does not outlive its purpose. The buffer
            /// stays allocated (empty()) so a follow-up
            /// `set_server_credentials` reassign hits the same
            /// storage path.
            sodium_memzero(override_key_pem_.data(),
                            override_key_pem_.size());
            override_key_pem_.clear();
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
        server_ctx_.use_certificate_chain_file(cert_path);
        server_ctx_.use_private_key_file(key_path,
            asio::ssl::context::pem);
        ok = true;
    } catch (...) {
        ok = false;
    }
    if (cert_free) cert_free(cert_user_data, cert_path);
    if (key_free)  key_free(key_user_data, key_path);
    return ok;
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

void TlsLink::register_session(gn_conn_id_t id,
                                     std::shared_ptr<Session> s) {
    std::lock_guard lk(sessions_mu_);
    sessions_[id] = std::move(s);
}

void TlsLink::erase_session(gn_conn_id_t id) {
    std::lock_guard lk(sessions_mu_);
    sessions_.erase(id);
}

std::shared_ptr<TlsLink::Session>
TlsLink::find_session(gn_conn_id_t id) const {
    std::lock_guard lk(sessions_mu_);
    auto it = sessions_.find(id);
    return it == sessions_.end() ? nullptr : it->second;
}

void TlsLink::shutdown() {
    if (shutdown_.exchange(true, std::memory_order_acq_rel)) return;

    if (acceptor_) {
        std::error_code ec;
        if (acceptor_->close(ec) && api_) {
            gn_log_debug(api_, "tls: acceptor close failed: %s",
                         ec.message().c_str());
        }
        acceptor_.reset();
    }

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
    std::vector<gn_conn_id_t> live_ids;
    {
        std::lock_guard lk(sessions_mu_);
        live_ids.reserve(sessions_.size());
        for (auto& [id, s] : sessions_) {
            live_ids.push_back(id);
            s->do_close();
        }
        sessions_.clear();
    }

    if (api_ && api_->notify_disconnect) {
        for (const auto id : live_ids) {
            (void)api_->notify_disconnect(api_->host_ctx, id, GN_OK);
        }
    }

    work_.reset();
    ioc_.stop();
    if (worker_.joinable()) worker_.join();
}

} // namespace gn::link::tls
