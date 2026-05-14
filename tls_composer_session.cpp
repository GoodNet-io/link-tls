// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/links/tls/tls_composer_session.cpp
/// @brief  Implementation of TlsLink::ComposerSession — see header.

#include "tls_composer_session.hpp"

#include <openssl/bio.h>
#include <openssl/err.h>

#include <utility>

namespace gn::link::tls {

TlsLink::ComposerSession::ComposerSession(
    SSL_CTX*               ctx,
    Mode                   mode,
    gn_conn_id_t           l1_id,
    gn_conn_id_t           composer_id,
    std::weak_ptr<TlsLink> transport,
    bool                   dtls)
    : mode_(mode),
      l1_id_(l1_id),
      composer_id_(composer_id),
      transport_(std::move(transport)),
      dtls_(dtls) {
    ssl_ = SSL_new(ctx);
    BIO_new_bio_pair(&internal_bio_, 0, &network_bio_, 0);
    SSL_set_bio(ssl_, internal_bio_, internal_bio_);
    if (mode_ == Mode::Server) SSL_set_accept_state(ssl_);
    else                       SSL_set_connect_state(ssl_);
    if (dtls_) {
        /// Set the DTLS MTU to match the UDP carrier's payload
        /// ceiling so the SSL state machine emits records that
        /// fit one datagram. `SSL_set_mtu` is advisory — OpenSSL
        /// still fragments handshake records as needed — but it
        /// pins the upper bound for post-handshake records so a
        /// peer never receives a record that exceeds the carrier
        /// MTU.
        SSL_set_mtu(ssl_, 1200);
    }
}

TlsLink::ComposerSession::~ComposerSession() {
    if (ssl_) {
        SSL_free(ssl_);  // also frees internal_bio_
        ssl_ = nullptr;
    }
    if (network_bio_) {
        BIO_free(network_bio_);
        network_bio_ = nullptr;
    }
}

void TlsLink::ComposerSession::kick_client_handshake(std::string peer_uri) {
    std::lock_guard lk(mu_);
    peer_uri_ = std::move(peer_uri);
    (void)SSL_do_handshake(ssl_);
    drain_to_carrier_unlocked();
}

void TlsLink::ComposerSession::feed_inbound(
    std::span<const std::uint8_t> bytes,
    std::string                    peer_uri) {
    /// Plaintext + handshake-complete dispatch happens AFTER `mu_` is
    /// released so the composer's data callback can re-enter
    /// `TlsLink::send` (and therefore reacquire this session's `mu_`
    /// through `do_send`) without deadlocking on a server-side reply
    /// mid-`pump_unlocked`.
    std::vector<std::vector<std::uint8_t>> plaintext_out;
    bool        fire_handshake_complete = false;
    std::string saved_peer_uri;
    {
        std::lock_guard lk(mu_);
        if (peer_uri_.empty() && !peer_uri.empty()) peer_uri_ = peer_uri;
        if (!bytes.empty()) {
            BIO_write(network_bio_, bytes.data(),
                       static_cast<int>(bytes.size()));
        }
        const bool was_done = handshake_done_;
        pump_unlocked(&plaintext_out);
        /// Accept-bus fires only for server-mode sessions — client-
        /// side `composer_connect` already returned the composer_id
        /// to the upper layer through its out-param, so re-publishing
        /// through accept-bus would double-deliver to subscribed
        /// composers.
        if (!was_done && handshake_done_) {
            fire_handshake_complete = (mode_ == Mode::Server);
            saved_peer_uri = peer_uri_;
        }
    }
    /// Fire callbacks WITHOUT holding session mu_. Composers (WS /
    /// HTTP / ...) commonly reply on the same conn from within the
    /// data callback; their reply path re-enters `TlsLink::send` →
    /// `do_send` → `mu_.lock()`, which would deadlock if we still
    /// held the lock here. The accumulated queue lets us serialise
    /// SSL state changes under the lock without serialising
    /// re-entrant sends.
    if (fire_handshake_complete) {
        if (auto t = transport_.lock()) {
            t->composer_handshake_complete(composer_id_, saved_peer_uri);
        }
    }
    auto t = transport_.lock();
    if (!t) return;
    TlsLink::ComposerDataSub sub{};
    {
        std::lock_guard sub_lk(t->composer_mu_);
        auto it = t->composer_data_subs_.find(composer_id_);
        if (it != t->composer_data_subs_.end()) sub = it->second;
    }
    for (auto& buf : plaintext_out) {
        if (sub.cb) {
            sub.cb(sub.user_data, composer_id_, buf.data(), buf.size());
        }
        t->bytes_in_.fetch_add(buf.size(), std::memory_order_relaxed);
        t->frames_in_.fetch_add(1,         std::memory_order_relaxed);
    }
}

gn_result_t TlsLink::ComposerSession::do_send(
    std::span<const std::uint8_t> plain) {
    std::lock_guard lk(mu_);
    if (!handshake_done_) {
        pending_writes_.emplace_back(plain.begin(), plain.end());
        return GN_OK;
    }
    const int n = SSL_write(ssl_, plain.data(),
                              static_cast<int>(plain.size()));
    if (n <= 0) {
        const int err = SSL_get_error(ssl_, n);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            closed_ = true;
            return GN_ERR_NULL_ARG;
        }
    }
    drain_to_carrier_unlocked();
    return GN_OK;
}

void TlsLink::ComposerSession::do_close() {
    std::lock_guard lk(mu_);
    if (closed_) return;
    closed_ = true;
    (void)SSL_shutdown(ssl_);
    drain_to_carrier_unlocked();
    auto t = transport_.lock();
    if (!t) return;
    auto* carrier = dtls_
        ? (t->carrier_dtls_ ? &*t->carrier_dtls_ : nullptr)
        : (t->carrier_      ? &*t->carrier_      : nullptr);
    if (carrier) (void)carrier->disconnect(l1_id_);
}

void TlsLink::ComposerSession::pump_unlocked(
    std::vector<std::vector<std::uint8_t>>* out) {
    if (!handshake_done_) {
        const int r = SSL_do_handshake(ssl_);
        if (r == 1) {
            handshake_done_ = true;
            drain_to_carrier_unlocked();
            // Flush queued plaintext writes.
            for (auto& buf : pending_writes_) {
                (void)SSL_write(ssl_, buf.data(),
                                 static_cast<int>(buf.size()));
            }
            pending_writes_.clear();
            drain_to_carrier_unlocked();
        } else {
            const int err = SSL_get_error(ssl_, r);
            drain_to_carrier_unlocked();
            if (err != SSL_ERROR_WANT_READ &&
                err != SSL_ERROR_WANT_WRITE) {
                closed_ = true;
            }
            return;
        }
    }
    /// Drain plaintext from `SSL_read` into the caller-owned queue.
    std::uint8_t buf[16 * 1024];
    while (true) {
        const int n = SSL_read(ssl_, buf, sizeof(buf));
        if (n > 0) {
            if (out) {
                out->emplace_back(buf,
                    buf + static_cast<std::size_t>(n));
            }
            continue;
        }
        const int err = SSL_get_error(ssl_, n);
        if (err == SSL_ERROR_WANT_READ) break;
        if (err == SSL_ERROR_ZERO_RETURN) {
            closed_ = true;
            break;
        }
        closed_ = true;
        break;
    }
    drain_to_carrier_unlocked();
}

void TlsLink::ComposerSession::drain_to_carrier_unlocked() {
    auto t = transport_.lock();
    if (!t) return;
    auto* carrier = dtls_
        ? (t->carrier_dtls_ ? &*t->carrier_dtls_ : nullptr)
        : (t->carrier_      ? &*t->carrier_      : nullptr);
    if (!carrier) return;
    std::uint8_t out[16 * 1024];
    while (BIO_pending(network_bio_) > 0) {
        const int n = BIO_read(network_bio_, out, sizeof(out));
        if (n <= 0) break;
        (void)carrier->send(
            l1_id_,
            std::span<const std::uint8_t>(
                out, static_cast<std::size_t>(n)));
    }
}

}  // namespace gn::link::tls
