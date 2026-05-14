// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/links/tls/tls_composer_session.hpp
/// @brief  TlsLink::ComposerSession — L2 BIO_pair-driven SSL session
///         that rides a LinkCarrier (TCP for tls://, UDP for dtls://)
///         instead of owning its own asio::ssl::stream. Lives in its
///         own TU so the inner BIO pump grows independently of the
///         kernel-mode L1 session.

#pragma once

#include "tls.hpp"

#include <openssl/ssl.h>

#include <cstdint>
#include <deque>
#include <mutex>
#include <span>
#include <string>
#include <vector>

namespace gn::link::tls {

/// Nested inside TlsLink so it can reach the parent's `composer_mu_`,
/// data-sub map, carrier pointers, and stats counters without a
/// friend declaration. Defined out-of-class here purely for source
/// organisation — visibility is unchanged.
class TlsLink::ComposerSession
    : public std::enable_shared_from_this<TlsLink::ComposerSession> {
public:
    enum class Mode { Server, Client };

    /// @param ctx          OpenSSL `SSL_CTX*` chosen by TlsLink — TLS
    ///                     server / client for tls://, DTLS server /
    ///                     client for dtls://
    /// @param mode         Direction within the SSL handshake
    /// @param l1_id        Carrier conn id (TCP or UDP) that backs
    ///                     this session
    /// @param composer_id  L2 id with `kComposerIdBit` set, returned
    ///                     to the upper composer (WSS, app, ...)
    /// @param transport    Back-pointer to the owning TlsLink; weak
    ///                     so a shutdown race does not keep the
    ///                     plugin alive past its dtor
    /// @param dtls         True iff the SSL_CTX wraps `DTLS_method`.
    ///                     Routes `do_close` / `drain_to_carrier`
    ///                     through `carrier_dtls_` instead of `carrier_`
    ///                     and sets DTLS MTU so OpenSSL records fit
    ///                     one UDP datagram.
    ComposerSession(SSL_CTX*               ctx,
                     Mode                   mode,
                     gn_conn_id_t           l1_id,
                     gn_conn_id_t           composer_id,
                     std::weak_ptr<TlsLink> transport,
                     bool                   dtls = false);

    ComposerSession(const ComposerSession&)            = delete;
    ComposerSession& operator=(const ComposerSession&) = delete;

    ~ComposerSession();

    [[nodiscard]] gn_conn_id_t l1_id() const noexcept       { return l1_id_; }
    [[nodiscard]] gn_conn_id_t composer_id() const noexcept { return composer_id_; }

    /// Client-side kickoff. Generates the ClientHello and drains it
    /// out to the carrier. Server-side waits for inbound bytes.
    void kick_client_handshake(std::string peer_uri);

    /// Inbound encrypted bytes from the carrier. Drives the SSL
    /// state machine forward; emits decrypted bytes to data
    /// subscribers and fires accept-bus on handshake completion.
    /// Callbacks dispatch AFTER `mu_` is released to avoid a
    /// recursive re-entry when the data callback calls back into
    /// `TlsLink::send` → `do_send` → `mu_.lock()`.
    void feed_inbound(std::span<const std::uint8_t> bytes,
                       std::string peer_uri);

    /// Application-level send: SSL_write → drain encrypted bytes
    /// out of `network_bio_` → carrier.send. Plaintext is queued
    /// when the handshake has not completed yet and flushed on
    /// completion.
    gn_result_t do_send(std::span<const std::uint8_t> plain);

    void do_close();

private:
    /// Run the SSL state machine: complete handshake if pending,
    /// then read every plaintext chunk available, push into @p out
    /// for the caller to deliver after `mu_` is released. The
    /// accept-bus is fired by the caller AFTER unlocking too.
    void pump_unlocked(std::vector<std::vector<std::uint8_t>>* out);

    /// Pull encrypted bytes out of `network_bio_` and ship them to
    /// the appropriate carrier (TLS → `carrier_`, DTLS → `carrier_dtls_`).
    void drain_to_carrier_unlocked();

    Mode                                   mode_;
    gn_conn_id_t                           l1_id_;
    gn_conn_id_t                           composer_id_;
    std::weak_ptr<TlsLink>                 transport_;
    bool                                   dtls_ = false;

    std::mutex                             mu_;
    SSL*                                   ssl_            = nullptr;
    BIO*                                   internal_bio_   = nullptr;
    BIO*                                   network_bio_    = nullptr;
    bool                                   handshake_done_ = false;
    bool                                   closed_         = false;
    std::string                            peer_uri_;
    std::deque<std::vector<std::uint8_t>>  pending_writes_;
};

}  // namespace gn::link::tls
