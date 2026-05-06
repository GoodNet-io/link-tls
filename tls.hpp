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
/// kernel config (`security-trust.md` §3 single-source principle).

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

    void start_accept();
    void on_accept(std::shared_ptr<Session> session,
                    const std::error_code& ec);

    void register_session(gn_conn_id_t id, std::shared_ptr<Session> s);
    void erase_session(gn_conn_id_t id);
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
    std::thread                                                      worker_;
    asio::ssl::context                                               server_ctx_;
    asio::ssl::context                                               client_ctx_;

    std::optional<asio::ip::tcp::acceptor>                           acceptor_;
    std::atomic<std::uint16_t>                                       listen_port_{0};
    std::atomic<bool>                                                shutdown_{false};

    mutable std::mutex                                                  sessions_mu_;
    std::unordered_map<gn_conn_id_t, std::shared_ptr<Session>>          sessions_;

    std::atomic<std::uint64_t> bytes_in_{0};
    std::atomic<std::uint64_t> bytes_out_{0};
    std::atomic<std::uint64_t> frames_in_{0};
    std::atomic<std::uint64_t> frames_out_{0};

    /// Per-connection write-queue thresholds per `backpressure.md` §1.
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
};

} // namespace gn::link::tls
