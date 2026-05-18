# Changelog — goodnet-link-tls

All notable changes to this plugin are listed here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions track the kernel ABI through `gn_link_vtable_t` /
`gn.link.tls` extension.

## [Unreleased]

### Composer split + DTLS-over-UDP

`ComposerSession` moves to its own translation unit. The same
split adds a `dtls://host:port` URI scheme that layers DTLS on
a `LinkCarrier(udp)` carrier — symmetric with the existing TLS
on `LinkCarrier(tcp)` composition, but for datagram contexts
(notably the TURN-over-DTLS path consumed by `link-ice`).

### Trust-store + recv-path hardening

When `verify` is on but the system trust store fails to load,
`connect()` now refuses the handshake instead of falling back
to permissive mode. Bind / listen error returns are aligned
with the TCP sibling so wrappers and tests see consistent
status codes across both schemes.

The recv path treats `LIMIT_REACHED` as transient. When the
kernel-side recv buffer saturates, the session parks the recv
loop until `notify_inbound_bytes` drains, rather than spinning
or dropping the connection. Closes the TLS half of the
B-LINKS-06 backpressure work.

## [1.0.0-rc1] — 2026-05-12

Initial release. TLS 1.3 transport with the composer surface
that lets it sit on top of `gn.link.tcp`.

### Added

- TLS 1.3 minimum, host OpenSSL trust store by default.
- `set_server_credentials` extension override for self-signed
  deployments. Server-private-key bytes are zeroised on
  reassignment and again after OpenSSL has copied them into the
  `SSL_CTX`, per the wipe-on-end-of-life rule from
  `plugins/security/noise/docs/handshake.en.md` §5b.
- Composer L2 surface — TLS rides a `LinkCarrier(tcp)` rather
  than binding its own socket. The TCP carrier feeds raw bytes
  into the OpenSSL BIO, and the post-handshake byte stream
  surfaces through the standard
  `host_api->notify_inbound_bytes` channel.
- SDK link teardown conformance — disconnect emit serialized
  with the shutdown flag, every published conn tracked so
  caller-thread `shutdown()` emits the matching `DISCONNECTED`
  notification for every active session.
- Multi-threaded `io_context` worker pool sized to half
  `hardware_concurrency()`.
- Self-signed test certificate helper under `tests/support/` so
  the conformance suite can run end-to-end without an external
  PKI dependency.
