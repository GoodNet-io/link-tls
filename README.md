# goodnet-link-tls

TLS-over-TCP transport for GoodNet. Pins TLS 1.3 minimum, uses the
host's OpenSSL trust store by default, and exposes a credential
override for self-signed deployments via `set_server_credentials`.
Server-private-key bytes are zeroised on reassignment and after
OpenSSL has copied them into the SSL context.

**Kind**: link · **Artefact**: dynamic plugin (`.so` via dlopen)
· **License**: Apache-2.0 (see `LICENSE`)

## Build

In-tree, alongside the kernel:

```sh
nix build .#goodnet-link-tls
# result/lib/goodnet/plugins/libgoodnet_link_tls.so
```

Standalone, against an installed kernel SDK (OpenSSL ≥ 3 on PATH):

```sh
cd plugins/links/tls
cmake -B build -DCMAKE_PREFIX_PATH=/usr/local -DBUILD_TESTING=OFF
cmake --build build
```

## Load

Manifest entry pins the SHA-256 digest; `gn_plugin_init` registers
the `tls` scheme. See `docs/install.md` and
`docs/contracts/plugin-manifest.md` in the kernel tree.

## Contract

- Kernel-side link contract: `docs/contracts/link.md`
- Wipe-on-end-of-life rule for the override key:
  `plugins/security/noise/docs/handshake.md` §5b (canonical statement,
  cross-applies to this plugin's TLS key buffer).
