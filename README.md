# goodnet-link-tls

TLS-over-TCP transport for GoodNet. Pins TLS 1.3 minimum, uses the
host's OpenSSL trust store by default, and exposes a credential
override for self-signed deployments via `set_server_credentials`.
Server-private-key bytes are zeroised on reassignment and after
OpenSSL has copied them into the SSL context.

**Kind**: link · **Artefact**: dynamic plugin (`.so` via dlopen)
· **License**: Apache-2.0 (see `LICENSE`)

## Build

This plugin lives in its own git with a flake that pulls the
kernel SDK as a Nix input (OpenSSL ≥ 3 on the build path). From
this checkout:

```sh
nix run .#build         # release build of libgoodnet_link_tls.so
nix run .#test          # vanilla ctest
nix run .#test-asan     # AddressSanitizer + UBSan
nix run .#test-tsan     # ThreadSanitizer
```

The kernel monorepo also builds this plugin in-tree through its
own `nix run .#build -- release` — operator install consumes
every bundled `.so` from there.

## Load

Manifest entry pins the SHA-256 digest; `gn_plugin_init` registers
the `tls` scheme. See `docs/install.en.md` and
`docs/contracts/plugin-manifest.en.md` in the kernel tree.

## Contract

- Kernel-side link contract: `docs/contracts/link.en.md`
- Wipe-on-end-of-life rule for the override key:
  `plugins/security/noise/docs/handshake.md` §5b (canonical statement,
  cross-applies to this plugin's TLS key buffer).
