# Standalone Nix derivation for the goodnet-link-tls plugin.
# Pulls the kernel SDK + AddPlugin.cmake helper through `goodnet-core`'s
# `propagatedBuildInputs` (asio / libsodium / openssl / spdlog / fmt /
# nlohmann_json). `openssl` is also listed explicitly here so the
# version pin surfaces at plugin build time if the kernel ever drifts
# away from 3.x — TLS plugin compiles against `OpenSSL::SSL` + memory
# BIO API which has been stable across 3.x, but the explicit entry
# matches the ice/quic pattern and avoids implicit-transitive coupling.
{ stdenv
, cmake
, ninja
, pkg-config
, gtest
, rapidcheck
, openssl
, goodnet-core
, lib
}:

stdenv.mkDerivation {
  pname   = "goodnet-link-tls";
  version = "1.0.0-rc1";
  src     = ./.;
  nativeBuildInputs = [ cmake ninja pkg-config ];
  buildInputs       = [ goodnet-core gtest rapidcheck openssl ];
  cmakeFlags = [
    "-DCMAKE_BUILD_TYPE=Release"
    "-DBUILD_TESTING=OFF"
  ];
  doCheck = false;

  meta = {
    description = "GoodNet plugin: goodnet-link-tls";
    license = lib.licenses.asl20;
    platforms = lib.platforms.linux;
  };
}
