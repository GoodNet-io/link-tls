// SPDX-License-Identifier: Apache-2.0
/// @file   tests/support/test_self_signed_cert.hpp
/// @brief  In-memory self-signed RSA-2048 cert + key generator for
///         TLS-touching tests.
///
/// Header-only because the helper has exactly one responsibility,
/// produces independent state on every call, and links naturally
/// against the OpenSSL targets every TLS-aware test already pulls
/// in. Used by the unit-level TLS suite and the cross-transport
/// conformance test so neither has to keep its own copy.

#pragma once

#include <string>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace gn::tests::support {

/// Generate an in-memory self-signed RSA-2048 cert + private key.
/// Returns false on any OpenSSL failure; on success @p cert_pem
/// and @p key_pem carry PEM-encoded text.
inline bool generate_self_signed(std::string& cert_pem,
                                  std::string& key_pem) {
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) return false;

    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!kctx) { EVP_PKEY_free(pkey); return false; }
    bool ok =
        EVP_PKEY_keygen_init(kctx) > 0 &&
        EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) > 0 &&
        EVP_PKEY_keygen(kctx, &pkey) > 0;
    EVP_PKEY_CTX_free(kctx);
    if (!ok) { EVP_PKEY_free(pkey); return false; }

    X509* x509 = X509_new();
    if (!x509) { EVP_PKEY_free(pkey); return false; }
    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_getm_notBefore(x509), 0);
    X509_gmtime_adj(X509_getm_notAfter(x509), 60L * 60L);  // 1 hour
    X509_set_pubkey(x509, pkey);

    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("goodnet-test"), -1, -1, 0);
    X509_set_issuer_name(x509, name);

    if (X509_sign(x509, pkey, EVP_sha256()) == 0) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return false;
    }

    BIO* cert_bio = BIO_new(BIO_s_mem());
    BIO* key_bio  = BIO_new(BIO_s_mem());
    if (!cert_bio || !key_bio) {
        if (cert_bio) BIO_free(cert_bio);
        if (key_bio)  BIO_free(key_bio);
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return false;
    }
    PEM_write_bio_X509(cert_bio, x509);
    PEM_write_bio_PrivateKey(key_bio, pkey,
        nullptr, nullptr, 0, nullptr, nullptr);

    char* cert_data = nullptr;
    const auto cert_len = BIO_get_mem_data(cert_bio, &cert_data);
    cert_pem.assign(cert_data, static_cast<std::size_t>(cert_len));
    char* key_data = nullptr;
    const auto key_len = BIO_get_mem_data(key_bio, &key_data);
    key_pem.assign(key_data, static_cast<std::size_t>(key_len));

    BIO_free(cert_bio);
    BIO_free(key_bio);
    X509_free(x509);
    EVP_PKEY_free(pkey);
    return true;
}

}  // namespace gn::tests::support
