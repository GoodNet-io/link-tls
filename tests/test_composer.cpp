// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/links/tls/tests/test_composer.cpp
/// @brief  TlsLink composer L2 surface — smoke coverage of the
///         dispatch + state-management paths added by the
///         composer-mode refactor. Full carrier-driven handshake
///         roundtrip lives in the WSS-over-TLS-over-TCP slice
///         (`plugins/links/ws/tests/test_wss.cpp` once it lands)
///         which exercises the whole composer chain end-to-end.

#include <gtest/gtest.h>

#include <tls.hpp>

#include <sdk/extensions/link.h>
#include <sdk/types.h>

#include <memory>

namespace {

using gn::link::tls::TlsLink;

}  // namespace

TEST(TlsComposer, ListenWithoutHostApiReturnsInvalidState) {
    auto t = std::make_shared<TlsLink>();
    EXPECT_EQ(t->composer_listen("tls://127.0.0.1:0"), GN_ERR_INVALID_STATE);
}

TEST(TlsComposer, ConnectWithoutHostApiReturnsInvalidState) {
    auto t = std::make_shared<TlsLink>();
    gn_conn_id_t out = GN_INVALID_ID;
    EXPECT_EQ(t->composer_connect("tls://127.0.0.1:0", &out),
              GN_ERR_INVALID_STATE);
    EXPECT_EQ(out, GN_INVALID_ID);
}

TEST(TlsComposer, BadSchemeReturnsInvalidEnvelope) {
    auto t = std::make_shared<TlsLink>();
    EXPECT_EQ(t->composer_listen("tcp://127.0.0.1:0"),
              GN_ERR_INVALID_ENVELOPE);
    gn_conn_id_t out = GN_INVALID_ID;
    EXPECT_EQ(t->composer_connect("tcp://127.0.0.1:0", &out),
              GN_ERR_INVALID_ENVELOPE);
}

TEST(TlsComposer, SubscribeDataRejectsKernelManagedConn) {
    auto t = std::make_shared<TlsLink>();
    // conn id without kComposerIdBit is kernel-managed; composer
    // surface routes by range so a "normal" id must NOT be accepted.
    EXPECT_EQ(t->composer_subscribe_data(
        42, [](void*, gn_conn_id_t, const std::uint8_t*, std::size_t) {},
        nullptr), GN_ERR_NOT_FOUND);
}

TEST(TlsComposer, SubscribeDataNullCbRejected) {
    auto t = std::make_shared<TlsLink>();
    EXPECT_EQ(t->composer_subscribe_data(
        TlsLink::kComposerIdBit | 1, nullptr, nullptr),
        GN_ERR_NULL_ARG);
}

TEST(TlsComposer, UnsubscribeDataOnUnknownIsIdempotent) {
    auto t = std::make_shared<TlsLink>();
    EXPECT_EQ(t->composer_unsubscribe_data(
        TlsLink::kComposerIdBit | 7), GN_OK);
    // Kernel-managed id range is no-op too.
    EXPECT_EQ(t->composer_unsubscribe_data(7), GN_OK);
}

TEST(TlsComposer, AcceptSubscriptionRoundtrip) {
    auto t = std::make_shared<TlsLink>();
    gn_subscription_id_t token = GN_INVALID_SUBSCRIPTION_ID;
    EXPECT_EQ(t->composer_subscribe_accept(
        [](void*, gn_conn_id_t, const char*) {}, nullptr, &token), GN_OK);
    EXPECT_NE(token, GN_INVALID_SUBSCRIPTION_ID);
    EXPECT_EQ(t->composer_unsubscribe_accept(token), GN_OK);
    // Second unsubscribe is idempotent.
    EXPECT_EQ(t->composer_unsubscribe_accept(token), GN_OK);
}

TEST(TlsComposer, AcceptSubscribeNullArgs) {
    auto t = std::make_shared<TlsLink>();
    gn_subscription_id_t token = GN_INVALID_SUBSCRIPTION_ID;
    EXPECT_EQ(t->composer_subscribe_accept(nullptr, nullptr, &token),
              GN_ERR_NULL_ARG);
    EXPECT_EQ(t->composer_subscribe_accept(
        [](void*, gn_conn_id_t, const char*) {}, nullptr, nullptr),
        GN_ERR_NULL_ARG);
}

TEST(TlsComposer, DisconnectComposerIdIsIdempotent) {
    auto t = std::make_shared<TlsLink>();
    EXPECT_EQ(t->disconnect(TlsLink::kComposerIdBit | 99), GN_OK);
    EXPECT_EQ(t->disconnect(TlsLink::kComposerIdBit | 99), GN_OK);
}

TEST(TlsComposer, SendComposerIdUnknownReturnsNotFound) {
    auto t = std::make_shared<TlsLink>();
    const std::uint8_t bytes[] = {1, 2, 3};
    EXPECT_EQ(t->send(TlsLink::kComposerIdBit | 0xCAFE,
                       std::span<const std::uint8_t>(bytes)),
              GN_ERR_NOT_FOUND);
}
