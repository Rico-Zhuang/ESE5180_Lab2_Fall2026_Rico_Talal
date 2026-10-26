/* SPDX-License-Identifier: Apache-2.0 */
#include "security_protocol.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static struct proto_identity client_id, server_id;
static struct proto client, server;
static uint64_t now;
static struct proto_event event;

static void setup(void)
{
    sec_random(client_id.pair_id, 8);
    memcpy(server_id.pair_id, client_id.pair_id, 8);
    sec_sign_keygen(client_id.public_key, client_id.private_key);
    sec_sign_keygen(server_id.public_key, server_id.private_key);
    memcpy(client_id.peer_public_key, server_id.public_key, 32);
    memcpy(server_id.peer_public_key, client_id.public_key, 32);
    now = 100;
    proto_init(&client, PROTO_CLIENT, &client_id, now);
    proto_init(&server, PROTO_SERVER, &server_id, now);
}

static enum proto_result transfer(struct proto *from, struct proto *to)
{
    uint8_t packet[255];
    size_t length = from->tx_length;
    memcpy(packet, from->tx_packet, length);
    if (now < from->next_tx_ms) { now = from->next_tx_ms; }
    assert(proto_tx_due(from, now));
    now += 2000; /* approximate LoRa airtime */
    proto_tx_done(from, now, true);
    return proto_receive(to, packet, length, ++now, &event);
}

static void connect_pair(void)
{
    assert(transfer(&client, &server) == RX_PROGRESS);
    assert(transfer(&server, &client) == RX_PROGRESS);
    assert(transfer(&client, &server) == RX_PROGRESS);
    assert(transfer(&server, &client) == RX_PROGRESS);
    assert(transfer(&client, &server) == RX_CONNECTED);
    assert(transfer(&server, &client) == RX_CONNECTED);
    assert(client.phase == PH_READY && server.phase == PH_READY);
    assert(!memcmp(client.aes_key, server.aes_key, 16));
    assert(!memcmp(client.session_id, server.session_id, 16));
    uint8_t zero[32] = {0};
    assert(!memcmp(client.dh_private, zero, 32));
    assert(!memcmp(server.dh_private, zero, 32));
}

static void sign_packet(uint8_t *packet, size_t length, const struct proto_identity *id)
{
    sec_sign(packet + length - 64, id->private_key, id->public_key, packet, length - 64);
}

static void test_key_derivation(void)
{
    const uint8_t expected[16] = {0xdb,0x4e,0xc3,0x7a,0x13,0x88,0x16,0x92,
                                  0xe7,0x66,0x8b,0xac,0xf5,0x7e,0x34,0xae};
    uint8_t secret[32], salt[32], key[16];
    for (unsigned i = 0; i < 32; ++i) { secret[i] = i; salt[i] = 31 - i; }
    sec_hkdf_aes128(key, secret, salt);
    assert(!memcmp(key, expected, 16)); /* Independently computed with Python cryptography. */
    puts("PASS HKDF-SHA256 against independent implementation");
}

static void decode_hex(uint8_t *out, const char *hex, size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        unsigned value;
        assert(sscanf(hex + i * 2, "%2x", &value) == 1);
        out[i] = value;
    }
}

static void test_identity_format(void)
{
    /* RFC 8032 section 7.1, TEST 1: raw Ed25519 seed format, also used
     * by Python cryptography in tools/provision.py. Public test vector. */
    uint8_t seed[32], public[32], expected[64], signature[64];
    decode_hex(seed, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", 32);
    decode_hex(public, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", 32);
    decode_hex(expected,
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b", 64);
    sec_sign(signature, seed, public, (const uint8_t *)"", 0);
    assert(!memcmp(signature, expected, 64));
    assert(sec_verify(signature, public, (const uint8_t *)"", 0));
    puts("PASS provisioned Ed25519 seed format against RFC 8032 vector");
}

static void test_data_and_duplicates(void)
{
    setup();
    const uint8_t message[] = "hello, secure LoRa";
    assert(!proto_send_data(&client, message, sizeof(message), now));
    connect_pair();
    assert(proto_send_data(&client, message, sizeof(message), now));
    assert(!proto_send_data(&client, message, sizeof(message), now));
    assert(transfer(&client, &server) == RX_DATA);
    assert(event.length == sizeof(message) && !memcmp(event.message, message, sizeof(message)));
    assert(transfer(&server, &client) == RX_RECEIPT);
    assert(client.tx_remaining == 1); /* Receipt must not cancel the required second copy. */
    assert(transfer(&client, &server) == RX_DUPLICATE);
    assert(event.length == 0);
    assert(transfer(&server, &client) == RX_PROGRESS);
    assert(!proto_tx_due(&client, now + 10000));
    assert(client.tx_remaining == 0);
    puts("PASS handshake, key agreement, two copies, one delivery, signed receipt");
}

static void test_each_handshake_packet_lost(void)
{
    for (unsigned lost = 0; lost < 6; ++lost) {
        setup();
        for (unsigned stage = 0; stage < 6; ++stage) {
            struct proto *from = stage % 2 ? &server : &client;
            struct proto *to = stage % 2 ? &client : &server;
            if (stage == lost) {
                uint8_t saved[255];
                size_t size = from->tx_length;
                memcpy(saved, from->tx_packet, size);
                now += 2000;
                proto_tx_done(from, now, true); /* sent, but dropped by the channel */
                assert(!proto_tx_due(from, now));
                now = from->next_tx_ms;
                assert(proto_tx_due(from, now));
                assert(size == from->tx_length && !memcmp(saved, from->tx_packet, size));
                if (stage == 5) { assert(client.phase != PH_READY); }
            }
            enum proto_result result = transfer(from, to);
            assert(result == (stage < 4 ? RX_PROGRESS : RX_CONNECTED));
        }
        assert(client.phase == PH_READY && server.phase == PH_READY);
    }
    puts("PASS loss and retry of each of the six handshake messages");
}

static void test_duplicate_handshakes(void)
{
    setup();
    for (unsigned stage = 0; stage < 6; ++stage) {
        struct proto *from = stage % 2 ? &server : &client;
        struct proto *to = stage % 2 ? &client : &server;
        uint8_t saved[255];
        size_t size = from->tx_length;
        memcpy(saved, from->tx_packet, size);
        assert(transfer(from, to) != RX_REJECTED);
        enum proto_phase phase = to->phase;
        assert(proto_receive(to, saved, size, ++now, &event) == RX_PROGRESS);
        assert(to->phase == phase);
    }
    puts("PASS duplicate handshake requests without state rollback");
}

static void test_authentication(void)
{
    setup();
    uint8_t packet[255];
    size_t size = client.tx_length;
    for (size_t i = 0; i < size; ++i) {
        memcpy(packet, client.tx_packet, size);
        packet[i] ^= 1;
        assert(proto_receive(&server, packet, size, ++now, &event) == RX_REJECTED);
        assert(server.phase == PH_LISTEN);
    }
    struct proto_identity rogue = client_id;
    sec_sign_keygen(rogue.public_key, rogue.private_key);
    memcpy(packet, client.tx_packet, size);
    memcpy(packet + PROTO_HEADER_LEN, rogue.public_key, 32);
    sign_packet(packet, size, &rogue);
    assert(proto_receive(&server, packet, size, ++now, &event) == RX_REJECTED);
    memcpy(packet, client.tx_packet, size);
    packet[8] ^= 1;
    sign_packet(packet, size, &client_id);
    assert(proto_receive(&server, packet, size, ++now, &event) == RX_REJECTED);
    connect_pair();
    assert(proto_send_data(&client, (const uint8_t *)"tamper test", 11, now));
    size = client.tx_length;
    for (size_t i = 0; i < size; ++i) {
        memcpy(packet, client.tx_packet, size);
        packet[i] ^= 1;
        assert(proto_receive(&server, packet, size, ++now, &event) == RX_REJECTED);
    }
    assert(server.rx_highest == 0);
    puts("PASS tampered headers/ciphertext/signatures and substituted public keys rejected");
}

static void test_invalid_dh_and_confirmation(void)
{
    setup();
    transfer(&client, &server);
    transfer(&server, &client);
    uint8_t packet[255];
    memcpy(packet, client.tx_packet, client.tx_length);
    memset(packet + PROTO_HEADER_LEN + 16, 0, 32);
    sign_packet(packet, client.tx_length, &client_id);
    assert(proto_receive(&server, packet, client.tx_length, ++now, &event) == RX_REJECTED);
    assert(server.phase == PH_KEY);
    assert(transfer(&client, &server) == RX_PROGRESS); /* valid retry still has DH private key */
    assert(transfer(&server, &client) == RX_PROGRESS);
    memcpy(packet, client.tx_packet, client.tx_length);
    packet[PROTO_HEADER_LEN] ^= 1; /* alter plaintext token via IV, leaving valid PKCS#7 */
    sign_packet(packet, client.tx_length, &client_id);
    assert(proto_receive(&server, packet, client.tx_length, ++now, &event) == RX_REJECTED);
    assert(server.phase == PH_CONFIRM);
    assert(transfer(&client, &server) == RX_CONNECTED);
    assert(transfer(&server, &client) == RX_CONNECTED);
    puts("PASS invalid DH and signed-but-wrong encrypted key confirmation rejected");
}

static void test_timeout_and_session_replay(void)
{
    setup();
    uint8_t old_hello[255], old_nonce[16];
    size_t hello_length = client.tx_length;
    memcpy(old_hello, client.tx_packet, hello_length);
    memcpy(old_nonce, client.client_nonce, 16);
    uint64_t since = client.last_rx_ms;
    assert(!proto_tick(&client, since + 59999));
    assert(proto_tick(&client, since + 60000));
    assert(memcmp(old_nonce, client.client_nonce, 16));
    now = since + 60000;
    connect_pair();
    assert(proto_receive(&server, old_hello, hello_length, ++now, &event) == RX_REJECTED);
    assert(proto_send_data(&client, (const uint8_t *)"old session", 11, now));
    uint8_t old_data[255];
    size_t data_length = client.tx_length;
    memcpy(old_data, client.tx_packet, data_length);
    transfer(&client, &server);
    now += 60001;
    assert(proto_tick(&server, now) && server.phase == PH_LISTEN);
    assert(proto_tick(&client, now));
    connect_pair();
    assert(proto_receive(&server, old_data, data_length, ++now, &event) == RX_REJECTED);
    assert(server.rx_highest == 0);
    puts("PASS exact 60-second reset, fresh session, and old-session replay rejection");
}

static void test_payload_boundaries_and_reordering(void)
{
    setup();
    connect_pair();
    uint8_t message[128], saved[3][255];
    size_t saved_length[3] = {0};
    for (size_t i = 0; i < sizeof(message); ++i) { message[i] = i; }
    const size_t lengths[] = {0, 1, 15, 16, 17, 126, 127};
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
        assert(proto_send_data(&client, message, lengths[i], now));
        assert(client.tx_length <= 255);
        assert(transfer(&client, &server) == RX_DATA);
        assert(event.length == lengths[i] && !memcmp(event.message, message, lengths[i]));
        assert(transfer(&client, &server) == RX_DUPLICATE);
        transfer(&server, &client);
    }
    assert(!proto_send_data(&client, message, 128, now));
    for (unsigned i = 0; i < 3; ++i) {
        assert(proto_send_data(&client, message, 10, now));
        memcpy(saved[i], client.tx_packet, client.tx_length);
        saved_length[i] = client.tx_length;
        proto_tx_done(&client, now, true);
        proto_tx_done(&client, now, true);
    }
    assert(proto_receive(&server, saved[2], saved_length[2], ++now, &event) == RX_DATA);
    assert(proto_receive(&server, saved[0], saved_length[0], ++now, &event) == RX_DATA);
    assert(proto_receive(&server, saved[1], saved_length[1], ++now, &event) == RX_DATA);
    assert(proto_receive(&server, saved[0], saved_length[0], ++now, &event) == RX_DUPLICATE);
    puts("PASS CBC padding boundaries, maximum payload, binary data, reordered delivery");
}

static void test_malformed_and_receipts(void)
{
    setup();
    uint8_t packet[256];
    for (size_t length = 0; length <= sizeof(packet); ++length) {
        memset(packet, 0xa5, sizeof(packet));
        assert(proto_receive(&server, packet, length, ++now, &event) == RX_REJECTED);
    }
    connect_pair();
    assert(proto_send_data(&client, (const uint8_t *)"receipt", 7, now));
    transfer(&client, &server);
    memcpy(packet, server.tx_packet, server.tx_length);
    packet[PROTO_HEADER_LEN] ^= 1;
    sign_packet(packet, server.tx_length, &server_id);
    uint64_t before = client.last_rx_ms;
    assert(proto_receive(&client, packet, server.tx_length, ++now, &event) == RX_REJECTED);
    assert(client.last_rx_ms == before);
    assert(transfer(&server, &client) == RX_RECEIPT);
    puts("PASS malformed frame lengths and incorrect signed receipts rejected");
}

int main(void)
{
    test_identity_format();
    test_key_derivation();
    test_data_and_duplicates();
    test_each_handshake_packet_lost();
    test_duplicate_handshakes();
    test_authentication();
    test_invalid_dh_and_confirmation();
    test_timeout_and_session_replay();
    test_payload_boundaries_and_reordering();
    test_malformed_and_receipts();
    puts("All protocol tests passed.");
    return 0;
}
