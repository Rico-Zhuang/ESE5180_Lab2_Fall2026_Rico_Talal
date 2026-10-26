/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SECURITY_PROTOCOL_H
#define SECURITY_PROTOCOL_H

#include "sec_crypto.h"

#define PROTO_MAX_PACKET 255
#define PROTO_HEADER_LEN 38
#define PROTO_MAX_MESSAGE 127
#define PROTO_TIMEOUT_MS 60000
#define PROTO_CLIENT 1
#define PROTO_SERVER 2

enum proto_type {
    PKT_HELLO = 1, PKT_HELLO_ACK, PKT_KEY, PKT_KEY_ACK,
    PKT_CONFIRM, PKT_CONFIRM_ACK, PKT_DATA, PKT_RECEIPT
};

enum proto_phase {
    PH_LISTEN, PH_HELLO_ACK, PH_KEY, PH_KEY_ACK,
    PH_CONFIRM, PH_CONFIRM_ACK, PH_READY
};

enum proto_result {
    RX_REJECTED, RX_PROGRESS, RX_CONNECTED, RX_DATA, RX_DUPLICATE, RX_RECEIPT
};

/* Only the local private signing seed is present in each board's image. */
struct proto_identity {
    uint8_t pair_id[8];
    uint8_t public_key[32];
    uint8_t private_key[32];
    uint8_t peer_public_key[32];
};

struct proto_event {
    uint32_t sequence;
    size_t length;
    uint8_t message[PROTO_MAX_MESSAGE + 1];
};

struct proto {
    const struct proto_identity *identity;
    uint8_t role;
    enum proto_phase phase;
    uint8_t client_nonce[16], server_nonce[16];
    uint8_t dh_public[32], dh_private[32], peer_dh[32];
    uint8_t transcript[32], session_id[16], aes_key[16];
    uint64_t last_rx_ms, next_tx_ms;
    uint8_t tx_packet[PROTO_MAX_PACKET];
    size_t tx_length;
    unsigned tx_remaining;
    bool tx_repeat;
    uint32_t tx_sequence, rx_highest;
    uint64_t rx_bitmap;
    uint8_t receipt_hash[32];
    bool receipt_seen;
};

void proto_init(struct proto *p, uint8_t role,
                const struct proto_identity *identity, uint64_t now);
/* Returns true when a 60-second receive timeout starts a new handshake. */
bool proto_tick(struct proto *p, uint64_t now);
bool proto_tx_due(const struct proto *p, uint64_t now);
void proto_tx_done(struct proto *p, uint64_t now, bool success);
enum proto_result proto_receive(struct proto *p, const uint8_t *packet,
                                size_t length, uint64_t now, struct proto_event *event);
bool proto_send_data(struct proto *p, const uint8_t *message, size_t length, uint64_t now);

#endif
