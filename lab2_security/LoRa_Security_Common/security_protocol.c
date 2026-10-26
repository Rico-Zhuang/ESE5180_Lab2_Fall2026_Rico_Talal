/* SPDX-License-Identifier: Apache-2.0 */
#include "security_protocol.h"
#include <limits.h>
#include <string.h>

/* Wire format (big endian integers; no C-struct packing on the radio):
 * magic[4], version, type, source, destination, pair[8], session[16],
 * sequence[4], payload_length[2], payload[N], Ed25519 signature[64].
 * HELLO through KEY_ACK use client_nonce as session; later packets use
 * the first 16 bytes of the complete handshake transcript's SHA256 hash.
 */
static const uint8_t magic[4] = {'E', '5', '1', '8'};

static void wipe(void *memory, size_t length)
{
    volatile uint8_t *p = memory;
    while (length--) { *p++ = 0; }
}

static bool equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t difference = 0;
    for (size_t i = 0; i < n; ++i) { difference |= a[i] ^ b[i]; }
    return difference == 0;
}

static void put32(uint8_t *out, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) { out[i] = value >> (24 - 8 * i); }
}

static uint32_t get32(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) | in[3];
}

static void frame(struct proto *p, uint8_t type, uint32_t sequence,
                  const uint8_t *payload, size_t length, uint64_t now,
                  bool repeat, unsigned copies)
{
    uint8_t *out = p->tx_packet;
    memcpy(out, magic, 4);
    out[4] = 1;
    out[5] = type;
    out[6] = p->role;
    out[7] = p->role == PROTO_CLIENT ? PROTO_SERVER : PROTO_CLIENT;
    memcpy(out + 8, p->identity->pair_id, 8);
    memcpy(out + 16, type <= PKT_KEY_ACK ? p->client_nonce : p->session_id, 16);
    put32(out + 32, sequence);
    out[36] = length >> 8;
    out[37] = length;
    memcpy(out + PROTO_HEADER_LEN, payload, length);
    sec_sign(out + PROTO_HEADER_LEN + length, p->identity->private_key,
             p->identity->public_key, out, PROTO_HEADER_LEN + length);
    p->tx_length = PROTO_HEADER_LEN + length + SEC_SIG_LEN;
    p->tx_remaining = copies;
    p->tx_repeat = repeat;
    p->next_tx_ms = now;
}

/* CBC built from the supplied AES128 block primitive. Each new logical
 * packet gets a fresh IV. Retries resend the identical signed ciphertext.
 * The signature is always checked BEFORE decrypting or checking padding.
 */
static size_t encrypt(const struct proto *p, uint8_t *out,
                      const uint8_t *message, size_t length)
{
    uint8_t block[16];
    size_t padded = (length / 16 + 1) * 16;
    sec_random(out, 16);
    for (size_t i = 0; i < padded; i += 16) {
        for (size_t j = 0; j < 16; ++j) {
            uint8_t value = i + j < length ? message[i + j] : (uint8_t)(padded - length);
            block[j] = value ^ out[i + j];
        }
        sec_aes128_encrypt(out + 16 + i, p->aes_key, block, 16);
    }
    wipe(block, sizeof(block));
    return 16 + padded;
}

static bool decrypt(const struct proto *p, uint8_t *out, size_t *out_length,
                    const uint8_t *payload, size_t length)
{
    if (length < 32 || length > 144 || length % 16) { return false; }
    size_t plain_length = length - 16;
    for (size_t i = 0; i < plain_length; i += 16) {
        sec_aes128_decrypt(out + i, p->aes_key, payload + 16 + i, 16);
        for (size_t j = 0; j < 16; ++j) { out[i + j] ^= payload[i + j]; }
    }
    uint8_t padding = out[plain_length - 1];
    if (!padding || padding > 16) { return false; }
    for (size_t i = 0; i < padding; ++i) {
        if (out[plain_length - 1 - i] != padding) { return false; }
    }
    *out_length = plain_length - padding;
    return true;
}

static bool derive_session(struct proto *p, const uint8_t peer_dh[32])
{
    static const uint8_t label[] = "ESE5180 LoRa handshake v1";
    uint8_t transcript[sizeof(label) - 1 + 8 + 16 + 16 + 32 * 4];
    uint8_t secret[32], private_copy[32];
    size_t offset = 0;
    memcpy(private_copy, p->dh_private, 32);
    bool valid = sec_dh_shared(secret, peer_dh, private_copy);
    wipe(private_copy, sizeof(private_copy));
    if (!valid) { wipe(secret, sizeof(secret)); return false; }
    memcpy(p->peer_dh, peer_dh, 32);
#define APPEND(value, count) do { memcpy(transcript + offset, value, count); offset += count; } while (0)
    APPEND(label, sizeof(label) - 1);
    APPEND(p->identity->pair_id, 8);
    APPEND(p->client_nonce, 16);
    APPEND(p->server_nonce, 16);
    APPEND(p->role == PROTO_CLIENT ? p->identity->public_key : p->identity->peer_public_key, 32);
    APPEND(p->role == PROTO_SERVER ? p->identity->public_key : p->identity->peer_public_key, 32);
    APPEND(p->role == PROTO_CLIENT ? p->dh_public : p->peer_dh, 32);
    APPEND(p->role == PROTO_SERVER ? p->dh_public : p->peer_dh, 32);
#undef APPEND
    sec_sha256(p->transcript, transcript, offset);
    sec_hkdf_aes128(p->aes_key, secret, p->transcript);
    memcpy(p->session_id, p->transcript, 16);
    wipe(secret, sizeof(secret));
    wipe(p->dh_private, sizeof(p->dh_private));
    return true;
}

static void confirmation(const struct proto *p, uint8_t role, uint8_t out[32])
{
    uint8_t input[33];
    memcpy(input, p->transcript, 32);
    input[32] = role;
    sec_sha256(out, input, sizeof(input));
}

static void send_confirmation(struct proto *p, uint64_t now)
{
    uint8_t token[32], payload[64];
    confirmation(p, p->role, token);
    size_t length = encrypt(p, payload, token, sizeof(token));
    frame(p, p->role == PROTO_CLIENT ? PKT_CONFIRM : PKT_CONFIRM_ACK,
          0, payload, length, now, true, 1);
    wipe(token, sizeof(token));
}

void proto_init(struct proto *p, uint8_t role,
                const struct proto_identity *identity, uint64_t now)
{
    wipe(p, sizeof(*p));
    p->identity = identity;
    p->role = role;
    p->last_rx_ms = now;
    p->phase = PH_LISTEN;
    if (role == PROTO_CLIENT) {
        sec_random(p->client_nonce, sizeof(p->client_nonce));
        p->phase = PH_HELLO_ACK;
        frame(p, PKT_HELLO, 0, identity->public_key, 32, now, true, 1);
    }
}

bool proto_tick(struct proto *p, uint64_t now)
{
    if (p->phase != PH_LISTEN && now - p->last_rx_ms >= PROTO_TIMEOUT_MS) {
        uint8_t role = p->role;
        const struct proto_identity *identity = p->identity;
        proto_init(p, role, identity, now);
        return true;
    }
    return false;
}

bool proto_tx_due(const struct proto *p, uint64_t now)
{
    return p->tx_remaining && now >= p->next_tx_ms;
}

void proto_tx_done(struct proto *p, uint64_t now, bool success)
{
    if (success && !p->tx_repeat && p->tx_remaining) { --p->tx_remaining; }
    uint8_t jitter;
    sec_random(&jitter, 1);
    /* Count from END of transmission; large SF10 frames take seconds. */
    /* Leave time for a full receipt plus peer signature processing before
     * the second data copy takes the half-duplex radio away from RX. */
    p->next_tx_ms = now + (p->tx_repeat ? (p->role == PROTO_CLIENT ? 4000 : 5500) : 3000)
                        + jitter * 2;
}

static bool packet_valid(const struct proto *p, const uint8_t *in, size_t length)
{
    if (length < PROTO_HEADER_LEN + SEC_SIG_LEN || length > PROTO_MAX_PACKET) { return false; }
    size_t payload = ((size_t)in[36] << 8) | in[37];
    if (payload + PROTO_HEADER_LEN + SEC_SIG_LEN != length ||
        !equal(in, magic, 4) || in[4] != 1 || in[7] != p->role ||
        in[6] != (p->role == PROTO_CLIENT ? PROTO_SERVER : PROTO_CLIENT) ||
        !equal(in + 8, p->identity->pair_id, 8)) { return false; }
    uint8_t type = in[5];
    if ((p->role == PROTO_CLIENT && type != PKT_HELLO_ACK && type != PKT_KEY_ACK &&
         type != PKT_CONFIRM_ACK && type != PKT_RECEIPT) ||
        (p->role == PROTO_SERVER && type != PKT_HELLO && type != PKT_KEY &&
         type != PKT_CONFIRM && type != PKT_DATA)) { return false; }
    if (type < PKT_DATA && get32(in + 32) != 0) { return false; }
    if (type >= PKT_DATA && get32(in + 32) == 0) { return false; }
    size_t required = type == PKT_HELLO ? 32 :
                      type <= PKT_KEY_ACK ? 48 :
                      type <= PKT_CONFIRM_ACK ? 64 : 32;
    if (type == PKT_DATA) {
        if (payload < 32 || payload > 144 || payload % 16) { return false; }
    } else if (payload != required) { return false; }
    if (type <= PKT_HELLO_ACK &&
        !equal(in + PROTO_HEADER_LEN, p->identity->peer_public_key, 32)) { return false; }
    return sec_verify(in + length - SEC_SIG_LEN, p->identity->peer_public_key,
                      in, length - SEC_SIG_LEN);
}

static bool seen(const struct proto *p, uint32_t sequence)
{
    if (sequence > p->rx_highest) { return false; }
    uint32_t behind = p->rx_highest - sequence;
    return behind >= 64 || (p->rx_bitmap & (UINT64_C(1) << behind));
}

static void remember(struct proto *p, uint32_t sequence)
{
    if (sequence > p->rx_highest) {
        uint32_t ahead = sequence - p->rx_highest;
        p->rx_bitmap = ahead >= 64 ? 1 : (p->rx_bitmap << ahead) | 1;
        p->rx_highest = sequence;
    } else {
        p->rx_bitmap |= UINT64_C(1) << (p->rx_highest - sequence);
    }
}

enum proto_result proto_receive(struct proto *p, const uint8_t *in,
                                size_t length, uint64_t now, struct proto_event *event)
{
    memset(event, 0, sizeof(*event));
    if (!packet_valid(p, in, length)) { return RX_REJECTED; }
    uint8_t type = in[5];
    const uint8_t *payload = in + PROTO_HEADER_LEN;
    size_t payload_length = length - PROTO_HEADER_LEN - SEC_SIG_LEN;
    enum proto_result result = RX_PROGRESS;
    uint8_t reply[48];

    if (p->role == PROTO_SERVER && type == PKT_HELLO && p->phase == PH_LISTEN) {
        memcpy(p->client_nonce, in + 16, 16);
        sec_random(p->server_nonce, 16);
        sec_dh_keygen(p->dh_public, p->dh_private);
        memcpy(reply, p->identity->public_key, 32);
        memcpy(reply + 32, p->server_nonce, 16);
        frame(p, PKT_HELLO_ACK, 0, reply, 48, now, true, 1);
        p->phase = PH_KEY;
    } else {
        if (!equal(in + 16, type <= PKT_KEY_ACK ? p->client_nonce : p->session_id, 16)) {
            return RX_REJECTED;
        }
        if (p->role == PROTO_CLIENT && type == PKT_HELLO_ACK && p->phase == PH_HELLO_ACK) {
            memcpy(p->server_nonce, payload + 32, 16);
            sec_dh_keygen(p->dh_public, p->dh_private);
            memcpy(reply, p->server_nonce, 16);
            memcpy(reply + 16, p->dh_public, 32);
            frame(p, PKT_KEY, 0, reply, 48, now, true, 1);
            p->phase = PH_KEY_ACK;
        } else if (p->role == PROTO_SERVER && type == PKT_KEY && p->phase == PH_KEY) {
            if (!equal(payload, p->server_nonce, 16) || !derive_session(p, payload + 16)) {
                return RX_REJECTED;
            }
            memcpy(reply, p->server_nonce, 16);
            memcpy(reply + 16, p->dh_public, 32);
            frame(p, PKT_KEY_ACK, 0, reply, 48, now, true, 1);
            p->phase = PH_CONFIRM;
        } else if (p->role == PROTO_CLIENT && type == PKT_KEY_ACK && p->phase == PH_KEY_ACK) {
            if (!equal(payload, p->server_nonce, 16) || !derive_session(p, payload + 16)) {
                return RX_REJECTED;
            }
            send_confirmation(p, now);
            p->phase = PH_CONFIRM_ACK;
        } else if ((p->role == PROTO_SERVER && type == PKT_CONFIRM &&
                    (p->phase == PH_CONFIRM || p->phase == PH_READY)) ||
                   (p->role == PROTO_CLIENT && type == PKT_CONFIRM_ACK &&
                    (p->phase == PH_CONFIRM_ACK || p->phase == PH_READY))) {
            uint8_t expected[32], plain[128];
            size_t plain_length = 0;
            confirmation(p, in[6], expected);
            bool valid = decrypt(p, plain, &plain_length, payload, payload_length) &&
                         plain_length == 32 && equal(plain, expected, 32);
            wipe(plain, sizeof(plain));
            wipe(expected, sizeof(expected));
            if (!valid) { return RX_REJECTED; }
            bool first = p->phase != PH_READY;
            if (p->role == PROTO_SERVER) { send_confirmation(p, now); }
            else if (first) { p->tx_remaining = 0; p->tx_repeat = false; }
            p->phase = PH_READY;
            result = first ? RX_CONNECTED : RX_PROGRESS;
        } else if (p->role == PROTO_SERVER && type == PKT_DATA && p->phase == PH_READY) {
            uint32_t sequence = get32(in + 32);
            uint8_t hash[32];
            if (seen(p, sequence)) {
                result = RX_DUPLICATE;
            } else {
                if (!decrypt(p, event->message, &event->length, payload, payload_length) ||
                    event->length > PROTO_MAX_MESSAGE) {
                    wipe(event, sizeof(*event));
                    return RX_REJECTED;
                }
                event->message[event->length] = 0;
                remember(p, sequence);
                result = RX_DATA;
            }
            event->sequence = sequence;
            sec_sha256(hash, in, length);
            /* A receipt proves which ciphertext arrived; it does not trigger
             * additional data retries. Data delivery remains best effort. */
            frame(p, PKT_RECEIPT, sequence, hash, sizeof(hash), now, false, 1);
        } else if (p->role == PROTO_CLIENT && type == PKT_RECEIPT && p->phase == PH_READY) {
            if (get32(in + 32) != p->tx_sequence || !equal(payload, p->receipt_hash, 32)) {
                return RX_REJECTED;
            }
            event->sequence = p->tx_sequence;
            result = p->receipt_seen ? RX_PROGRESS : RX_RECEIPT;
            p->receipt_seen = true;
        } else if ((p->role == PROTO_SERVER && type == PKT_HELLO && p->phase == PH_KEY) ||
                   (p->role == PROTO_SERVER && type == PKT_KEY && p->phase == PH_CONFIRM &&
                    equal(payload, p->server_nonce, 16) && equal(payload + 16, p->peer_dh, 32)) ||
                   (p->role == PROTO_CLIENT && type == PKT_HELLO_ACK && p->phase == PH_KEY_ACK &&
                    equal(payload + 32, p->server_nonce, 16)) ||
                   (p->role == PROTO_CLIENT && type == PKT_KEY_ACK && p->phase == PH_CONFIRM_ACK &&
                    equal(payload, p->server_nonce, 16) && equal(payload + 16, p->peer_dh, 32))) {
            /* Peer missed our next stage: resend the cached response without
             * changing keys, nonces, or moving the state machine backwards. */
            p->next_tx_ms = now;
        } else { return RX_REJECTED; }
    }
    p->last_rx_ms = now;
    return result;
}

bool proto_send_data(struct proto *p, const uint8_t *message, size_t length, uint64_t now)
{
    if (p->role != PROTO_CLIENT || p->phase != PH_READY || p->tx_remaining ||
        length > PROTO_MAX_MESSAGE || p->tx_sequence == UINT32_MAX) { return false; }
    uint8_t payload[144];
    size_t encrypted_length = encrypt(p, payload, message, length);
    frame(p, PKT_DATA, ++p->tx_sequence, payload, encrypted_length, now, false, 2);
    sec_sha256(p->receipt_hash, p->tx_packet, p->tx_length);
    p->receipt_seen = false;
    return true;
}
