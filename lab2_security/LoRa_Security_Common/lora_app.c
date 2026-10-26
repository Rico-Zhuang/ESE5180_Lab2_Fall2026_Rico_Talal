/* SPDX-License-Identifier: Apache-2.0 */
#include "lora_app.h"
#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/lora.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

LOG_MODULE_REGISTER(secure_lora, LOG_LEVEL_INF);

#define RADIO_NODE DT_ALIAS(lora0)
BUILD_ASSERT(DT_NODE_HAS_STATUS_OKAY(RADIO_NODE), "No default LoRa radio");
static const struct gpio_dt_spec leds[] = {
    GPIO_DT_SPEC_GET(DT_NODELABEL(blue_led_1), gpios),
    GPIO_DT_SPEC_GET(DT_NODELABEL(green_led_2), gpios),
    GPIO_DT_SPEC_GET(DT_NODELABEL(red_led_3), gpios),
};
static struct proto protocol;

struct received_packet {
    uint8_t data[PROTO_MAX_PACKET];
    uint16_t length;
    int16_t rssi;
    int8_t snr;
};
K_MSGQ_DEFINE(received_packets, sizeof(struct received_packet), 4, 4);

static void receive_callback(const struct device *dev, uint8_t *data, uint16_t size,
                             int16_t rssi, int8_t snr, void *user_data)
{
    ARG_UNUSED(dev);
    ARG_UNUSED(user_data);
    if (size > PROTO_MAX_PACKET) { return; }
    struct received_packet packet = {.length = size, .rssi = rssi, .snr = snr};
    memcpy(packet.data, data, size);
    /* The callback only copies a frame. Crypto and printing run in main. */
    k_msgq_put(&received_packets, &packet, K_NO_WAIT);
}

static bool crypto_self_test(const struct proto_identity *identity)
{
    /* Exercise the target's RNG and 32-bit crypto code before networking.
     * All test secrets are temporary and are erased before returning. */
    struct {
        uint8_t challenge[16], signature[64];
        uint8_t public_a[32], private_a[32], public_b[32], private_b[32];
        uint8_t secret_a[32], secret_b[32], ciphertext[16], plaintext[16];
    } test;
    sec_random(test.challenge, sizeof(test.challenge));
    sec_sign(test.signature, identity->private_key, identity->public_key,
             test.challenge, sizeof(test.challenge));
    bool passed = sec_verify(test.signature, identity->public_key,
                             test.challenge, sizeof(test.challenge));
    sec_dh_keygen(test.public_a, test.private_a);
    sec_dh_keygen(test.public_b, test.private_b);
    passed &= sec_dh_shared(test.secret_a, test.public_b, test.private_a);
    passed &= sec_dh_shared(test.secret_b, test.public_a, test.private_b);
    passed &= memcmp(test.secret_a, test.secret_b, 32) == 0;
    sec_aes128_encrypt(test.ciphertext, test.secret_a, test.challenge, 16);
    sec_aes128_decrypt(test.plaintext, test.secret_a, test.ciphertext, 16);
    passed &= memcmp(test.challenge, test.plaintext, 16) == 0;
    volatile uint8_t *bytes = (volatile uint8_t *)&test;
    for (size_t i = 0; i < sizeof(test); ++i) { bytes[i] = 0; }
    return passed;
}

static void led(unsigned index, bool enabled)
{
    if (gpio_is_ready_dt(&leds[index])) { gpio_pin_set_dt(&leds[index], enabled); }
}

int secure_lora_main(uint8_t role, const struct proto_identity *identity)
{
    const struct device *radio = DEVICE_DT_GET(RADIO_NODE);
    struct lora_modem_config config = {
        .frequency = 433920000, .bandwidth = BW_125_KHZ, .datarate = SF_10,
        .preamble_len = 8, .coding_rate = CR_4_5, .iq_inverted = false,
        .public_network = false, .tx_power = -15, .tx = true,
    };
    if (!device_is_ready(radio)) { LOG_ERR("Radio is not ready"); return -ENODEV; }
    for (unsigned i = 0; i < ARRAY_SIZE(leds); ++i) {
        if (gpio_is_ready_dt(&leds[i])) { gpio_pin_configure_dt(&leds[i], GPIO_OUTPUT_INACTIVE); }
    }
    int ret = lora_config(radio, &config);
    if (ret) { LOG_ERR("LoRa configuration failed: %d", ret); return ret; }
    LOG_INF("%s: 433.92 MHz, SF10, BW125, -15 dBm",
            role == PROTO_CLIENT ? "CLIENT" : "SERVER");
    LOG_HEXDUMP_INF(identity->pair_id, sizeof(identity->pair_id), "Pair ID (public)");
    /* This driver caches airtime parameters only after a TX configuration.
     * Querying airtime after RX-only configuration divides by zero. */
    LOG_INF("Maximum frame airtime: %u ms", lora_airtime(radio, PROTO_MAX_PACKET));
    config.tx = false;
    ret = lora_config(radio, &config);
    if (ret) { LOG_ERR("Initial RX configuration failed: %d", ret); return ret; }
    if (!crypto_self_test(identity)) { LOG_ERR("Crypto self-test FAILED"); return -EIO; }
    LOG_INF("Crypto self-test passed: RNG, Ed25519, Curve25519, AES128");
    proto_init(&protocol, role, identity, k_uptime_get());
    ret = lora_recv_async(radio, receive_callback, NULL);
    if (ret) { LOG_ERR("Cannot start continuous RX: %d", ret); return ret; }
    LOG_INF("%s", role == PROTO_CLIENT ? "Starting handshake" : "Listening for authenticated HELLO");
    uint64_t next_message = 0;
    uint32_t reading = 0, rejected = 0;

    while (true) {
        uint64_t now = k_uptime_get();
        if (proto_tick(&protocol, now)) {
            LOG_WRN("No authenticated response for 60 s; restarting handshake");
            next_message = now;
        }
        led(0, protocol.phase != PH_READY);
        led(1, protocol.phase == PH_READY);
        if (role == PROTO_CLIENT && protocol.phase == PH_READY &&
            !protocol.tx_remaining && now >= next_message) {
            char message[PROTO_MAX_MESSAGE + 1];
            int length = snprintf(message, sizeof(message), "ESE5180 secure reading %u", reading);
            if (length > 0 && proto_send_data(&protocol, (uint8_t *)message, length, now)) {
                LOG_INF("Queued DATA seq=%u, %d plaintext bytes, two copies", protocol.tx_sequence, length);
                ++reading;
                next_message = now + 10000;
            }
        }
        if (proto_tx_due(&protocol, now)) {
            /* Stop continuous reception only for our own transmission. */
            ret = lora_recv_async(radio, NULL, NULL);
            config.tx = true;
            if (!ret) { ret = lora_config(radio, &config); }
            if (!ret) {
                led(2, true);
                ret = lora_send(radio, protocol.tx_packet, (uint8_t)protocol.tx_length);
                led(2, false);
            }
            if (ret) { LOG_WRN("TX failed: %d; will retry", ret); }
            else { LOG_INF("TX type=%u, %u bytes", protocol.tx_packet[5], (unsigned)protocol.tx_length); }
            proto_tx_done(&protocol, k_uptime_get(), ret == 0);
            config.tx = false;
            ret = lora_config(radio, &config);
            if (ret) { LOG_ERR("Cannot return to RX: %d", ret); return ret; }
            ret = lora_recv_async(radio, receive_callback, NULL);
            if (ret) { LOG_ERR("Cannot restart continuous RX: %d", ret); return ret; }
        }
        struct received_packet received;
        /* This timeout polls the queue, not the radio: RF reception remains
         * continuous even when a complete SF10 frame spans many iterations. */
        ret = k_msgq_get(&received_packets, &received, K_MSEC(100));
        if (!ret) {
            const uint8_t *packet = received.data;
            struct proto_event event;
            LOG_INF("RX %u bytes, RSSI=%d, SNR=%d", received.length, received.rssi, received.snr);
            enum proto_result result = proto_receive(&protocol, packet, received.length, k_uptime_get(), &event);
            switch (result) {
            case RX_CONNECTED:
                LOG_INF("PAIRED: peer signature and encrypted key confirmation verified");
                break;
            case RX_DATA:
                LOG_INF("DATA seq=%u, RSSI=%d, SNR=%d: %s", event.sequence, received.rssi, received.snr, event.message);
                break;
            case RX_DUPLICATE:
                LOG_INF("Duplicate/stale DATA seq=%u ignored", event.sequence);
                break;
            case RX_RECEIPT:
                LOG_INF("Server verified receipt of DATA seq=%u", event.sequence);
                break;
            case RX_PROGRESS:
                LOG_INF("Authenticated RX type=%u; phase=%u", packet[5], protocol.phase);
                break;
            default:
                if (++rejected % 16 == 1) { LOG_WRN("Rejected packet (total %u)", rejected); }
                break;
            }
        } else if (ret != -EAGAIN) {
            LOG_WRN("Receive queue failed: %d", ret);
            k_msleep(100);
        }
    }
}
