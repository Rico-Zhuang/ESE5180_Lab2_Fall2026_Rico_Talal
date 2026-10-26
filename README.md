# Lab 2 IoT Security

ESE5180: IoT Wireless, Security, & Scaling

**Group Number:**

| Team Member Name | Email Address       |
|------------------|---------------------|
| Talal Ammache| tammache@seas.upenn.edu|
| Rico Zhuang         | zzhuan13@engineering.upenn.edu           |

**GitHub Repository URL:** https://github.com/Rico-Zhuang/ESE5180_Lab2_Fall2026_Rico_Talal

**Lab dependencies:** https://github.com/ese5180/ESE5180-Lab-Dependencies

## Part 1 — Implementing Our Own LoRa Security

The implementation is included directly in this group repository under [`lab2_security/`](lab2_security/):

- [Client firmware](lab2_security/LoRa_Encrypted_Client_Zephyr/)
- [Server firmware](lab2_security/LoRa_Encrypted_Server_Zephyr/)
- [Shared protocol and radio loop](lab2_security/LoRa_Security_Common/)
- [Build instructions, packet definitions, verification results, and checkoff procedure](lab2_security/README.md)
- [Protocol tests](lab2_security/tests/) and [build/provisioning tools](lab2_security/tools/)

The client and server authenticate each other, exchange ephemeral Curve25519 keys, confirm an AES-128 session key, and transfer signed, encrypted readings. Each reading is transmitted twice; the server prints it once and ignores the duplicate. The firmware also retries handshake packets and restarts after one minute without an authenticated response.

Both boards have been flashed and verified. Hardware checks covered pairing, encrypted data delivery, duplicate rejection, signed receipts, and timeout recovery. All ten host protocol test groups pass. The teaching-team demonstration and individual explanations are still required. The optional TCP-like extra credit is not implemented.

The Crypto dependency is included with its original licenses. Generated `build*` folders and private `src/identity.h` files are excluded from Git. The local `ese5180deps/` checkout is only the starter reference; the submitted implementations are the regular files in `lab2_security/`.

### Answer 1.1

We chose Curve25519 Diffie–Hellman because the boards can derive a fresh shared key without transmitting a secret or asking someone to enter a new passphrase for each connection. The starter already provides the DH operations. We use Ed25519 signatures and provisioned peer public keys to authenticate the exchange, then derive the AES key with HKDF-SHA256 and confirm it with signed, encrypted challenge values. This adds identity provisioning and a larger handshake, but avoids trusting a public key just because it arrived in an advertisement.

The remaining weaknesses include radio jamming, packet loss, traffic analysis, denial of service through repeated traffic, and physical extraction of a board's signing key. LoRa's long range increases the area from which someone could listen or interfere. For an occasional, noncritical sensor reading, an isolated lost packet may be acceptable and fresh DH exchanges are infrequent. That reduces the operational impact; it does not remove the vulnerabilities or make LoRa inherently secure.

For confidentiality, AES encrypts application data using a key derived locally from the authenticated DH exchange. For integrity and identity, signatures cover the entire header and ciphertext, confirmation binds the handshake transcript, and session IDs plus sequence tracking reject replayed delivery. For availability under ordinary packet loss, ACK retries, two data transmissions, and one-minute recovery prevent the protocol from waiting forever on a lost message. These mechanisms support the CIA goals within the lab's packet-loss threat model. They cannot guarantee availability against an active jammer or guarantee delivery when both copies are lost.

## Part 2 — Encryption Speed and Memory Tradeoffs

The [AES benchmark](lab2_security/AES_Benchmark_Zephyr/) measures the four required variants. All four were built and run on the same NUCLEO-WL55JC board at 48 MHz on October 26, 2026, using 200 iterations and a 176-byte message. Each passed the FIPS-197 known-answer test and the full-message round-trip check. The [run instructions](lab2_security/AES_Benchmark_Zephyr/README.md) and [saved serial, size, and symbol output](lab2_security/AES_Benchmark_Zephyr/results/) accompany the results below.

### Answer 2.1 — Speed

| Variant | Key setup, first call (cyc) | Key setup (cyc) | Encrypt (cyc/B) | Decrypt (cyc/B) | Encrypt 176 B (µs) |
| --- | ---: | ---: | ---: | ---: | ---: |
| SW, RAM tables | 46,319 | 8,815 | 82 | 82 | 301.628 |
| SW, ROM tables | 8,891 | 8,886 | 106 | 106 | 392.251 |
| SW, ROM + fewer | 8,902 | 8,882 | 107 | 107 | 395.003 |
| HW | 1,098 | 1,036 | 62 | 81 | 228.128 |

Each row comes from one run of 200 iterations. Cycle columns use the integer averages printed by the benchmark; the microsecond column is converted from the full accumulated cycle count before averaging, so it retains more precision.

### Answer 2.2 — Memory

| Variant | text | data | bss | Flash (text + data) | RAM (data + bss) |
| --- | ---: | ---: | ---: | ---: | ---: |
| SW, RAM tables | 30,704 | 220 | 19,028 | 30,924 | 19,248 |
| SW, ROM tables | 38,912 | 220 | 10,280 | 39,132 | 10,500 |
| SW, ROM + fewer | 32,808 | 220 | 10,280 | 33,028 | 10,500 |
| HW | 26,464 | 492 | 9,304 | 26,956 | 9,796 |

All values are bytes from `arm-zephyr-eabi-size`. Flash is `text + data` and RAM is `data + bss`, as specified in the handout.

### Answer 2.3 — Locating the tables

| Variant | FT0 address | FT0 in RAM or flash | FT1 present | FSb address |
| --- | --- | --- | --- | --- |
| SW, RAM tables | `0x20002510` | RAM | yes | `0x20002c24` |
| SW, ROM tables | `0x080089f0` | flash | yes | `0x080096fd` |
| SW, ROM + fewer | `0x08007210` | flash | missing | `0x08007f25` |
| HW | missing | missing | missing | missing |

### Answer 2.4 — Choosing a variant

We would use the STM32 hardware AES variant. It used 9,796 bytes of RAM, compared with 19,248 bytes for RAM tables and 10,500 bytes for either ROM variant, which makes it the best fit for limited free RAM. It also encrypted the 176-byte message in 228.128 µs, compared with 301.628 µs for RAM tables and 395.003 µs for ROM with fewer tables. Since the sensor encrypts only once every ten minutes, the small timing differences matter less than keeping RAM available, so the lowest measured RAM use is our main reason for choosing hardware AES.
