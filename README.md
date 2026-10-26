# Lab 2 IoT Security

ESE5180: IoT Wireless, Security, & Scaling

**Group Number:**

| Team Member Name | Email Address       |
|------------------|---------------------|
| [Name 1]         | [Email 1]           |
| [Name 2]         | [Email 2]           |

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
