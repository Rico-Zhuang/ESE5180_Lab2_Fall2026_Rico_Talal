#include "sec_crypto.h"

#include "RNG.h" /* shim: backs the library's RNG with Zephyr's CSPRNG */
#include "Curve25519.h"
#include "Ed25519.h"
#include "SHA256.h"
#include "AES.h"
#include "Crypto.h"
#include <string.h>

RNGClass RNG;

extern "C" {

void sec_random(uint8_t *buf, size_t len)
{
	RNG.rand(buf, len);
}

void sec_sign_keygen(uint8_t pub[SEC_PUBKEY_LEN], uint8_t priv[SEC_PRIVKEY_LEN])
{
	Ed25519::generatePrivateKey(priv);
	Ed25519::derivePublicKey(pub, priv);
}

void sec_sign(uint8_t sig[SEC_SIG_LEN], const uint8_t priv[SEC_PRIVKEY_LEN],
	      const uint8_t pub[SEC_PUBKEY_LEN], const uint8_t *msg, size_t len)
{
	Ed25519::sign(sig, priv, pub, msg, len);
}

bool sec_verify(const uint8_t sig[SEC_SIG_LEN], const uint8_t pub[SEC_PUBKEY_LEN],
		const uint8_t *msg, size_t len)
{
	return Ed25519::verify(sig, pub, msg, len);
}

void sec_dh_keygen(uint8_t pub[SEC_PUBKEY_LEN], uint8_t priv[SEC_PRIVKEY_LEN])
{
	/* dh1 generates and clamps a random private key f and outputs k = f * base */
	Curve25519::dh1(pub, priv);
}

bool sec_dh_shared(uint8_t secret[32], const uint8_t their_pub[SEC_PUBKEY_LEN],
		   uint8_t priv[SEC_PRIVKEY_LEN])
{
	for (int i = 0; i < 32; i++) {
		secret[i] = their_pub[i];
	}
	/* dh2 turns k (their public key) into the shared secret and wipes f */
	return Curve25519::dh2(secret, priv);
}

void sec_sha256(uint8_t out[SEC_HASH_LEN], const uint8_t *data, size_t len)
{
	SHA256 sha;

	sha.reset();
	sha.update(data, len);
	sha.finalize(out, SEC_HASH_LEN);
}

void sec_hkdf_aes128(uint8_t out[16], const uint8_t secret[32], const uint8_t salt[32])
{
    /* RFC 5869 extract, then one expand block; retain its first 16 bytes. */
    static const uint8_t info[] = "ESE5180 LoRa AES128 v1";
    uint8_t prk[32], output[32];
    const uint8_t counter = 1;
    SHA256 sha;
    sha.resetHMAC(salt, 32);
    sha.update(secret, 32);
    sha.finalizeHMAC(salt, 32, prk, 32);
    sha.resetHMAC(prk, 32);
    sha.update(info, sizeof(info) - 1);
    sha.update(&counter, 1);
    sha.finalizeHMAC(prk, 32, output, 32);
    memcpy(out, output, 16);
    clean(prk);
    clean(output);
}

void sec_aes128_encrypt(uint8_t *out, const uint8_t key[SEC_AES_KEY_LEN],
			const uint8_t *in, size_t len)
{
	AES128 aes;

	aes.setKey(key, SEC_AES_KEY_LEN);
	for (size_t i = 0; i + SEC_AES_BLOCK <= len; i += SEC_AES_BLOCK) {
		aes.encryptBlock(out + i, in + i);
	}
}

void sec_aes128_decrypt(uint8_t *out, const uint8_t key[SEC_AES_KEY_LEN],
			const uint8_t *in, size_t len)
{
	AES128 aes;

	aes.setKey(key, SEC_AES_KEY_LEN);
	for (size_t i = 0; i + SEC_AES_BLOCK <= len; i += SEC_AES_BLOCK) {
		aes.decryptBlock(out + i, in + i);
	}
}

} /* extern "C" */
