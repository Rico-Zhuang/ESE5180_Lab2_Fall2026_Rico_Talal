#include <zephyr/kernel.h>
#include <zephyr/console/console.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/kvss/nvs.h>
#include <zephyr/sys/util.h>
#include <psa/crypto.h>
#include <soc.h>
#include <errno.h>
#include <string.h>

#define NVS_APP_KEY_ID 1
#define LORAWAN_KEY_SIZE 16

static struct nvs_fs fs;

/* Provision over serial so the plaintext key never becomes part of the image. */
static int receive_app_key(uint8_t plain[LORAWAN_KEY_SIZE])
{
    char hex[2 * LORAWAN_KEY_SIZE];
    size_t count = 0;
    int rc = console_init();

    if (rc < 0) {
        return rc;
    }
    printk("NVS empty. Enter AppKey (32 hex digits, then Enter; no echo):\n");
    while (true) {
        int c = console_getchar();

        if (c < 0) {
            return c;
        }
        if (c == '\r' || c == '\n') {
            break;
        }
        if (count == sizeof(hex)) {
            return -EINVAL;
        }
        hex[count++] = (char)c;
    }
    if (count != sizeof(hex) ||
        hex2bin(hex, count, plain, LORAWAN_KEY_SIZE) != LORAWAN_KEY_SIZE) {
        return -EINVAL;
    }
    return 0;
}

static void print_key(const uint8_t plain[LORAWAN_KEY_SIZE])
{
    printk("AppKey: ");
    for (size_t i = 0; i < LORAWAN_KEY_SIZE; ++i) {
        printk("%02X", plain[i]);
    }
    printk("\n");
}

#if LAB3_PLAINTEXT
static int store_unencrypted_secret(const uint8_t *plain, size_t len)
{
    int rc = nvs_write(&fs, NVS_APP_KEY_ID, plain, len);

    return rc < 0 ? rc : (rc == 0 || rc == len ? 0 : -EIO);
}
#else
static const uint8_t app_salt[] = "ESE5180_LAB2_SECTION3_2_SALT";
static const uint8_t key_info[] = "LoRaWAN AppKey wrapping";

/* CBC has no authentication tag. A digest checks the decrypted key without
 * embedding the original secret in flash. This detects the lab's exact clone;
 * it is not an authenticated-encryption format for hostile record edits.
 */
struct encrypted_record {
    uint8_t cipher_text[32]; /* PSA prepends a random 16-byte IV. */
    uint8_t digest[32];      /* SHA-256 of the original AppKey. */
};

static void get_stm32_hardware_uid(uint8_t uid_out[12])
{
    const volatile uint32_t *uid_registers = (const volatile uint32_t *)UID_BASE;

    for (size_t i = 0; i < 3; ++i) {
        uint32_t word = uid_registers[i];

        memcpy(uid_out + i * sizeof(word), &word, sizeof(word));
    }
}

static psa_status_t derive_huk_aes_key(psa_key_id_t *key_handle)
{
    uint8_t hw_uid[12];
    psa_key_id_t uid_key = PSA_KEY_ID_NULL;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_algorithm_t hkdf = PSA_ALG_HKDF(PSA_ALG_SHA_256);
    psa_status_t status;

    get_stm32_hardware_uid(hw_uid);
    printk("STM32 Silicon UID: ");
    for (size_t i = 0; i < sizeof(hw_uid); ++i) {
        printk("%02X", hw_uid[i]);
    }
    printk("\n");

    psa_set_key_type(&attributes, PSA_KEY_TYPE_DERIVE);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, hkdf);
    status = psa_import_key(&attributes, hw_uid, sizeof(hw_uid), &uid_key);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }
    status = psa_key_derivation_setup(&operation, hkdf);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }
    status = psa_key_derivation_input_bytes(&operation, PSA_KEY_DERIVATION_INPUT_SALT,
                                           app_salt, sizeof(app_salt) - 1);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }
    status = psa_key_derivation_input_key(&operation, PSA_KEY_DERIVATION_INPUT_SECRET,
                                         uid_key);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }
    status = psa_key_derivation_input_bytes(&operation, PSA_KEY_DERIVATION_INPUT_INFO,
                                           key_info, sizeof(key_info) - 1);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }
    psa_reset_key_attributes(&attributes);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 128);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_CBC_NO_PADDING);
    status = psa_key_derivation_output_key(&attributes, &operation, key_handle);

cleanup:
    psa_key_derivation_abort(&operation);
    psa_destroy_key(uid_key);
    psa_reset_key_attributes(&attributes);
    return status;
}

static int store_encrypted_secret(psa_key_id_t key_handle, const uint8_t *plain, size_t len)
{
    struct encrypted_record record;
    size_t out_len;
    psa_status_t status = psa_cipher_encrypt(key_handle, PSA_ALG_CBC_NO_PADDING,
                                            plain, len, record.cipher_text,
                                            sizeof(record.cipher_text), &out_len);

    if (status != PSA_SUCCESS || out_len != sizeof(record.cipher_text)) {
        return status != PSA_SUCCESS ? status : -EIO;
    }
    status = psa_hash_compute(PSA_ALG_SHA_256, plain, len, record.digest,
                              sizeof(record.digest), &out_len);
    if (status != PSA_SUCCESS || out_len != sizeof(record.digest)) {
        return status != PSA_SUCCESS ? status : -EIO;
    }
    int rc = nvs_write(&fs, NVS_APP_KEY_ID, &record, sizeof(record));

    return rc < 0 ? rc : (rc == 0 || rc == sizeof(record) ? 0 : -EIO);
}

static int read_and_decrypt_secret(psa_key_id_t key_handle)
{
    struct encrypted_record record;
    uint8_t plain[LORAWAN_KEY_SIZE];
    size_t out_len;
    int rc = nvs_read(&fs, NVS_APP_KEY_ID, &record, sizeof(record));

    if (rc != sizeof(record)) {
        printk("[FAIL] Expected encrypted NVS record; erase NVS before provisioning.\n");
        return rc < 0 ? rc : -EINVAL;
    }
    psa_status_t status = psa_cipher_decrypt(key_handle, PSA_ALG_CBC_NO_PADDING,
                                            record.cipher_text, sizeof(record.cipher_text),
                                            plain, sizeof(plain), &out_len);

    if (status != PSA_SUCCESS || out_len != sizeof(plain)) {
        return status != PSA_SUCCESS ? status : -EIO;
    }
    status = psa_hash_compare(PSA_ALG_SHA_256, plain, out_len,
                              record.digest, sizeof(record.digest));
    if (status != PSA_SUCCESS) {
        printk("[FAIL] Decrypted key check failed: wrong board UID or damaged record.\n");
        return status;
    }
    printk("[PASS] Stored AppKey decrypted and verified.\n");
    print_key(plain);
    return 0;
}
#endif

int main(void)
{
    printk("\n--- Lab 2 Part 3: %s storage ---\n",
           LAB3_PLAINTEXT ? "plaintext" : "UID-derived encrypted");
    fs.flash_device = PARTITION_DEVICE(storage_partition);
    fs.offset = PARTITION_OFFSET(storage_partition);
    struct flash_pages_info info;
    int rc;

    if (!device_is_ready(fs.flash_device)) {
        printk("[FAIL] Flash device not ready.\n");
        return 0;
    }
    rc = flash_get_page_info_by_offs(fs.flash_device, fs.offset, &info);
    if (rc < 0) {
        printk("[FAIL] Flash page lookup: %d\n", rc);
        return 0;
    }
    fs.sector_size = info.size;
    fs.sector_count = PARTITION_SIZE(storage_partition) / info.size;
    rc = nvs_mount(&fs);
    if (rc < 0) {
        printk("[FAIL] NVS mount: %d\n", rc);
        return 0;
    }

    uint8_t plain[LORAWAN_KEY_SIZE];
    rc = nvs_read(&fs, NVS_APP_KEY_ID, plain, sizeof(plain));
    if (rc < 0 && rc != -ENOENT) {
        printk("[FAIL] NVS read: %d\n", rc);
        return 0;
    }
    bool needs_provisioning = rc == -ENOENT;

#if LAB3_PLAINTEXT
    if (needs_provisioning) {
        rc = receive_app_key(plain);
        if (rc == 0) {
            rc = store_unencrypted_secret(plain, sizeof(plain));
        }
    } else if (rc != sizeof(plain)) {
        rc = -EINVAL;
    } else {
        rc = 0;
    }
    if (rc == 0) {
        printk("[PASS] Plaintext AppKey stored in NVS.\n");
        print_key(plain);
    }
#else
    psa_key_id_t key_handle = PSA_KEY_ID_NULL;

    rc = psa_crypto_init();
    if (rc == PSA_SUCCESS) {
        rc = derive_huk_aes_key(&key_handle);
    }
    if (rc == PSA_SUCCESS && needs_provisioning) {
        rc = receive_app_key(plain);
        if (rc == 0) {
            rc = store_encrypted_secret(key_handle, plain, sizeof(plain));
        }
    }
    /* Never replace an existing record: Board B must test Board A's ciphertext. */
    if (rc == 0) {
        rc = read_and_decrypt_secret(key_handle);
    }
    psa_destroy_key(key_handle);
#endif
    if (rc != 0) {
        printk("[FAIL] Part 3 stopped: %d. NVS was not replaced.\n", rc);
    }
    return 0;
}
