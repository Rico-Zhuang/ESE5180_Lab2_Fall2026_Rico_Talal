# Part 3 — Hardware Unique Keys

This project stores a 16-byte key in NVS at `0x0803F000`. Plaintext mode demonstrates extraction; the default mode wraps it with AES-128-CBC using HKDF-SHA256 over the board's 96-bit UID, the starter salt, and an application label.

We used the starter sample key `2B7E151628AED2A6ABF7158809CF4F3C`, as requested, instead of the unavailable Lab 1 key. It is entered over serial once, so it is absent from the compiled firmware. Booting with an existing NVS record only reads it; otherwise a clone could overwrite the evidence and incorrectly pass.

The starter's configuration and `psa_cipher_encrypt` API use CBC, despite its TODO comments saying GCM. A SHA-256 digest stored alongside the IV/ciphertext checks the decrypted key without embedding the original secret. This verifies the lab's exact-copy cloning test. The readable UID is not a secret hardware key, and the CBC record is not authenticated encryption.

## Recorded results

- [Plaintext memory screenshot](../../part3_plain.png): sample key at `0x0803F000`.
- [Encrypted memory screenshot](../../part3_encrypted.png): IV, ciphertext, and digest; no plaintext key anywhere in the 256 KiB flash dump.
- [Board output and clone comparison](results/clone-check.txt): A passed after reboot; B rejected the identical full flash image and also rejected it after reboot.

Both boards are left running Part 3 for checkoff:

| Board | ST-LINK serial | Console | Expected result |
| --- | --- | --- | --- |
| A | `0010000D4142500220353451` | `/dev/ttyACM1` | PASS |
| B | `002C001B4142500220353451` | `/dev/ttyACM0` | FAIL: wrong board UID |

Open a console at 115200 baud and press reset to repeat the check. ACM numbers can change; identify boards through `/dev/serial/by-id/`.

## Build and provision

In the activated Zephyr environment, set `APP` to this project and build both modes:

```bash
APP="$HOME/ESE5180/ESE5180_Lab2_Fall2026_Rico_Talal/lab2_security/Hardware_Unique_Keys"
west build -p auto -b nucleo_wl55jc -d "$APP/build_plaintext" "$APP" --no-sysbuild -- -DLAB3_PLAINTEXT=ON
west build -p auto -b nucleo_wl55jc -d "$APP/build_encrypted" "$APP" --no-sysbuild -- -DLAB3_PLAINTEXT=OFF
```

On this computer, use the environment from `../tools/lab2.py` and append these CMake options to each build:

```bash
-DBOARD_FLASH_RUNNER=openocd \
-DOPENOCD="$APP/../tools/openocd.sh" \
-DZEPHYR_EXTRA_MODULES="$HOME/ESE5180/.deps/hal_stm32"
```

For Part 3.1, program Board A with `build_plaintext/zephyr/zephyr.hex`. For Part 3.2, use `build_encrypted/zephyr/zephyr.hex`. **Erase the flash before each initial provisioning** so old plaintext NVS records cannot remain. Back up any firmware you need first. On this Linux setup, OpenOCD provides the SWD reads/writes corresponding to the manual's STM32CubeProgrammer commands:

```bash
OCD="$APP/../tools/openocd.sh"
CFG="$ZEPHYR_BASE/boards/st/nucleo_wl55jc/support/openocd.cfg"
BOARD_A=0010000D4142500220353451
BOARD_B=002C001B4142500220353451
IMAGE="$APP/build_plaintext/zephyr/zephyr.hex"  # Change to build_encrypted for 3.2.
"$OCD" -f "$CFG" -c "adapter serial $BOARD_A" \
  -c "init; reset halt; flash erase_address 0x08000000 0x40000; flash write_image $IMAGE; verify_image $IMAGE; reset run; shutdown"
python3 -m serial.tools.miniterm /dev/ttyACM1 115200
```

Press reset after opening the console. At the prompt, enter the 32 hex digits and press Enter. Input is not echoed. Close the monitor when finished. The key is requested only when NVS is empty; a failed clone never provisions a replacement.

## Dump and clone

After provisioning each mode, read the NVS partition and open the dump in an 8-bit hex viewer:

```bash
mkdir -p "$APP/build_evidence"
"$OCD" -f "$CFG" -c "adapter serial $BOARD_A" \
  -c "init; reset halt; dump_image $APP/build_evidence/nvs_dump.bin 0x0803F000 0x1000; reset run; shutdown"
xxd -g 1 -o 0x0803F000 "$APP/build_evidence/nvs_dump.bin"
```

With encrypted mode provisioned on A, copy all 256 KiB, including NVS, to B:

```bash
"$OCD" -f "$CFG" -c "adapter serial $BOARD_A" \
  -c "init; reset halt; dump_image $APP/build_evidence/flash_dump.bin 0x08000000 0x40000; reset run; shutdown"
"$OCD" -f "$CFG" -c "adapter serial $BOARD_B" \
  -c "init; reset halt; flash erase_address 0x08000000 0x40000; flash write_image $APP/build_evidence/flash_dump.bin 0x08000000 bin; verify_image $APP/build_evidence/flash_dump.bin 0x08000000 bin; reset run; shutdown"
```

Reset both boards with their consoles open. A must print `Stored AppKey decrypted and verified`; B must print `Decrypted key check failed`. Do not erase or provision B after cloning. Build folders, full flash dumps, and the local Part 1 backups in `build_evidence/` are ignored by Git.
