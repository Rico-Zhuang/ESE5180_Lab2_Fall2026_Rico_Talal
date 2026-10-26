# AES_Benchmark_Zephyr (Lab 2, Part 2)

Standalone AES-128 speed/memory benchmark for the NUCLEO-WL55JC. One board, no radio.

The timing section in `src/main.c` measures 200 key setups, 200 encryptions, and 200 decryptions of a 176-byte message. Each call is bracketed by `timing_counter_get()`; teardown, error checks, and cycle accumulation happen outside those brackets. Encryption and decryption each reuse an already prepared key. The first key setup is measured separately before the known-answer test warms up the implementation.

All four variants were built and measured on October 26, 2026. Each passed the FIPS-197 known-answer test and the 176-byte round-trip check. Answers 2.1–2.4 are in the [group README](../../README.md#part-2--encryption-speed-and-memory-tradeoffs); the [results folder](results/) contains each run's serial output and the matching `size` and `nm` output.

Measurements used the board with ST-LINK serial `0010000D4142500220353451`, a 48 MHz cycle counter, Zephyr 4.4.0 (`bf801e4e3d19`) in the installed nRF Connect SDK workspace, and Zephyr SDK 1.0.1 / GCC 14.3.0. The board was restored to its Part 1 client firmware afterward and paired again with the server.

## Variants (one per build)

| Overlay | Implementation | Where the AES tables live |
|---|---|---|
| `sw_ram.conf` | Software, PSA Crypto | 4+4 tables built at boot in **RAM** |
| `sw_rom.conf` | Software, PSA Crypto | 4+4 tables precomputed in **flash** |
| `sw_rom_fewer.conf` | Software, PSA Crypto | 1+1 tables in **flash** (more math per byte) |
| `hw.conf` | STM32WL55 AES peripheral | no tables, done in hardware |

## Build, flash, read

From your Zephyr workspace (with the venv active):

```bash
APP=$HOME/ESE5180/ESE5180_Lab2_Fall2026_Rico_Talal/lab2_security/AES_Benchmark_Zephyr
west build -p -b nucleo_wl55jc -d "$APP/build_sw_ram" "$APP" -- -DEXTRA_CONF_FILE=sw_ram.conf
west flash -d "$APP/build_sw_ram" --runner openocd --cmd-pre-init "adapter serial YOUR_STLINK_SERIAL"
python3 -m serial.tools.miniterm /dev/ttyACM0 115200
```

On the computer used for these measurements, the build used `--no-sysbuild` before `--`, and these additional CMake arguments after `--` to use the locally installed STM32 HAL and OpenOCD:

```bash
-DBOARD_FLASH_RUNNER=openocd \
-DOPENOCD="$APP/../tools/openocd.sh" \
-DZEPHYR_EXTRA_MODULES="$HOME/ESE5180/.deps/hal_stm32"
```

The toolchain environment is the same one configured by `../tools/lab2.py`. The Nordic SDK emitted its unsupported-SoC notice for the STM32 target; all four Zephyr builds completed and passed the board checks recorded here.

Select the connected board by its ST-LINK serial and use its corresponding console port. Press its reset button after opening the console. Require `FIPS-197 known-answer test: PASS` and `Round trip of 176 B payload: OK` before recording results. Save the serial output from each run, for example in that variant's ignored build folder.

Repeat with `sw_rom`, `sw_rom_fewer` and `hw` (change both the overlay and the `-d` folder). The same source is used for all four variants. The hardware backend retains the starter's one-block-per-call ECB implementation.

The `CSV,...` line contains the variant, first key setup cycles, average key setup cycles, encryption cycles per byte, decryption cycles per byte, and average encryption time for 176 bytes in microseconds. The variant name is quoted because the software variant names contain commas.

## Memory and table locations

Use the toolchain's `size` and `nm` tools for the values requested by questions 2.2 and 2.3:

```bash
arm-zephyr-eabi-size "$APP/build_sw_ram/zephyr/zephyr.elf"
arm-zephyr-eabi-nm -S "$APP/build_sw_ram/zephyr/zephyr.elf" | grep -E " (FT0|FT1|RT0|FSb)$"
```

Repeat for each build folder. For the report, flash is `text + data` and RAM is `data + bss`. Addresses starting at `0x08000000` are in flash; addresses starting at `0x20000000` are in RAM. Write `missing` only when a symbol is absent from the actual `nm` output.
