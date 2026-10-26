#!/usr/bin/env python3
"""Build or flash Part 1 with the existing Nordic/Zephyr installation."""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def environment():
    env = os.environ.copy()
    workspace = Path(env.get('LAB2_ZEPHYR_WORKSPACE', Path.home() / 'ncs/v3.4.0')).expanduser()
    bundle_path = env.get('LAB2_TOOLCHAIN_BUNDLE')
    candidates = sorted((Path.home() / 'ncs/toolchains').glob('*/environment.json'))
    if bundle_path:
        bundle = Path(bundle_path).expanduser()
    elif len(candidates) == 1:
        bundle = candidates[0].parent
    else:
        bundle = None  # Standard activated Zephyr environment, or explicit override.
    if bundle:
        for item in json.loads((bundle / 'environment.json').read_text())['env_vars']:
            key = item['key']
            if item['type'] == 'relative_paths':
                value = os.pathsep.join(str(bundle / p) for p in item['values'])
                if item.get('existing_value_treatment') == 'prepend_to' and env.get(key):
                    value += os.pathsep + env[key]
            else:
                value = item['value']
            env[key] = value
    if not (workspace / '.west').is_dir():
        raise SystemExit('Set LAB2_ZEPHYR_WORKSPACE to your existing west workspace.')
    env['ZEPHYR_BASE'] = str(workspace / 'zephyr')
    return workspace, env


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['build', 'flash'])
    parser.add_argument('role', choices=['client', 'server'])
    parser.add_argument('--probe', help='ST-LINK serial, required for flashing to select the board explicitly')
    args = parser.parse_args()
    workspace, env = environment()
    build = ROOT / f'build-{args.role}'
    if args.action == 'build':
        app = ROOT / f'LoRa_Encrypted_{args.role.title()}_Zephyr'
        command = ['west', 'build', '-p', 'auto', '-b', 'nucleo_wl55jc', '-d', str(build),
                   str(app), '--no-sysbuild', '--', '-DBOARD_FLASH_RUNNER=openocd']
        stm32 = Path(env.get('LAB2_STM32_MODULE', Path.home() / 'ESE5180/.deps/hal_stm32')).expanduser()
        if stm32.is_dir():
            command += [f'-DZEPHYR_EXTRA_MODULES={stm32}']
        if (Path.home() / '.local/share/ese5180-tools/openocd/usr/bin/openocd').is_file():
            command += [f'-DOPENOCD={ROOT / "tools/openocd.sh"}']
    else:
        if not args.probe or not args.probe.isalnum():
            parser.error('flash requires --probe with the ST-LINK serial from /dev/serial/by-id')
        command = ['west', 'flash', '-d', str(build), '--runner', 'openocd',
                   '--cmd-pre-init', f'adapter serial {args.probe}', '--verify']
    print(shlex.join(command), flush=True)
    subprocess.run(command, cwd=workspace, env=env, check=True)


if __name__ == '__main__':
    main()
