#!/usr/bin/env python3
"""Exercise the same C protocol and Arduino Crypto sources used on the boards."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / 'build-host-tests'
BUILD.mkdir(exist_ok=True)
common = ROOT / 'LoRa_Security_Common'
client = ROOT / 'LoRa_Encrypted_Client_Zephyr/src'
shim = ROOT / 'tests/shim'
crypto = ROOT / 'Crypto/src'
flags = ['-g', '-O1', '-fno-omit-frame-pointer', '-fsanitize=address,undefined']
includes = [f'-I{common}', f'-I{client}', f'-I{shim}', f'-I{crypto}']
objects = []
for source in [common / 'security_protocol.c', ROOT / 'tests/test_protocol.c']:
    obj = BUILD / (source.stem + '.o')
    subprocess.run(['gcc', '-std=c11', '-Wall', '-Wextra', '-Werror', *flags, *includes,
                    '-c', str(source), '-o', str(obj)], check=True)
    objects.append(str(obj))
sources = [client / 'sec_crypto.cpp'] + [crypto / (name + '.cpp') for name in (
    'AES128', 'AESCommon', 'BigNumberUtil', 'BlockCipher', 'Crypto', 'Curve25519',
    'Ed25519', 'Hash', 'SHA256', 'SHA512')]
for source in sources:
    obj = BUILD / (source.stem + '.o')
    subprocess.run(['g++', '-std=c++17', *flags, *includes, '-include', str(shim / 'RNG.h'),
                    '-c', str(source), '-o', str(obj)], check=True)
    objects.append(str(obj))
binary = BUILD / 'test_protocol'
subprocess.run(['g++', *flags, *objects, '-o', str(binary)], check=True)
subprocess.run([str(binary)], check=True)
