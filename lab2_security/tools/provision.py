#!/usr/bin/env python3
"""Create a matched pair of Ed25519 identities; never print private keys."""
import argparse
import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--replace', action='store_true', help='Rotate both identities; both boards must be rebuilt/reflashed')
    args = parser.parse_args()
    paths = [ROOT / f'LoRa_Encrypted_{role}_Zephyr/src/identity.h' for role in ('Client', 'Server')]
    if any(path.exists() for path in paths) and not args.replace:
        parser.error('Identity file already exists. Keep it, or explicitly rotate BOTH using --replace.')
    seeds = [os.urandom(32), os.urandom(32)]
    public = [Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
              for seed in seeds]
    pair = os.urandom(8)
    for i, path in enumerate(paths):
        fields = dict(pair_id=pair, public_key=public[i], private_key=seeds[i], peer_public_key=public[1-i])
        text = '/* Generated local credentials. DO NOT COMMIT. */\n#include "security_protocol.h"\n'
        text += 'static const struct proto_identity board_identity = {\n'
        for name, value in fields.items():
            text += f'    .{name} = {{' + ', '.join(f'0x{b:02x}' for b in value) + '},\n'
        text += '};\n'
        # Restrict permissions before writing any private material.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w') as output:
            output.write(text)
    print(f'Provisioned client/server identities for public pair ID {pair.hex()}.')
    print('Build both roles from this same pair. Private seeds remain in ignored identity.h files.')


if __name__ == '__main__':
    main()
