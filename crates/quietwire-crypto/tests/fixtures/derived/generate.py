# SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
#
# SPDX-License-Identifier: Apache-2.0

"""Regenerates the vectors in this directory from implementations independent
of the Rust crates under test: the Python standard library for HKDF-SHA512 and
argon2-cffi 25.1.0 (the reference C implementation) for Argon2id.

    pip install argon2-cffi==25.1.0
    python generate.py
"""

import hashlib
import hmac
import json
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw

HERE = Path(__file__).parent
ARGON2_VERSION_1_3 = 0x13
SUBKEY_LABEL = b"QUIETWIRE-DEK-v1"
PURPOSES = ["db", "field", "identity", "sessions", "meta"]


def hkdf_sha512(ikm: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(b"\0" * hashlib.sha512().digest_size, ikm, hashlib.sha512).digest()
    block, okm, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha512).digest()
        okm += block
        counter += 1
    return okm[:length]


def argon2id_case(password: bytes, salt: bytes, memory_kib: int, iterations: int, parallelism: int) -> dict:
    tag = hash_secret_raw(
        password, salt, iterations, memory_kib, parallelism, 32, Type.ID, ARGON2_VERSION_1_3
    )
    return {
        "password": password.hex(),
        "salt": salt.hex(),
        "memory_kib": memory_kib,
        "iterations": iterations,
        "parallelism": parallelism,
        "tag": tag.hex(),
    }


def argon2id_kek() -> list:
    return [
        argon2id_case(b"correct horse battery staple", bytes(range(32)), 256, 4, 2),
        argon2id_case(b"", b"\xaa" * 32, 64, 1, 1),
        argon2id_case(bytes(range(256)), bytes(range(32, 64)), 512, 3, 4),
    ]


def dek_subkeys() -> dict:
    dek = bytes(range(32))
    return {
        "dek": dek.hex(),
        "subkeys": {p: hkdf_sha512(dek, SUBKEY_LABEL + p.encode(), 32).hex() for p in PURPOSES},
    }


def write(name: str, value) -> None:
    (HERE / name).write_text(json.dumps(value, indent=2) + "\n")


if __name__ == "__main__":
    write("argon2id_kek.json", argon2id_kek())
    write("dek_subkeys.json", dek_subkeys())
