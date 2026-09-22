# SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
#
# SPDX-License-Identifier: Apache-2.0

"""Regenerates the vectors in this directory from implementations independent
of the Rust crates under test: cryptography 50.0.1 (OpenSSL) for X25519 and
Ed25519, blake3 1.0.9 for BLAKE3, kyber-py 1.2.0 for ML-KEM-768 and the Python
standard library for HKDF-SHA512.

kyber-py is a pure-Python FIPS 203 implementation; before it is trusted here it
is checked against the ACVP vectors that quietwire-crypto pins.

    pip install cryptography==50.0.1 blake3==1.0.9 kyber-py==1.2.0
    python generate.py
"""

import hashlib
import hmac
import json
from pathlib import Path

from blake3 import blake3
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from kyber_py.ml_kem import ML_KEM_768

HERE = Path(__file__).parent
ACVP = HERE / "../../../../quietwire-crypto/tests/fixtures/acvp"
TRANSCRIPT_CONTEXT = "QUIETWIRE-X3DH-TRANSCRIPT-v1"
HYBRID_INFO = b"QUIETWIRE-X3DH-HYBRID-v1"
CURVE25519_PREFIX = b"\xff" * 32


def hkdf_sha512(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha512).digest()
    block, okm, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha512).digest()
        okm += block
        counter += 1
    return okm[:length]


def acvp_ml_kem_768(name: str, function: str) -> list:
    groups = json.loads((ACVP / name).read_text())["testGroups"]
    return [
        test
        for group in groups
        if group["parameterSet"] == "ML-KEM-768" and group.get("function", "") == function
        for test in group["tests"]
    ]


def check_kyber_py_against_acvp() -> None:
    for test in acvp_ml_kem_768("ml_kem_key_gen.json", ""):
        ek, dk = ML_KEM_768._keygen_internal(bytes.fromhex(test["d"]), bytes.fromhex(test["z"]))
        assert (ek.hex(), dk.hex()) == (test["ek"].lower(), test["dk"].lower()), test["tcId"]
    for test in acvp_ml_kem_768("ml_kem_encap_decap.json", "encapsulation"):
        shared, ciphertext = ML_KEM_768._encaps_internal(
            bytes.fromhex(test["ek"]), bytes.fromhex(test["m"])
        )
        assert (shared.hex(), ciphertext.hex()) == (test["k"].lower(), test["c"].lower()), test["tcId"]


def secret(label: str) -> bytes:
    return hashlib.sha256(b"QUIETWIRE test vector " + label.encode()).digest()


def x25519_public(private: bytes) -> bytes:
    key = X25519PrivateKey.from_private_bytes(private).public_key()
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def x25519(private: bytes, public: bytes) -> bytes:
    peer = X25519PublicKey.from_public_bytes(public)
    return X25519PrivateKey.from_private_bytes(private).exchange(peer)


def ed25519_public(seed: bytes) -> bytes:
    key = Ed25519PrivateKey.from_private_bytes(seed).public_key()
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def identity(party: str) -> dict:
    kem_d, kem_z = secret(party + " kem d"), secret(party + " kem z")
    dh_private = secret(party + " identity dh")
    return {
        "sign_public": ed25519_public(secret(party + " identity sign")),
        "dh_private": dh_private,
        "dh_public": x25519_public(dh_private),
        "kem_d": kem_d,
        "kem_z": kem_z,
        "kem_public": ML_KEM_768._keygen_internal(kem_d, kem_z)[0],
    }


def public_identity(keys: dict) -> bytes:
    return keys["sign_public"] + keys["dh_public"] + keys["kem_public"]


def x3dh_case(name: str, with_one_time_prekey: bool) -> dict:
    alice, bob = identity(name + " alice"), identity(name + " bob")
    signed_prekey = secret(name + " bob signed prekey")
    one_time_prekey = secret(name + " bob one-time prekey") if with_one_time_prekey else None
    ephemeral = secret(name + " alice ephemeral")
    kem_randomness = secret(name + " alice kem randomness")
    kem_shared, kem_ciphertext = ML_KEM_768._encaps_internal(bob["kem_public"], kem_randomness)

    spk_public = x25519_public(signed_prekey)
    opk_public = x25519_public(one_time_prekey) if one_time_prekey else b""
    ephemeral_public = x25519_public(ephemeral)
    agreements = [
        x25519(alice["dh_private"], spk_public),
        x25519(ephemeral, bob["dh_public"]),
        x25519(ephemeral, spk_public),
    ]
    if one_time_prekey:
        agreements.append(x25519(ephemeral, opk_public))
    transcript = blake3(
        public_identity(alice)
        + public_identity(bob)
        + ephemeral_public
        + spk_public
        + opk_public
        + kem_ciphertext,
        derive_key_context=TRANSCRIPT_CONTEXT,
    ).digest()
    ikm = CURVE25519_PREFIX + b"".join(agreements) + kem_shared

    return {
        "name": name,
        "initiator": hex_fields(alice),
        "responder": hex_fields(bob),
        "signed_prekey_private": signed_prekey.hex(),
        "signed_prekey_public": spk_public.hex(),
        "one_time_prekey_private": one_time_prekey.hex() if one_time_prekey else None,
        "one_time_prekey_public": opk_public.hex() if one_time_prekey else None,
        "ephemeral_private": ephemeral.hex(),
        "ephemeral_public": ephemeral_public.hex(),
        "kem_ciphertext": kem_ciphertext.hex(),
        "kem_shared": kem_shared.hex(),
        "transcript": transcript.hex(),
        "shared_key": hkdf_sha512(ikm, transcript, HYBRID_INFO, 32).hex(),
    }


def hex_fields(keys: dict) -> dict:
    return {field: value.hex() for field, value in keys.items()}


def write(name: str, value) -> None:
    (HERE / name).write_text(json.dumps(value, indent=2) + "\n")


if __name__ == "__main__":
    check_kyber_py_against_acvp()
    write(
        "x3dh.json",
        [
            x3dh_case("with one-time prekey", True),
            x3dh_case("without one-time prekey", False),
        ],
    )
