# SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
#
# SPDX-License-Identifier: Apache-2.0

"""Regenerates the vectors in this directory from implementations independent
of the Rust crates under test: cryptography 50.0.1 (OpenSSL) for X25519 and
Ed25519, blake3 1.0.9 for BLAKE3, kyber-py 1.2.0 for ML-KEM-768, PyNaCl 1.6.2
(libsodium) for XChaCha20-Poly1305 and the Python standard library for
HKDF-SHA512 and HMAC-SHA512.

kyber-py is a pure-Python FIPS 203 implementation and PyNaCl's AEAD is not
otherwise exercised here; before either is trusted it is checked against the
ACVP and Wycheproof vectors that quietwire-crypto pins.

    pip install cryptography==50.0.1 blake3==1.0.9 kyber-py==1.2.0 pynacl==1.6.2
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
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt as xchacha_seal
from nacl.exceptions import CryptoError

HERE = Path(__file__).parent
CRYPTO_FIXTURES = HERE / "../../../../quietwire-crypto/tests/fixtures"
ACVP = CRYPTO_FIXTURES / "acvp"
WYCHEPROOF_XCHACHA = CRYPTO_FIXTURES / "wycheproof/xchacha20_poly1305_test.json"
TRANSCRIPT_CONTEXT = "QUIETWIRE-X3DH-TRANSCRIPT-v1"
HYBRID_INFO = b"QUIETWIRE-X3DH-HYBRID-v1"
CURVE25519_PREFIX = b"\xff" * 32
ROOT_INFO = b"QUIETWIRE-ROOT-v1"
PLAINTEXT_LEN = 396


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


def check_pynacl_against_wycheproof() -> None:
    for group in json.loads(WYCHEPROOF_XCHACHA.read_text())["testGroups"]:
        for test in group["tests"]:
            key, nonce = bytes.fromhex(test["key"]), bytes.fromhex(test["iv"])
            if len(key) != 32 or len(nonce) != 24:
                continue
            aad, message = bytes.fromhex(test["aad"]), bytes.fromhex(test["msg"])
            sealed = (test["ct"] + test["tag"]).lower()
            try:
                matches = xchacha_seal(message, aad, nonce, key).hex() == sealed
            except CryptoError:
                matches = False
            assert matches == (test["result"] != "invalid"), test["tcId"]


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


def kdf_root(root_key: bytes, own: bytes, remote: bytes) -> tuple:
    out = hkdf_sha512(x25519(own, remote), root_key, ROOT_INFO, 64)
    return out[:32], out[32:]


def kdf_chain(chain_key: bytes) -> tuple:
    def derive(constant: int) -> bytes:
        return hmac.new(chain_key, bytes([constant]), hashlib.sha512).digest()[:32]

    return derive(0x01), derive(0x02)


class RatchetParty:
    """The Double Ratchet of plan §5.4, written from the plan alone: every
    chain is kept as its full list of message keys, so skipped keys need no
    bookkeeping of their own."""

    def __init__(self, root_key: bytes, own_ratchet: bytes, ratchet_labels: list):
        self.root_key = root_key
        self.own_ratchet = own_ratchet
        self.ratchet_labels = ratchet_labels
        self.remote_ratchet = None
        self.sending = None
        self.previous_sending_len = 0
        self.receiving = {}
        self.used = set()

    def start_sending(self, remote: bytes) -> None:
        self.root_key, chain_key = kdf_root(self.root_key, self.own_ratchet, remote)
        self.sending = [chain_key, 0]
        self.remote_ratchet = remote

    def encrypt(self, nonce: bytes, plaintext: bytes) -> bytes:
        chain_key, number = self.sending
        message_key, self.sending[0] = kdf_chain(chain_key)
        self.sending[1] += 1
        header = (
            x25519_public(self.own_ratchet)
            + self.previous_sending_len.to_bytes(4, "little")
            + number.to_bytes(4, "little")
        )
        return header + xchacha_seal(plaintext, header, nonce, message_key)

    def decrypt(self, nonce: bytes, frame: bytes) -> bytes:
        header, sealed = frame[:40], frame[40:]
        ratchet = header[:32]
        number = int.from_bytes(header[36:40], "little")
        if ratchet not in self.receiving:
            self.ratchet_step(ratchet)
        message_key = self.message_key(ratchet, number)
        assert (ratchet, number) not in self.used
        self.used.add((ratchet, number))
        return crypto_aead_xchacha20poly1305_ietf_decrypt(sealed, header, nonce, message_key)

    def ratchet_step(self, remote: bytes) -> None:
        self.root_key, chain_key = kdf_root(self.root_key, self.own_ratchet, remote)
        self.receiving[remote] = [chain_key]
        self.previous_sending_len = self.sending[1] if self.sending else 0
        self.own_ratchet = secret(self.ratchet_labels.pop(0))
        self.start_sending(remote)

    def message_key(self, ratchet: bytes, number: int) -> bytes:
        chain = self.receiving[ratchet]
        while len(chain) <= number + 1:
            message_key, next_chain_key = kdf_chain(chain.pop())
            chain += [message_key, next_chain_key]
        return chain[number]


def ratchet_case() -> dict:
    """Alice (the X3DH initiator) and Bob exchange frames out of order across
    three DH ratchet steps; a3 is held back until Bob has moved on to Alice's
    second chain, so it is served from the keys skipped in her first."""
    shared_key = secret("ratchet shared key")
    initiator_labels = ["ratchet alice ratchet %d" % i for i in range(3)]
    responder_labels = ["ratchet bob signed prekey"] + ["ratchet bob ratchet %d" % i for i in range(1, 3)]
    alice = RatchetParty(shared_key, secret(initiator_labels[0]), initiator_labels[1:])
    bob = RatchetParty(shared_key, secret(responder_labels[0]), responder_labels[1:])
    alice.start_sending(x25519_public(bob.own_ratchet))
    parties = {"initiator": alice, "responder": bob}

    messages, steps = {}, []

    def send(sender: str, name: str) -> None:
        nonce = secret("ratchet nonce " + name)[:24]
        plaintext = hashlib.shake_256(b"QUIETWIRE test vector plaintext " + name.encode()).digest(PLAINTEXT_LEN)
        frame = parties[sender].encrypt(nonce, plaintext)
        messages[name] = {"sender": sender, "nonce": nonce.hex(), "plaintext": plaintext.hex(), "frame": frame.hex()}
        steps.append({"send": name})

    def receive(receiver: str, name: str) -> None:
        message = messages[name]
        assert message["sender"] != receiver
        opened = parties[receiver].decrypt(bytes.fromhex(message["nonce"]), bytes.fromhex(message["frame"]))
        assert opened.hex() == message["plaintext"], name
        steps.append({"receive": name})

    for name in ["a0", "a1", "a2", "a3"]:
        send("initiator", name)
    for name in ["a0", "a2", "a1"]:
        receive("responder", name)
    for name in ["b0", "b1"]:
        send("responder", name)
    for name in ["b1", "b0"]:
        receive("initiator", name)
    send("initiator", "a4")
    receive("responder", "a4")
    receive("responder", "a3")
    send("responder", "b2")
    receive("initiator", "b2")

    return {
        "shared_key": shared_key.hex(),
        "initiator_ratchet_keys": [secret(label).hex() for label in initiator_labels],
        "responder_ratchet_keys": [secret(label).hex() for label in responder_labels],
        "messages": [{"name": name, **message} for name, message in messages.items()],
        "steps": steps,
    }


def write(name: str, value) -> None:
    (HERE / name).write_text(json.dumps(value, indent=2) + "\n")


if __name__ == "__main__":
    check_kyber_py_against_acvp()
    check_pynacl_against_wycheproof()
    write(
        "x3dh.json",
        [
            x3dh_case("with one-time prekey", True),
            x3dh_case("without one-time prekey", False),
        ],
    )
    write("ratchet.json", ratchet_case())
