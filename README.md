<!--
SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>

SPDX-License-Identifier: CC-BY-4.0
-->

# QUIETWIRE

**An infrastructure-free, end-to-end encrypted, delay-tolerant messaging system.**

No internet. No phone lines. No servers. No accounts. No recovery.
Messages travel across whatever physical medium is available — Bluetooth LE, Wi-Fi Direct, LoRa radio, USB sticks, printed QR codes — hopping through any devices that happen to be in range. Intermediate devices cannot read the message, cannot identify the sender, cannot identify the recipient, and cannot tell a real packet from a decoy.

Everything in the codebase — identifiers, comments, commit messages, UI strings, documentation — is written in English.

---

## Table of contents

1. [Scope and honest promises](#1-scope-and-honest-promises)
2. [Threat model](#2-threat-model)
3. [Technology decisions (the short version)](#3-technology-decisions-the-short-version)
4. [System architecture](#4-system-architecture)
5. [Cryptographic specification](#5-cryptographic-specification)
6. [Wire format](#6-wire-format)
7. [Transport layer specification](#7-transport-layer-specification)
8. [Routing specification](#8-routing-specification)
9. [Traffic analysis resistance](#9-traffic-analysis-resistance)
10. [Local storage specification](#10-local-storage-specification)
11. [Authentication, duress and panic](#11-authentication-duress-and-panic)
12. [User interface specification](#12-user-interface-specification)
13. [Repository layout](#13-repository-layout)
14. [Step-by-step build plan](#14-step-by-step-build-plan)
15. [Hardware bill of materials](#15-hardware-bill-of-materials)
16. [Budget](#16-budget)
17. [Testing and verification](#17-testing-and-verification)
18. [Security audit programme](#18-security-audit-programme)
19. [Governance, licence and lifecycle](#19-governance-licence-and-lifecycle)
20. [Legal and regulatory](#20-legal-and-regulatory)
21. [Decisions deliberately rejected](#21-decisions-deliberately-rejected)
22. [Appendix A — First design review log](#appendix-a--first-design-review-log)
23. [Appendix B — Second design review log](#appendix-b--second-design-review-log)
24. [Appendix C — Full linear read](#appendix-c--full-linear-read)

---

## 1. Scope and honest promises

### What QUIETWIRE guarantees

| Requirement | Status |
|---|---|
| Only endpoint B can decrypt a message sent by endpoint A | **Guaranteed by construction** |
| Relay nodes learn nothing (not sender, not recipient, not size, not content) | **Guaranteed by construction** |
| Works with no internet and no cellular network | **Guaranteed** — and in the `airgap` build, structurally: no `INTERNET` permission exists in the manifest (§7.4) |
| Works on Android, iOS, Windows, macOS, Linux, Raspberry Pi | **Guaranteed** |
| Any device can act as a relay | **Guaranteed** |
| Local message store encrypted at rest | **Guaranteed** |
| Password required to read *and* to send | **Guaranteed** |
| Unlimited distance, including intercontinental | **Guaranteed, with variable latency** |
| Least-cost, most-efficient path selection | **Guaranteed, probabilistically** |
| Simple interface usable by non-technical people | **Guaranteed — three screens in daily use**, plus a four-step first-run setup (§12) |

### The one thing that is physically impossible

Radio waves do not bend around the planet at 2.4 GHz. There is no software that can make a Bluetooth packet reach another continent in real time without infrastructure. Any system claiming otherwise is lying.

QUIETWIRE solves this the only way it can be solved: it is a **Delay-Tolerant Network (DTN)**. A message is a sealed object that survives disconnection. It waits, cached and encrypted, inside relay devices until an onward opportunity appears.

**Expected latency by medium:**

| Medium | Range per hop | Typical end-to-end latency |
|---|---|---|
| Wi-Fi Direct | 50–200 m | < 2 seconds |
| Bluetooth LE | 10–100 m | 2–30 seconds |
| LoRa (868/915 MHz) | 2–15 km line of sight | 30 seconds – 10 minutes |
| LoRa multi-hop city mesh | city-wide | 5–60 minutes |
| Cross-border via travelling carrier | unlimited | hours to days |
| Printed QR / postal mail | unlimited | days to weeks |

This is not a weakness. It is the correct design for a network with no infrastructure. The product promise is **"it always arrives"**, not "it arrives instantly".

---

## 2. Threat model

### Adversaries QUIETWIRE defends against

| # | Adversary | Capability | Defence |
|---|---|---|---|
| A1 | Passive relay | Runs a node, stores everything it relays | Payload is E2E encrypted; relay has no key |
| A2 | Active relay | Modifies, drops, replays, injects cells | AEAD authentication; **ratchet message numbers** as the replay defence (the 24 h relay cache is only an airtime optimisation, §8.5) |
| A3 | **Regional** passive observer | Records all radio traffic across a city or region | Fixed-size cells, cover traffic, random delay, per-message tags, no plaintext addressing |
| A4 | Sybil attacker | Floods the mesh with fake nodes | **The 8-copy bound is the real defence** — a swarm cannot amplify traffic, only absorb it. Proof-of-relay reputation reduces waste but resets with the daily pseudonym (§8.6) |
| A5 | Device seizure, powered off or locked | Takes the device and images it | Argon2id + XChaCha20 full-store encryption; the DEK is zeroized on lock (§11.2), so a locked device holds no usable key material in RAM either |
| A6 | Coercion | Forces the owner to unlock | Duress password opens a decoy store; wipe-on-fail counter |
| A7 | Future adversary | Records now, decrypts later with a quantum computer | Hybrid X25519 + ML-KEM-768 key agreement |
| A8 | Endpoint impersonation | Man-in-the-middle during contact exchange | In-person QR exchange + out-of-band safety-number verification |

### Adversaries QUIETWIRE does NOT defend against

- **A malicious or compromised endpoint device.** If B's phone has a keylogger, nothing helps. Out of scope.
- **Rubber-hose cryptanalysis beyond the duress mechanism.** The duress store is deniability, not invulnerability.
- **Radio direction finding of the physical device.** If an adversary can triangulate a transmitter, encryption is irrelevant to their goal. Mitigation is operational (low power, short transmissions, mobility), not cryptographic.
- **Denial of service by jamming.** Physics wins. Mitigation is medium diversity: if 2.4 GHz is jammed, LoRa and sneakernet still work.
- **A truly global observer with unlimited retention.** An adversary who simultaneously records every radio in the mesh and runs intersection attacks over months is not defeated, and §9 says so. A3 above is the regional version, which is defeated. Listing only the regional adversary as in-scope would have implied a guarantee the system does not provide.
- **Traffic confirmation against an already-suspected pair.** An adversary who suspects that A talks to B, and can observe both, can often confirm it by correlation. Anonymity systems with far more cover traffic than this one fail the same test.

---

## 3. Technology decisions (the short version)

| Layer | **Chosen** | Why | Rejected |
|---|---|---|---|
| Security core | **Rust**, edition 2021, **exact pinned toolchain in `rust-toolchain.toml`** | Memory safety without GC, no runtime, compiles to every target including iOS/Android/embedded, mature audited crypto crates, constant-time primitives. **The toolchain is pinned exactly, not floored.** An MSRV is a compatibility promise to downstream users, which this project does not have; a pinned toolchain is a reproducibility requirement, which it does. The pin advances deliberately, reviewed quarterly, and every advance is an ADR because it changes the reproducible-build baseline | C/C++ (memory bugs), Go (GC pauses + weaker mobile story), Python (unsuitable for a security core) |
| Cross-language bindings | **UniFFI 0.28** (Mozilla) | One Rust core → generated Kotlin, Swift and Python bindings; keeps a single auditable implementation | Hand-written JNI/FFI (error-prone), separate implementations per platform (disaster) |
| Android app | **Kotlin + Jetpack Compose** | First-class BLE/Wi-Fi Direct access, StrongBox keystore, background service support | Flutter (poor low-level BLE), React Native (no) |
| iOS app | **Swift + SwiftUI**, version pinned in `.swift-version` and the Xcode project, never in prose | Only viable route to Core Bluetooth, Secure Enclave, background BLE modes | Anything cross-platform |
| Desktop app | **Tauri 2.x** (Rust backend + Svelte 5 frontend) | Uses the exact same Rust core as a native library; ships Windows/macOS/Linux from one codebase; ~8 MB binaries; no Node runtime shipped | Electron (bloat, Node in the trust boundary), Qt (licensing + FFI friction) |
| "Web app" | **Local-only web UI served by the desktop node at `127.0.0.1`** | Satisfies the web-interface requirement without putting keys in a browser | A public web app — see §21 |
| Network / routing layer | **Reticulum Network Stack** (`reticulum-rs`) + **QUIETWIRE Opportunistic DTN** (encounter-utility, §8.2) | Reticulum is a proven, field-tested, infrastructure-free stack with LoRa/packet-radio/serial interfaces and an existing user base. We use it as the wide-area layer and add our own store-carry-forward layer for short-range encounters it does not cover | Building a whole network stack from zero (2+ years), libp2p (assumes IP) |
| End-to-end crypto | **Double Ratchet + hybrid PQ X3DH**, implemented against the Signal specification, using `vodozemac` (Apache-2.0, audited by Least Authority) as the reference for ratchet construction and primitive usage | Signal-grade forward secrecy and post-compromise security, stronger than Reticulum's native E2E. "`vodozemac`-style" in an earlier draft was too vague to be a decision: we take its audited primitive usage and ratchet structure, and write our own session layer because we need the hybrid PQ handshake and the tag scheme it does not provide | Rolling our own primitives (never), PGP (no forward secrecy), Reticulum-only E2E (no ratcheting), `libsignal` (AGPL, incompatible with the licence in §19) |
| Link crypto | **Noise Protocol Framework, `XX` handshake** (`snow` crate) | Formally analysed, gives hop-to-hop confidentiality so relays cannot even see that an E2E packet exists | TLS (needs PKI and certificates) |
| Local database | **SQLite 3 via `rusqlite`, with SQLCipher page encryption + per-field XChaCha20-Poly1305** | Two independent layers; even the schema and indices leak nothing | Plain SQLite (leaks), Realm (proprietary), flat files (no queries) |
| Password KDF | **Argon2id**, m=256 MiB, t=4, p=2 (desktop m=1 GiB) | OWASP-recommended, memory-hard, GPU/ASIC resistant | PBKDF2, bcrypt, scrypt (all weaker here) |
| Symmetric AEAD | **XChaCha20-Poly1305** (`chacha20poly1305` crate) | 192-bit nonce means random nonces are safe forever; fast without AES-NI (critical on cheap ARM) | AES-GCM (nonce reuse is catastrophic, needs hardware) |
| Signatures | **Ed25519** (`ed25519-dalek` v2) | Fast, small, deterministic, no nonce risk | ECDSA (nonce fragility) |
| Key agreement | **X25519 + ML-KEM-768 hybrid** (`x25519-dalek` + `ml-kem`) | Classical security today, harvest-now-decrypt-later resistance tomorrow | X25519 alone |
| Hash / KDF | **BLAKE3** + **HKDF-SHA512** | BLAKE3 for speed and tree hashing; HKDF-SHA512 for standardized key derivation | SHA-1, MD5 (obviously) |
| Erasure coding for QR/sneakernet | **RaptorQ** (`raptorq` crate, RFC 6330) | Fountain code: a scanner recovers the payload from any sufficient subset of frames, no frame ordering needed | Static QR chunking (fails on a single missed frame) |
| Build reproducibility | **Nix flakes** + `cargo-auditable` + SLSA provenance | Anyone can verify the published binary matches the published source | Trusting CI blindly |
| Prototyping / node daemon tooling | **Python 3.12** | Only for the lab bench, simulation harness and Raspberry Pi provisioning scripts. Never in the security path | Python in the core |

---

## 4. System architecture

```
┌─────────────────────────────────────────────────────────────┐
│  L5  PRESENTATION                                            │
│      Android (Compose) · iOS (SwiftUI) · Tauri desktop       │
│      · localhost web UI                                      │
├─────────────────────────────────────────────────────────────┤
│  L4a BINDINGS                    [Rust · quietwire-ffi]      │
│      UniFFI → Kotlin · Swift · Python. The trust boundary:   │
│      nothing above this line holds a secret                  │
├─────────────────────────────────────────────────────────────┤
│  L4b APPLICATION CORE            [Rust · quietwire-core]     │
│      Contacts · conversations · fragmentation · reassembly   │
│      · delivery receipts · duress logic                      │
├─────────────────────────────────────────────────────────────┤
│  L3b END-TO-END SECURITY         [Rust · quietwire-e2e]      │
│      Hybrid PQ X3DH · Double Ratchet · per-message tags      │
├─────────────────────────────────────────────────────────────┤
│  L3a PRIMITIVES & KEY HIERARCHY  [Rust · quietwire-crypto]   │
│      X25519 · Ed25519 · ML-KEM-768 · XChaCha20 · Argon2id    │
│      · BLAKE3 · zeroization · constant-time helpers          │
├─────────────────────────────────────────────────────────────┤
│  L2  PACKET & PRIVACY            [Rust · quietwire-packet]   │
│      Fixed 512 B cells · padding · cover traffic             │
│      · random delay · replay cache                           │
├─────────────────────────────────────────────────────────────┤
│  L1  ROUTING                     [Rust · quietwire-route]    │
│      Binary Spray-and-Wait · encounter utility               │
│      · GCS digests · TTL/copy budgets                        │
├─────────────────────────────────────────────────────────────┤
│  L0  TRANSPORT ADAPTERS          [Rust · quietwire-transport]│
│      BLE · Wi-Fi Direct · LoRa/RNode · Reticulum            │
│      · Sneakernet · QR · NFC                                 │
├─────────────────────────────────────────────────────────────┤
│  L-1 STORAGE                     [Rust · quietwire-store]    │
│      SQLCipher + field-level AEAD · key hierarchy            │
│      · secure erase                                          │
└─────────────────────────────────────────────────────────────┘
```

**Single source of truth.** L-1 through L4b are one Rust workspace compiled once per target architecture. The platform apps are thin: they render state and forward user intent. No security logic exists above L4b. This is what makes a single audit meaningful.

---

## 5. Cryptographic specification

### 5.1 Identity

Every installation generates, at first launch, using the operating system CSPRNG:

```
IK_sign   Ed25519 keypair          long-term signing identity
IK_dh     X25519 keypair           long-term Diffie-Hellman identity
PQ_kem    ML-KEM-768 keypair       post-quantum identity
SPK       X25519 keypair           signed prekey, rotated every 7 days
OPK[0..99] X25519 keypairs         one-time prekeys, burned on publication
```

**Correction of a common misconception:** these keys are **not** generated inside a hardware secure element. Apple's Secure Enclave supports only NIST P-256; Android StrongBox supports only the algorithms in its attestation profile. Neither can generate or hold X25519, Ed25519 or ML-KEM keys. Hardware is therefore used exactly one way in QUIETWIRE: to *wrap* the already-encrypted key blob for fast unlock (§5.7). Any claim that identity keys "live in the Secure Enclave" would be false, and the app must not make it.

**One-time prekey semantics.** There is no server holding a prekey pool. An OPK is consumed when it is *published*, not when it is used: each time the device renders its contact QR it burns one `OPK`, marks it used, and never offers it again. The pool of 100 is therefore a budget of 100 contact-QR displays between refills; the app regenerates the pool in the background whenever fewer than 20 remain. If the pool is empty and cannot be refilled, the bundle omits the OPK, `DH4` is skipped, and the app shows a one-line notice that this contact exchange has slightly weaker deniability. It never silently degrades.

The **QUIETWIRE Address** is the device's own fingerprint from §5.2 — `fp(self)`, the same derivation, truncated to **160 bits** and displayed as 8 groups of 4 base32 characters (32 characters; 5 bits each). An earlier draft specified 128 bits *and* 8 groups of 4, which is 160 bits of display for 128 bits of value — the two never matched, and it defined a second identifier derivation for no reason. One derivation, used twice: the full 240-bit form is the safety number, the truncated form is the Address.

The Address is a **display-only convenience** shown in the Advanced screen so a user can read their identity aloud or write it down. It is never used for routing, never used for addressing, and never transmitted in the clear — nothing in the protocol consumes it. Contacts are keyed internally by a random 16-byte row id unrelated to any key material (§10.2).

### 5.2 Contact establishment

Contacts are added **in person, by QR code**. There is no directory, no lookup, no server.

The QR encodes a *prekey bundle*: `IK_sign_pub`, `IK_dh_pub`, `PQ_kem_pub`, current `SPK_pub`, one `OPK_pub`, a signature over all of it by `IK_sign`, and a 32-bit CRC.

**Remote enrollment** (when in-person is impossible) uses a bundle relayed through the mesh, followed by **mandatory safety-number verification**.

The safety number must be **order-independent**, or the two devices compute different values and the feature is worse than useless. It is therefore defined over a canonical ordering:

```
fp(X)  = BLAKE3_derive_key("QUIETWIRE-FINGERPRINT-v1",
                           IK_sign_pub_X || IK_dh_pub_X || PQ_kem_pub_X)[0..30]
(lo, hi) = the two fingerprints sorted lexicographically as byte strings
SN     = decimal_digits(fp_to_int(lo), 30) || decimal_digits(fp_to_int(hi), 30)
```

Both parties see the same 60 digits, shown as 12 groups of 5, and confirm them over an independent channel (voice call, in person, a letter). The number commits to **all three** identity keys, so substituting only the post-quantum key is detected. Until confirmed, the conversation is marked **UNVERIFIED** with a persistent amber banner and every message bubble carries a small amber dot.

### 5.3 Session establishment — Hybrid PQ X3DH

```
DH1 = X25519(IK_A_priv,  SPK_B_pub)
DH2 = X25519(EK_A_priv,  IK_B_pub)
DH3 = X25519(EK_A_priv,  SPK_B_pub)
DH4 = X25519(EK_A_priv,  OPK_B_pub)        # omitted if no OPK available
(SS_pq, CT_pq) = ML-KEM-768.Encapsulate(PQ_kem_B_pub)

transcript = BLAKE3_derive_key("QUIETWIRE-X3DH-TRANSCRIPT-v1",
        IK_A_sign_pub || IK_A_dh_pub || PQ_kem_A_pub ||
        IK_B_sign_pub || IK_B_dh_pub || PQ_kem_B_pub ||
        EK_A_pub || SPK_B_pub || OPK_B_pub_or_empty || CT_pq)

SK = HKDF-SHA512(
        ikm  = 0xFF * 32 || DH1 || DH2 || DH3 || DH4 || SS_pq,
        salt = transcript,
        info = "QUIETWIRE-X3DH-HYBRID-v1"
     )[0..32]
```

Three details that are easy to get wrong and are therefore normative:

- **The transcript is the HKDF salt, not decoration.** It binds both identities, the ephemeral key, the prekeys actually used and the KEM ciphertext into the derived key. Without it the hybrid construction is not a sound KEM combiner and the handshake is exposed to unknown-key-share and key-substitution attacks. An implementation that omits `CT_pq` from the transcript is broken even though it will interoperate with itself.
- **The 32 leading `0xFF` bytes** replicate the Curve25519 domain-separation prefix from the Signal X3DH specification, preventing cross-protocol collisions with other uses of the same curve.
- **`OPK_B_pub_or_empty`** is the empty string when no one-time prekey was available, and the fact of its absence is therefore bound into the key. An attacker cannot strip the OPK undetected.

`EK_A` is an ephemeral X25519 keypair, zeroized immediately after `SK` is derived. `CT_pq` travels in the first message header. Classical security holds if X25519 is unbroken; quantum resistance holds if ML-KEM-768 is unbroken. Breaking the session requires breaking **both**.

### 5.4 Message encryption — Double Ratchet

Standard Signal Double Ratchet, with:

- **Root chain**: `out = HKDF-SHA512(ikm = X25519(DH_self, DH_remote), salt = RK, info = "QUIETWIRE-ROOT-v1")`, 64 bytes, split as `RK' = out[0..32]`, `CK' = out[32..64]`. The old root key is the salt and the new DH output is the input keying material — the reverse order is a real and frequently-made implementation bug, so the argument names are written out here rather than positionally
- **Symmetric chain**: `MK = HMAC-SHA512(key = CK, message = 0x01)[0..32]`, `CK' = HMAC-SHA512(key = CK, message = 0x02)[0..32]`. Argument names are written out for the same reason as the root chain above — `HMAC(a, b)` is ambiguous about which is the key, and getting it backwards produces a scheme that works, interoperates with itself, and is wrong
- **Message encryption**: `XChaCha20-Poly1305(MK, nonce_24_random, plaintext, aad = ratchet_header)`
- **Skipped keys**: up to 1 000 retained per chain, 10 000 total, evicted oldest-first. Necessary because a DTN reorders messages routinely.
- **Chain limit**: after 2 000 messages without a DH ratchet, sending is blocked until the peer responds. Prevents unbounded key material.

**Guarantees achieved:** forward secrecy (a compromised device cannot decrypt past messages), post-compromise security (the session self-heals after one round trip), and break-in recovery.

### 5.5 Sealed sender and per-message tags

A packet carries **no recipient address and no sender address**. It carries a 16-byte tag.

A naive design derives one tag per session per hour. **That design is broken, and the reason is worth stating because it is the kind of flaw that survives into shipped products:** if both parties derive the same tag, then two devices emitting the same 16 bytes in the same hour are visibly talking to each other, and every cell of a conversation within that hour carries an identical marker that lets an observer count the messages. The tag must therefore be both **directional** and **per-message**.

```
dir        = 0x00 for initiator→responder, 0x01 for responder→initiator
epoch      = floor(unix_seconds / 3600)                    # 1-hour window
tag_secret = HKDF-SHA512(ikm = SK_session, salt = "",
                         info = "QUIETWIRE-TAG-v1" || dir)[0..32]
tag[i]     = BLAKE3_keyed(tag_secret, LE64(epoch) || LE32(i))[0..16]
```

`i` is a per-direction counter that advances with every cell sent, including cover traffic and fragments. Every cell on the wire therefore carries a tag that has never appeared before and will never appear again.

**The tag secret ratchets too.** Deriving `tag_secret` from `SK_session` alone would leave it fixed for the life of the session, so anyone who ever compromised the device could recompute every tag it had ever emitted and retroactively link months of captured traffic to this one contact — defeating unlinkability *backwards*, which forward secrecy otherwise prevents for content. The secret is therefore advanced once per epoch and the old value destroyed:

```
tag_secret[e0] = HKDF-SHA512(ikm = SK_session, salt = "",
                             info = "QUIETWIRE-TAG-v1" || dir)[0..32]
tag_secret[e]  = BLAKE3_derive_key("QUIETWIRE-TAG-RATCHET-v1",
                                   tag_secret[e-1])          # e > e0
```

Only the current epoch's secret and the two either side of it are retained; everything older is zeroized. A seized device can compute tags for a five-hour window and nothing before it.

Each device precomputes, for every contact, the tags for **both directions** across the current epoch ±2 hours (clock-skew tolerance) over a sliding window of 256 counter values anchored on the highest `i` seen so far, and keeps them in a hash map. On receiving a cell:

1. Look up the tag in the local map. **O(1).**
2. Hit → decrypt; this cell is for me, and the window advances.
3. Miss → relay it. I learn nothing about it.

**Cost of the window.** 50 contacts × 2 directions × 256 counters × 5 epochs = 128 000 entries, about 2 MB of hash map, recomputed incrementally.

The cost is **linear in contact count**, so it has to be bounded rather than assumed away. The window is 256 entries for contacts active in the last 7 days and **32 entries for dormant contacts**, widening automatically the moment one of them sends. At 500 contacts — an unrealistic upper bound for a tool that requires meeting people in person — that is 8.6 MB, still inside the `QW-N-SYS-323` budget of 90 MB. Above 1 000 contacts the app warns and stops widening. An earlier draft quoted the 50-contact figure with no scaling rule at all.

**Window exhaustion.** If more than 256 cells in one direction are lost or arrive out of order, the receiver's window falls behind and the sender's cells stop matching. Recovery is automatic. The sender cannot observe a match failure directly — nothing comes back from a tag that did not match — so the observable it acts on is **eight consecutive cells with no delivery receipt** (`content_type = 0x02`, always enabled, §12). At that point the sender emits one cell with `i` reset to the epoch base, which always lies inside the receiver's window, and the window re-anchors. This is the one place where a deliberate, bounded resynchronisation signal exists, and it is indistinguishable on the wire from any other cell.

### 5.6 Hop-to-hop encryption

Every physical link between two devices runs a **Noise `XX`** handshake (`snow` crate, `Noise_XX_25519_ChaChaPoly_BLAKE2s`). All L2 cells are encrypted again inside this tunnel. An observer sniffing the air sees only an opaque Noise stream, not even the fact that a QUIETWIRE cell exists inside it.

**The Noise static key is not the identity key.** Using `IK_dh` as the Noise static would hand every relay a permanent, unique identifier for the device, which would make the rotating BLE advertisement in §7.1 pointless and would let a network of passive relays track a person's movements precisely. Instead each device holds a **link pseudonym**: an X25519 keypair regenerated every 24 hours, unrelated to the identity keys, used as the Noise static for that day only and then zeroized.

This is a deliberate trade-off and it costs something. Peer reputation (§8.6) and encounter statistics (§8.2) can only accumulate within a 24-hour pseudonym lifetime, which weakens both. The alternative — a stable relay identity — would buy better routing and stronger anti-Sybil at the price of turning every relay into a tracking beacon. **Unlinkability wins, because it is the promise the product is built on; the routing cost is accepted and is reflected in the delivery gates in §17.4.**

### 5.7 Key hierarchy at rest

```
User password ──Argon2id(m=256MiB, t=4, p=2, salt=32B random)──▶ KEK (256 bit)
                                                                    │
    ┌───────────────────────────────────────────────────────────────┘
    │  XChaCha20-Poly1305 unwrap
    ▼
  DEK (256 bit, random at install, never leaves memory unwrapped)
    │
    ├──HKDF("db")────────▶  SQLCipher page key
    ├──HKDF("field")─────▶  field-encryption key
    ├──HKDF("identity")──▶  wraps IK_sign / IK_dh / PQ_kem
    ├──HKDF("sessions")──▶  wraps all ratchet states
    └──HKDF("meta")──────▶  wraps contact list and routing history
```

Argon2id parameters are **m = 256 MiB, t = 4, p = 2 on mobile and m = 1 GiB, t = 4, p = 2 on desktop**, matching §3; the diagram shows the mobile figure only for width.

On devices with hardware key storage (Android StrongBox, iOS Secure Enclave, TPM 2.0, macOS Secure Enclave), the **wrapped** DEK can additionally be sealed by a hardware-bound key with biometric release.

**This is off by default and must stay off by default**, because the brief this system was built to says the password is required both to read and to send, and a fingerprint is not a password. When a user turns it on, the constraint is explicit: the password is still required for the first unlock after every boot, after every wipe-counter increment, and after any 24-hour period without one. Biometrics shorten a session; they never open one from cold. Hardware sealing is **optional and additive** — the password alone is always sufficient.

Every long-lived key sits alone on its own 16 KiB-aligned allocation, `mlock`ed where the OS permits and wiped on drop (ADR-0014); transient key material lives in `zeroize::Zeroizing` buffers. `QW-U-CRY-050` checks that nothing secret survives in freed memory.

---

## 6. Wire format

### 6.1 The cell — exactly 512 bytes, always

Every packet on every medium is exactly 512 bytes. No exceptions. Size reveals nothing.

```
Offset  Size  Field                      In AEAD AAD?
──────────────────────────────────────────────────────────────────────
  0      1    version            0x01              yes
  1      1    flags              all 8 bits reserved, MUST be random  yes
  2      1    ttl                hops remaining, 0..64              NO
  3      1    copies             copy budget, 0..15                 NO
  4     16    tag                per-message tag (see §5.5)         yes
 20     24    nonce              random, XChaCha20-Poly1305         yes
 44    452    ciphertext         E2E encrypted payload              —
496     16    mac                Poly1305 tag                       —
──────────────────────────────────────────────────────────────────────
Total: 512 bytes
```

**No flag bit carries meaning.** The `flags` byte exists only so the format has room to grow, and every bit of it is random today. An earlier draft assigned bit0 to "fragment follows" and bit1 to "ack requested" — both in the **cleartext** header, where every relay and every observer could read them. That would have leaked, per cell, whether it belonged to a multi-cell message and whether a reply was expected: enough to group fragments of one message together and to tell a conversation from a one-way notification, from outside the encryption. Both facts already exist inside the encrypted payload (`fragment_index`, `fragment_total`, `content_type`), where they belong. Anything ever added to this byte must be information a hostile relay is *supposed* to have.

**There is no decoy flag either.** An earlier draft of this specification carried a `real/decoy` bit in the header, described as "local only, stripped on relay". That is a contradiction: a bit in the cleartext header is visible to every relay the cell touches, so the bit would have destroyed exactly the property the cover traffic exists to create. A decoy is instead a cell addressed to the sender itself, with `content_type = 0xFF` inside the encrypted payload where nobody but the sender can see it. It is forwarded like any other cell and dies when its TTL expires. Nothing in the header distinguishes it.

**The AAD is `bytes[0..2] || bytes[4..44]`** — version, flags, tag and nonce — and deliberately **excludes `ttl` and `copies`**, which every relay legitimately modifies. Stating "the MAC covers bytes 0..496" would be incoherent with that, since it would break on the first hop. The mutable pair is protected hop by hop instead: it travels inside the Noise tunnel (§5.6), so a relay can forge its own neighbours' view of the copy budget but cannot forge anyone else's, and the damage is bounded by the analysis in §18.6 A028.

### 6.2 Ratchet frame — the 452 bytes of `ciphertext`

```
Offset  Size  Field
──────────────────────────────────────────────────────────────
  0     32    dh_ratchet_pub     sender's current ratchet public key
 32      4    prev_chain_len     u32 LE
 36      4    message_number     u32 LE
 40    396    inner_ciphertext   XChaCha20-Poly1305 under MK
436     16    inner_mac          Poly1305 tag, AAD = bytes 0..40
──────────────────────────────────────────────────────────────
Total: 452 bytes
```

An earlier draft described `inner_ciphertext` as "including a 16-byte inner Poly1305 tag" **and** listed a separate 16-byte `inner_mac` — the tag was counted twice. It is counted once: 40 bytes of ratchet header, 396 bytes of ciphertext, 16 bytes of tag, 452 in total.

The first message of a session carries `CT_pq` (1 088 bytes for ML-KEM-768) and `EK_A_pub` (32 bytes), which do not fit in one cell. **1 120 bytes over 365-byte bodies is four cells, not three** — an earlier draft said three, which is 1 095 bytes of capacity and 25 bytes short. Session establishment is therefore always a **four-cell fragment set** with `content_type = 0x07 session_init`, reassembled before the ratchet starts, with the fourth cell's remaining 335 bytes carrying the beginning of the first real message. This is the only message type with a mandatory multi-cell form, and it is why a first message to a new contact is slower to arrive than every subsequent one.

### 6.3 Application payload — the 396 bytes of `inner_ciphertext`

```
Offset  Size  Field
──────────────────────────────────────────────────────────────
  0     16    message_id         random 128-bit, dedup + receipt matching
 16      8    timestamp_ms       u64 LE, sender's clock, rounded to 60 s
 24      1    content_type       0x01 text/utf8
                                 0x02 delivery receipt
                                 0x03 read receipt
                                 0x04 contact bundle
                                 0x05 file fragment
                                 0x06 reserved (was telemetry/position — see below)
                                 0x07 session init
                                 0x08 tag resynchronisation
                                 0xFF decoy
 25      2    fragment_index     u16 LE
 27      2    fragment_total     u16 LE
 29      2    body_length        u16 LE, ≤ 365
 31    365    body               content, then random padding to 365
──────────────────────────────────────────────────────────────
Total: 396 bytes — no trailing slack
```

An earlier draft titled this "380 bytes usable" and appended a phantom padding row at offset 396. Both were wrong: the header is 31 bytes, the body field is 365, and 31 + 365 is exactly 396. **365 bytes is the usable figure** and it is the one quoted everywhere else in this document.

`message_id` is a random 128-bit value, not a UUIDv4. A v4 UUID fixes six bits to encode its version and variant, which would make four of the sixteen header bytes constant across every cell in the system — a free distinguisher for an attacker who ever breaks one layer, and an unnecessary loss of 6 bits of dedup space.

`timestamp_ms` is **rounded down to the nearest 60 seconds** before encryption. Millisecond precision would let a recipient — and anyone who ever compromises a recipient — correlate a message against external observations far more sharply than the feature is worth.

**Content type `0x06`, telemetry and position, is withdrawn from v1.** An earlier draft listed it in the wire format and then never mentioned it again: no user interface, no threat analysis, no consent model, no test. A location-sharing feature that appears only in a table is an attack surface nobody has reviewed, inside a product whose entire purpose is not revealing where people are. The code point stays reserved so a future version can define it properly, with its own AUD-1 review.

`fragment_total` is a `u16`, so a message or file is capped at 65 535 fragments — **about 23.9 MB**. That ceiling is enforced at send time with a clear message rather than discovered at fragment 65 536, and it is generous: at LoRa's thirteen cells an hour, 23.9 MB is over five hundred years of airtime. The practical limit is always the medium, never the format.

**365 bytes of text per cell ≈ 365 ASCII characters or ~120 CJK characters.** Longer messages fragment across cells; each fragment is independently routed, independently padded, and independently indistinguishable. Files are simply many fragments with an extra RaptorQ layer so a receiver can rebuild the file from any sufficiently large subset of fragments.

---

## 7. Transport layer specification

All adapters implement one Rust trait:

```rust
#[async_trait]
pub trait Transport: Send + Sync {
    fn id(&self) -> TransportId;
    fn cost(&self) -> LinkCost;              // see §8.3
    async fn discover(&self) -> Result<Vec<PeerHandle>>;
    async fn connect(&self, peer: &PeerHandle) -> Result<Link>;
    async fn send(&self, link: &Link, cell: &Cell512) -> Result<()>;
    fn incoming(&self) -> Receiver<(PeerHandle, Cell512)>;
    fn mtu_cells_per_second(&self) -> f32;
}
```

Adding a medium later (satellite, meteor scatter, acoustic modem) means implementing this trait and nothing else.

### 7.1 Bluetooth Low Energy — `transport-ble`

- **Discovery:** BLE advertising with a rotating **128-bit** custom service UUID, derived deterministically so that every device computes the same one without any server:
  `UUID = BLAKE3_derive_key("QUIETWIRE-BLE-SERVICE-v1", LE64(floor(unix_seconds / 86400)))[0..16]`, with the version and variant nibbles forced to RFC 4122 form. A device scans for **yesterday's, today's and tomorrow's** UUIDs simultaneously, so a clock off by a day still finds peers. A 16-bit UUID, as an earlier draft specified, is not available to use: that range is allocated by the Bluetooth SIG and colliding with an assigned number would make the app discoverable as something else entirely.
- **What rotation does and does not buy.** The service UUID is identical for every QUIETWIRE device, so it never identified an individual and rotating it does not prevent device tracking — that is what the link pseudonym in §5.6 and the platform's own MAC randomisation are for. What rotation buys is that a long-term observer cannot use a single fixed constant to census QUIETWIRE users across months, and that a scanner built today stops working tomorrow.
- **Data channel:** **L2CAP Connection-Oriented Channels** where available (Android 10+, iOS 11+, BlueZ 5.50+), giving 50–200 kB/s. Falls back to GATT characteristic writes with MTU negotiation (~500 B/s) on older stacks.
- **Rust:** `btleplug` for desktop. On mobile, the platform BLE APIs are driven from Kotlin/Swift and cells are handed to the Rust core through UniFFI — Android and iOS both require background BLE to be managed by the OS-native layer.
- **Android background:** foreground service of type `connectedDevice`, plus permissions that differ by API level and must not be requested blindly:
  - **API 31+**: `BLUETOOTH_SCAN` with `usesPermissionFlags="neverForLocation"`, `BLUETOOTH_ADVERTISE`, `BLUETOOTH_CONNECT`. **No location permission is requested**, because `neverForLocation` is precisely the declaration that removes the need for it — asking anyway would demand a permission the app does not use, in a privacy tool.
  - **API 26–30**: `ACCESS_FINE_LOCATION` is unavoidable; the platform ties BLE scanning to it. The app explains why before asking, in one sentence, and the Advanced screen states that this is an Android limitation and not something QUIETWIRE uses.
  - Battery-optimisation exemption requested with a clear explanation, and the app functions without it, degraded.
- **iOS background:** `bluetooth-central` + `bluetooth-peripheral` background modes. **Known and accepted limitation:** iOS backgrounded peripherals advertise only in the overflow area and are discoverable only by other iOS apps holding the same service UUID. iOS devices are therefore weaker relays than Android. Documented to users, not hidden.
- **Duty cycle:** scan 8 s every 45 s in idle, continuous when the app is foregrounded or a message is pending.

### 7.1b Supported platform versions

Stated once, here, because an earlier draft scattered version numbers across four sections and never assembled them.

| Platform | Minimum | Reason for the floor | Notes |
|---|---|---|---|
| Android | **8.0, API 26** | Wi-Fi Aware and modern Keystore | Full relay capability at API 29+ where BLE L2CAP CoC exists |
| iOS | **16.0** | Background BLE behaviour, Swift concurrency, current entitlement model | Weak relay by platform design (see §7.1) |
| macOS | **13 Ventura** | Matches the iOS toolchain and Secure Enclave API | |
| Windows | **10, 1903** | Wi-Fi Direct API and modern TPM 2.0 access | |
| Linux | **BlueZ 5.50+**, kernel 5.4+ | L2CAP CoC support | Also the Raspberry Pi target |
| Raspberry Pi | **Pi 3B+ or newer** | Headless relay daemon | Pi Zero 2 W works but is not gated |

Devices below these floors are not supported and the app refuses to install rather than running in a state nobody has tested.

### 7.2 Wi-Fi Direct / Wi-Fi Aware — `transport-wifidirect`

- Android: Wi-Fi Aware (NAN) on API 26+, Wi-Fi Direct fallback.
- Linux/Windows: `wpa_supplicant` P2P / Windows Wi-Fi Direct API.
- macOS/iOS: not available to third parties. Those platforms use BLE only for short range. Stated plainly.
- Throughput 5–40 MB/s. Used opportunistically for bulk sync when two nodes have a large backlog to exchange.

### 7.3 LoRa — `transport-lora`

- **Hardware:** RNode-compatible boards (Semtech SX1262/SX1276). Connected by USB-OTG, USB serial, or BLE-to-RNode.
- **Region defaults:** EU 863–870 MHz (SF7–SF12, BW 125 kHz, CR 4:5, +14 dBm ERP, **1 % duty cycle enforced in software**, per ETSI EN 300 220); US and Canada 902–928 MHz (+20 dBm, 400 ms dwell limit, frequency hopping, per FCC Part 15.247 and ISED RSS-247). The earlier label "ES-overseas" was meaningless — Spain is an EU 868 MHz territory, and its overseas regions follow their own national allocations, which the region table resolves individually.
- **Airtime accounting:** the adapter maintains a rolling duty-cycle ledger and refuses to transmit if it would breach the regional limit. This is a hard, non-configurable safety interlock.
- **Cell over LoRa:** 512 bytes exceeds a LoRa frame, so cells are split into 4 × 128-byte link frames with a 2-byte link header and RaptorQ repair symbols. At SF9/BW125/CR4:5 each 130-byte frame is 158 symbols ≈ 697 ms including preamble, so **one full cell costs ≈ 2.8 s of airtime**, not the 2.1 s an earlier draft claimed.
- **The consequence nobody likes.** A 1 % duty cycle is 36 seconds of transmission per hour. At 2.8 s per cell that is **fewer than 13 cells per hour per device on EU 868 MHz** — roughly 12 messages an hour, shared between relaying other people's traffic and sending your own. This single number governs the realistic behaviour of any European LoRa mesh and is the reason the routing budget in §8 is as miserly as it is. It also means **cover traffic is never generated over LoRa** (see §9): forty decoy cells an hour would exceed the legal budget by a factor of three. On LoRa, unlinkability is bought by the per-message tags and by batching, not by decoys.

### 7.4 Reticulum bridge — `transport-reticulum`

QUIETWIRE speaks Reticulum through `reticulum-rs`, which gives it, for free:

- Established LoRa/packet-radio/serial/TCP interfaces
- Reticulum's own transport-layer routing and path discovery
- Interoperability with the existing Sideband / MeshChat / NomadNet user base and with community LXMF propagation nodes

QUIETWIRE cells are carried as opaque Reticulum payloads. **Our E2E layer is applied first and is never removed by Reticulum**, so interop never weakens our guarantees — a Reticulum node relaying our traffic sees exactly as little as any other relay.

**Two build flavours, because "no internet" has to mean it.** Reticulum's TCP and I2P interfaces reach the internet, and §1 promises a system that works without it. Shipping one binary that merely *prefers* not to use the network would make that promise unverifiable by the user. So there are two:

| Flavour | Transports | Android permission | Who it is for |
|---|---|---|---|
| **airgap** (default) | BLE, Wi-Fi Direct, LoRa, Reticulum over serial/RNode only, sneakernet | **No `INTERNET` permission in the manifest at all** | Anyone who needs the guarantee to be structural rather than a setting |
| **bridged** | the above plus Reticulum over TCP and I2P | `INTERNET` declared, cleartext forbidden | Users linking two isolated meshes across a region that does have connectivity |

The airgap flavour's inability to reach the network is verifiable by anyone with `aapt` in ten seconds — a far stronger claim than a toggle inside an app. Both flavours interoperate; the choice is about what the device itself can do, not what the network is. An earlier draft listed "Reticulum over TCP/I2P" in the cost table while promising no internet anywhere else, and never reconciled the two.

### 7.5 Sneakernet — `transport-sneakernet`

The layer that makes intercontinental delivery real.

- **Bundle file:** `*.qwb` — a container of cells plus a GCS digest of what the bundle carries. Written to a USB drive, SD card, or any file share.
- **Import/export:** one tap. The app writes every pending cell whose routing budget permits, and ingests everything it finds.
- **Encrypted paper message:** a message rendered as an animated QR sequence at 8 fps using RaptorQ fountain coding — the receiver's camera recovers the payload from any sufficient subset of frames, so no frame ordering or perfect capture is required. Also renders to a static multi-page PDF for printing and physical mail.
- **NFC:** tap-to-transfer for a single cell, useful for contact exchange.

A traveler carrying a phone from Madrid to Buenos Aires *is* the transcontinental link. The cells in their device are encrypted and unreadable to them; they are an unwitting, harmless carrier.

---

## 8. Routing specification

There is no global topology, so there is no Dijkstra. QUIETWIRE uses **utility-based opportunistic routing**, which is the state of the art for DTNs.

### 8.1 Binary Spray-and-Wait

Each new message is created with **L = 8 copies**.

- When node X (holding `n` copies) meets node Y that does not hold the message, X hands over `floor(n/2)` copies and keeps `ceil(n/2)`.
- A node holding exactly 1 copy enters **wait mode**: it forwards only to the final recipient, never to another relay.

This bounds total network flooding at 8 copies per message while keeping delivery probability close to unrestricted epidemic routing. It is the single most important efficiency decision in the system: it directly answers "the shortest and most efficient route without costing so much".

### 8.2 Encounter-utility routing — and why it is not PRoPHET

Spray-and-Wait decides *how many* copies. Something has to decide *to whom*.

**The obvious answer does not work here, and this is the most important correction in the routing design.** Classic PRoPHET maintains `P(A, B)`, a per-*destination* delivery probability, and hands copies to whichever neighbour scores highest for that destination. That requires a stable identifier for the destination. QUIETWIRE deliberately has none: §5.5 gives every cell a tag that has never appeared before and will never appear again, precisely so that nobody can tell two cells belong to the same conversation. A routing table keyed on destination is therefore **unbuildable**, and any attempt to build one — a longer-lived "routing tag", a daily destination pseudonym — reintroduces exactly the linkability the tag design exists to destroy. An earlier draft of this document specified destination-keyed PRoPHET alongside per-message tags. The two cannot both be true.

The resolution is to route on **properties of the carrier rather than knowledge of the destination**. Each node scores every neighbour it meets with a utility that says nothing about who the cell is for:

```
U(peer) = w1 · meeting_rate(peer)        # encounters per hour, EWMA
        + w2 · distinct_peers(peer)      # reported degree, capped
        + w3 · mobility(peer)            # self-reported movement class: 0 fixed,
                                         #   1 local, 2 commuting, 3 travelling
        + w4 · relay_reliability(peer)   # proof-of-relay success rate (§8.6)
        - w5 · backlog_pressure(peer)    # how full the peer already is

default weights: w1=0.30  w2=0.20  w3=0.30  w4=0.15  w5=0.05
```

A copy goes to the highest-utility neighbour that does not already hold it. The intuition is the one that actually holds in a delay-tolerant network: a cell reaches an unknown destination fastest by being carried by whoever meets the most people and travels the furthest. Delivery itself needs no routing knowledge at all — the recipient recognises its own cell by trial tag lookup the moment the two devices meet.

**All five inputs are self-reported by the peer and therefore untrusted.** They are treated as hints, capped (`distinct_peers` at 64, `mobility` at 3), and cross-checked against what the node observes directly. `relay_reliability` is the only input that cannot be inflated by assertion, which is why it carries weight even though the 24-hour link pseudonym (§5.6) limits how much of it can accumulate. Utility vectors are exchanged **only inside the Noise tunnel**.

**What this costs.** Encounter-utility routing is measurably worse than destination-aware routing in delivery latency — the published DTN literature puts the gap at roughly 10–20 % of delivery ratio at a fixed deadline, depending on mobility model. That is the price of unlinkability and it is paid deliberately. The simulation gates in §17.4 are set against this design, not against the PRoPHET figures an earlier draft quoted.

### 8.3 Link cost

```
cost = base_cost(transport)
     × (1 + energy_per_cell_mJ / 100)
     × (1 + airtime_penalty)
     ÷ (1 + U(peer))
```

`U(peer)` is the encounter utility from §8.2, normalised to [0, 1]. The earlier formula divided by `delivery_predictability`, a per-destination quantity that §8.2 shows cannot exist in this system.

| Transport | base_cost |
|---|---|
| Wi-Fi Direct | 1 |
| BLE L2CAP | 4 |
| BLE GATT | 12 |
| Reticulum over TCP/I2P | 6 |
| LoRa SF7 | 40 |
| LoRa SF12 | 220 |
| Sneakernet | 1 (but latency weight 10 000) |

The scheduler minimises `cost × expected_latency` subject to the remaining copy budget, the TTL, and a per-day energy budget the user sets with a single three-position slider (Saver / Balanced / Maximum reach).

### 8.4 Digest exchange — Golomb-Coded Sets

Before transferring anything, two nodes exchange a compact summary of what they already hold, so nothing is sent twice.

A **Golomb-Coded Set** over the message IDs is used rather than a Bloom filter: for the same 1 % false-positive rate a GCS is roughly 30 % smaller, which matters enormously when the link is a 2 s-per-cell LoRa channel. A 1 000-message digest fits in about 1.1 kB.

### 8.5 Lifecycle limits

| Limit | Value | Purpose |
|---|---|---|
| TTL | 64 hops | Prevents infinite circulation |
| Copies | 8 | Bounds flooding |
| Max age in transit | 30 days (user-configurable 1–365) | Bounds storage |
| Relay cache | `min(500 MB, 5 % of free space)`, LRU by `age × (1/copies)` | Bounds disk use without filling a budget phone |
| Relay dedup window | 100 000 recent cell hashes, 24 h | Stops a cell circling back; an optimisation, **not** the replay defence |
| E2E replay defence | ratchet message number, for the life of the session | Blocks replay attacks properly |

**Why replay protection needs two mechanisms.** A 24-hour cache of cell hashes cannot be the replay defence when a cell may legitimately remain in transit for 30 days: an attacker who stores a cell and re-injects it on day two would sail past a 24-hour window. The actual defence is at the end-to-end layer, where the Double Ratchet refuses a message number it has already consumed for the life of the session, and skipped-key entries are deleted the moment they are used. The relay-level cache exists only to stop a cell bouncing between two neighbours and wasting airtime. An earlier draft conflated the two and would have shipped a real replay vulnerability.

### 8.6 Anti-Sybil

A node that receives many cells and relays none accumulates negative reputation from its neighbours (measured by **proof of relay**: a relayed cell produces an acknowledgement signed by the next hop's link pseudonym). Low-reputation neighbours get reduced copy allocation. This is deliberately soft — it degrades leeches rather than excluding them, because hard exclusion is itself an attack surface.

**Honest assessment of how weak this is.** Reputation is bound to a link pseudonym that is discarded every 24 hours (§5.6), so an attacker resets their reputation daily at zero cost, and a Sybil swarm can mint a fresh identity per encounter. Proof-of-relay therefore penalises a *lazy* node over the course of a day; it does not stop a *determined* one. The real Sybil defence is the copy budget: because at most 8 copies of any cell exist network-wide regardless of how many nodes ask for one, a swarm of ten thousand fake nodes cannot amplify traffic, only absorb it. Reputation reduces waste; the copy bound is what makes the attack survivable. This limitation is disclosed rather than papered over, and `QW-S-RTE-155` and `QW-X-SYS-303` test the system under the assumption that reputation provides nothing.

---

## 9. Traffic analysis resistance

Five mechanisms, all mandatory, none user-configurable:

1. **Fixed 512-byte cells.** Size carries zero information.
2. **Cover traffic, budgeted per transport.** On BLE and Wi-Fi Direct the node emits decoy cells (`content_type = 0xFF`, addressed to itself, invisible as decoys to everyone else) following a **Poisson process with λ = 1 / 90 s**. Real messages are emitted by replacing the next scheduled decoy, so the externally observable emission process is statistically identical whether the user is silent or chatting.
   **On LoRa there is no cover traffic at all.** Forty decoy cells an hour would need 112 seconds of airtime against a legal budget of 36 (§7.3). Generating them would be both illegal and self-defeating, since a device transmitting at three times the duty cycle of everything else around it is the most conspicuous object on the band. On LoRa the unlinkability budget is spent entirely on per-message tags, fixed cell size and batching. **This is a real reduction in traffic-analysis resistance on the long-range medium and users are told so in the Advanced screen**, rather than being left to assume the protection is uniform.
   On the sneakernet transport the concept does not apply: a USB bundle is padded to a fixed number of cells with decoys, which costs nothing.
3. **Random forwarding delay.** Each relay holds a cell for `Exponential(mean = 4 s)` before forwarding. Breaks timing correlation between ingress and egress.
4. **Batched exchange.** Cells transfer in shuffled batches of 16, not individually.
5. **No addressing in the clear.** Epoch tags rotate hourly and are unlinkable without the session key (§5.5).

**Honest limit:** these defeat a regional observer. They do not defeat an adversary who can simultaneously observe every single radio in the mesh *and* has unlimited computation for intersection attacks over months. No practical system defeats that; claiming otherwise would be dishonest.

---

## 10. Local storage specification

### 10.1 Two independent encryption layers

**Layer 1 — SQLCipher** encrypts every database page with AES-256-CBC and authenticates it with HMAC-SHA512, keyed by `HKDF(DEK, "db")`.

Two details matter and an earlier draft got both slightly wrong:

- **The key is supplied raw**, as `PRAGMA key = "x'<64 hex chars>'"`, not as a passphrase. Handing SQLCipher a passphrase would make it run its own PBKDF2-HMAC-SHA512 over a key that Argon2id has already derived — a second, weaker KDF stacked pointlessly on a strong one, costing hundreds of milliseconds at every open for no security.
- **SQLCipher does not encrypt the first 16 bytes**; by default it writes a random salt there. Saying "even the file header is encrypted" was inaccurate. The salt is random, so the claim that the file is indistinguishable from random bytes survives — but only because we then set `PRAGMA cipher_plaintext_header_size = 0` and supply the salt externally from the vault, giving a file with **no plaintext header at all**, not even a recognisable SQLite magic string.

**Layer 2 — per-field AEAD.** Every sensitive column additionally stores `XChaCha20-Poly1305(HKDF(DEK,"field"), nonce, value, aad = table||rowid||column)`. If SQLCipher were ever broken, the schema, the indices and the row sizes still reveal nothing.

### 10.2 Schema

**Structural correction: two store files, not one table column.** An earlier draft placed a `store_id` column on `contacts` and `messages` so that the real and decoy stores shared one database. That design cannot satisfy the duress requirement in §11.3: both stores' rows sit in one file, so row counts, page counts and free-list structure reveal that a second store exists, and a single bug in one `WHERE store_id = ?` clause leaks real data into the decoy view.

The correct design is **two physically separate database files, with independent DEKs, created at install time and both always present**. Exactly two exist whether or not the user ever sets a duress password; the unused one is populated at install with generated decoy content and is written to on the same schedule as the real one, so the pair is indistinguishable by size, modification time or growth pattern. Store isolation is then a property of *which file is open*, enforced by the type system: there is no query in the codebase capable of addressing the other store, because the handle for it does not exist in that process state.

```sql
-- One file per store. *_enc columns are BLOBs of XChaCha20-Poly1305 ciphertext.
-- Every timestamp is coarsened to the hour before it is written.

PRAGMA journal_mode      = WAL;
PRAGMA secure_delete     = ON;
PRAGMA temp_store        = MEMORY;   -- no plaintext temp files, ever
PRAGMA auto_vacuum       = FULL;

CREATE TABLE schema_meta (
    k               TEXT PRIMARY KEY,        -- 'version'
    v               INTEGER NOT NULL
);

CREATE TABLE contacts (
    id              BLOB PRIMARY KEY,        -- random 16 B, unrelated to identity
    display_enc     BLOB NOT NULL,
    identity_enc    BLOB NOT NULL,           -- IK_sign, IK_dh, PQ_kem
    state_enc       BLOB NOT NULL,           -- verified / blocked / muted flags
    created_at_h    INTEGER NOT NULL         -- hours since epoch
);

CREATE TABLE prekeys (                        -- our own OPK pool (§5.1)
    idx             INTEGER PRIMARY KEY,
    keypair_enc     BLOB NOT NULL,
    published_at_h  INTEGER                   -- NULL until burned by a QR display
);

CREATE TABLE sessions (
    contact_id      BLOB PRIMARY KEY REFERENCES contacts(id) ON DELETE CASCADE,
    ratchet_enc     BLOB NOT NULL,           -- full Double Ratchet state
    skipped_enc     BLOB,                    -- skipped message keys
    tagwindow_enc   BLOB NOT NULL,           -- per-direction tag counters (§5.5)
    updated_at_h    INTEGER NOT NULL
);

CREATE TABLE messages (
    id              BLOB PRIMARY KEY,        -- message_id
    contact_id      BLOB NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    envelope_enc    BLOB NOT NULL,           -- direction, state, timestamps, body
    sent_at_h       INTEGER NOT NULL,        -- hour bucket, for ordering only
    expires_at_h    INTEGER
);
CREATE INDEX idx_messages_thread ON messages(contact_id, sent_at_h DESC);
CREATE INDEX idx_messages_expiry ON messages(expires_at_h)
    WHERE expires_at_h IS NOT NULL;

CREATE TABLE outbox (                         -- cells awaiting an opportunity
    cell_id         BLOB PRIMARY KEY,
    message_id      BLOB NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    cell            BLOB NOT NULL,           -- the sealed 512 B
    copies          INTEGER NOT NULL,
    ttl             INTEGER NOT NULL,
    created_at_h    INTEGER NOT NULL
);

CREATE TABLE inbox_fragments (                -- partial reassembly
    message_id      BLOB NOT NULL,
    fragment_index  INTEGER NOT NULL,
    payload_enc     BLOB NOT NULL,
    received_at_h   INTEGER NOT NULL,
    PRIMARY KEY (message_id, fragment_index)
);
CREATE INDEX idx_frag_evict ON inbox_fragments(received_at_h);

CREATE TABLE relay_cache (                    -- other people's traffic
    row_id          BLOB PRIMARY KEY,        -- random, NOT the cell tag
    cell            BLOB NOT NULL,           -- raw 512 B, already E2E encrypted
    received_at_h   INTEGER NOT NULL,
    copies          INTEGER NOT NULL,
    ttl             INTEGER NOT NULL
);
CREATE INDEX idx_relay_evict ON relay_cache(received_at_h, copies);

CREATE TABLE peer_utility (                   -- §8.2, keyed on link pseudonym
    pseudonym       BLOB PRIMARY KEY,         -- 24 h lifetime
    utility_enc     BLOB NOT NULL,
    updated_at_h    INTEGER NOT NULL
);

CREATE TABLE seen_cells (                     -- 24 h relay dedup (§8.5)
    cell_hash       BLOB PRIMARY KEY,
    seen_at_h       INTEGER NOT NULL
);
CREATE INDEX idx_seen_evict ON seen_cells(seen_at_h);
```

**Partial reassembly is an attack surface and is bounded accordingly.** A hostile peer can send fragment 40 000 of a message that will never complete, forever, from an endless supply of message ids. `inbox_fragments` therefore carries an eviction index and three hard caps: at most **64 incomplete messages** in flight per contact, at most **8 MB** of partial reassembly in total, and a **6-hour** expiry on any incomplete set, oldest-evicted-first. `seen_cells` gets the same treatment — both tables are swept on a timer, and neither can be grown without bound by anything arriving from outside. An earlier draft defined both tables with no eviction index at all, which would have made the sweep a full table scan on the largest tables in the database.

Three further deliberate changes from the earlier draft, each closing a metadata leak:

- **`direction`, `state` and `verified` are no longer plaintext integer columns.** Section 10.1 claims that if SQLCipher were broken the schema would still reveal nothing; small plaintext enums break that claim immediately, since counting rows where `direction = 1` gives an examiner the exact number of messages the user sent. They now live inside `envelope_enc` and `state_enc`.
- **Every timestamp is stored as an hour bucket**, not a millisecond value, and is used only for ordering and eviction. Message-level precision lives encrypted in the envelope.
- **`relay_cache` is keyed on a random row id, not on the cell tag.** Keying on the tag was a straightforward bug: tags are now per-message and unique (§5.5), so `PRIMARY KEY (tag, received_at)` would have grown a distinct index entry per cell anyway while advertising the tag in the clear inside the index structure.

The `predictability` table is gone entirely, replaced by `peer_utility`, because destination-keyed routing state cannot exist in this system (§8.2).

The vault lives **outside** either store file, in a small fixed-size blob of exactly 4 096 bytes holding: the Argon2 salt, the SQLCipher salts, two wrapped DEKs, the fail counter, and random padding to the fixed length. Its layout is positional, with no key names — an earlier draft used a `vault` table with `TEXT` keys such as `'wrapped_dek'`, which would have printed the word "duress" into an examiner's hex dump the moment a second slot existed.

`relay_cache` holds cells the device is carrying **for other people**. They are already E2E encrypted and the device has no key for them. This table is what makes the device a relay, and it is also the table an examiner will find largest — which is a feature: a seized device is full of traffic its owner cannot read and never could.

### 10.3 Secure deletion

SQLite's `secure_delete` pragma is enabled, and deletion performs a three-pass overwrite of the page before `VACUUM`. **Stated honestly:** on flash storage with wear levelling, overwriting does not reliably destroy the physical block. The real protection is that nothing was ever written unencrypted — deleting the DEK renders every remaining ciphertext permanently unrecoverable. That is the mechanism the panic wipe relies on.

---

## 11. Authentication, duress and panic

### 11.1 Unlock

1. User enters password.
2. `KEK = Argon2id(password, salt, m=256MiB, t=4, p=2)` — one derivation, since both slots share the vault salt.
3. Attempt to unwrap **both** wrapped DEKs, always, in a fixed order, with the result selected by constant-time comparison rather than by an early return.
4. Slot A unwraps → open store file A. Slot B unwraps → open store file B. Which file is "real" is decided at setup and is not recorded anywhere.
5. Neither unwraps → increment the fail counter, apply exponential backoff (1 s, 2 s, 4 s … capped at 5 min).

**Both unwraps always execute.** Returning as soon as one succeeds would make an unlock into the first slot measurably faster than an unlock into the second, which is precisely the signal the duress design exists to suppress. Argon2id dominates the wall-clock time either way, but §18.6 D007 requires the property to hold by construction, not by luck.

**Which slot is which is not stored.** There is no "real" flag. Setup writes the user's primary content to one slot chosen at random and the decoy content to the other. An examiner with the vault blob sees two structurally identical wrapped keys.

### 11.2 Password required to read *and* to send

The DEK lives in memory only while the app is unlocked. It is zeroized when:

- the app backgrounds (configurable grace period 0–5 min, default 60 s)
- the screen locks
- 10 minutes of inactivity pass
- the user taps the lock icon

Composing or sending after that point re-prompts for the password, as specified.

### 11.3 Duress password

Set up optionally during onboarding. It opens a fully functional, separate store containing decoy contacts and conversations the user writes themselves. Everything works normally: messages can be sent and received in the decoy store, with decoy identities. There is **no indication anywhere on the device** that a second store exists — the two wrapped DEKs are stored in identical-looking rows, and the real store's row is indistinguishable from the random padding rows that always accompany it.

### 11.4 Wipe on repeated failure

After **N consecutive failures** (default 10, user-settable 3–50, or disabled):

1. Overwrite **both** wrapped DEKs with random bytes.
2. Overwrite the Argon2 salt and both SQLCipher salts.
3. Delete and recreate **both** store files, then repopulate both with freshly generated decoy content.
4. Delete the hardware-sealed key handles.
5. Reset the fail counter.

**Both slots must die, not just one.** An earlier draft wiped only the real slot. That is worse than not wiping at all: an examiner who already holds the duress password would open the decoy store successfully while the other slot sat destroyed, which proves that a second store existed and that its owner had something to hide. The wipe must leave a device that looks exactly like a freshly installed one — which, after step 3, it is.

The data becomes mathematically unrecoverable. **This is irreversible by design and stated in red text during setup, with a typed confirmation rather than a tap.**

### 11.5 Panic action

A user-chosen trigger immediately zeroizes the DEK from RAM, force-closes the app, and optionally executes the full wipe. The available triggers are constrained by what an application can actually observe:

- A gesture inside the app (a long three-finger press anywhere).
- A decoy password typed at the QUIETWIRE unlock screen — a third slot that unwraps nothing and triggers the panic action.
- On Android only, a registered accessibility-free hardware shortcut (volume-down held during app launch).

An earlier draft offered "a duress PIN on the lock screen". **No third-party app can observe the operating system lock screen on Android or iOS**, so that trigger cannot be built and the claim is withdrawn.

### 11.6 No recovery. Ever.

There is no password reset, no recovery phrase, no backup key, no support address. If the password is lost, the data is gone. **Any recovery mechanism is a backdoor.** This is presented once, clearly, during onboarding, with a required confirmation.

Users who want a backup export an encrypted `*.qwb` archive to their own storage, protected by a separate passphrase of their choosing. It remains entirely under their control — **and it is also a hole in every other guarantee on this page, which the app says plainly at the moment of export**:

- The archive is not reached by the panic wipe or the fail-counter wipe. Destroying the device does not destroy the backup.
- The archive contains the real store only, so possessing one contradicts the deniability the duress store provides.
- Its security is the passphrase the user chose for it, protected by the same Argon2id parameters, and nothing more.

Backups are therefore off by default, never automatic, never written to cloud-synced folders (the export dialog refuses known sync paths), and the warning is shown every time rather than once. A user who needs deniability should not make one; a user who needs continuity across a lost device has no alternative. The app states the trade-off and lets the person decide, which is the only honest thing it can do.

**Device replacement.** Without a backup, a new device means a new identity: the user regenerates keys and re-scans QR codes with each contact. Contacts see the new identity as **unverified**, with a banner reading *"This is a new device for Marta. Check the safety number with her before trusting it."* The app never silently accepts a new identity for an existing contact — that is the exact shape of a man-in-the-middle attack (§2, A8), and it must look alarming because it sometimes is.

---

## 12. User interface specification

Design rule: **three screens in daily use, no settings visible by default.** Everything in §5–§11 happens with zero user involvement.

There is a fourth flow, seen once: **first-run setup**. Four steps, no skipping — choose a password; confirm it; read and acknowledge that there is no recovery; optionally set a duress password. Duress setup is the only step that can be deferred, and it is offered again exactly once, a week later, then never again unless the user goes looking. This flow is what `QW-E-APP-271` measures, and the three-minute target covers it end to end.

### Screen 1 — Unlock

```
┌──────────────────────────┐
│                          │
│        QUIETWIRE         │
│                          │
│   ┌──────────────────┐   │
│   │  ••••••••••      │   │
│   └──────────────────┘   │
│                          │
│         [ Open ]         │
│                          │
└──────────────────────────┘
```

One field. One button. Nothing else — no logo animation, no "forgot password", no sign-up.

### Screen 2 — People

```
┌──────────────────────────┐
│  People              [+] │
├──────────────────────────┤
│ ● Marta          2 min   │
│   See you tomorrow       │
├──────────────────────────┤
│ ◐ Luis           1 h     │
│   Travelling             │
├──────────────────────────┤
│ ○ Ana            3 d     │
│   Waiting for a carrier  │
└──────────────────────────┘
```

Status is a single dot, and the only network concept the user ever needs:

| Dot | Meaning | Words shown |
|---|---|---|
| ● green | Delivered and confirmed | *Delivered* |
| ◐ amber | Moving through the mesh | *Travelling* |
| ○ grey | Waiting for an onward opportunity | *Waiting for a carrier* |
| ⊗ red | Expired without delivery | *Did not arrive — resend?* |

`[+]` opens the camera to scan a contact's QR, or shows this device's own QR. Long-pressing a row offers **Verify**, **Mute**, **Block** and **Delete**.

**Block and Delete are not optional features.** A messaging system with no directory, no accounts and no moderation has exactly one defence against harassment: the recipient's own device. **Block** discards every cell whose tag matches that contact before decryption and stops all outbound traffic to them, silently, with no signal to the sender. **Delete** additionally destroys the session, the ratchet state and the message history, so the contact must be re-added in person to reach the user again. Both were missing from the earlier draft, which described an app that could be used to harass someone with no way to stop it.

**Read receipts are off by default.** A read receipt tells a contact when the user was awake, holding their phone, and looking at a specific conversation — considerably more than most people realise they are disclosing. The wire format supports them (`content_type = 0x03`); the product does not send them unless the user turns them on, per contact, in Advanced. Delivery receipts (`0x02`) are always on, because without them the status dots are meaningless.

### Screen 3 — Conversation

```
┌──────────────────────────┐
│ ‹  Marta            ●    │
├──────────────────────────┤
│              Hi ●        │
│  How are you?            │
│              Fine ◐      │
├──────────────────────────┤
│ [ Message…        ] [ → ]│
└──────────────────────────┘
```

Tapping a status dot reveals one plain sentence: *"Sent 2 hours ago. Not confirmed yet."* or *"Delivered 10 minutes ago."*

An earlier draft proposed *"Currently 3 hops away, carried by 4 devices."* **The sender cannot know that and must never appear to.** There is no route knowledge in this system by design, no telemetry comes back from relays, and a system that could report the position of a cell in the mesh would be a system that had already abandoned the privacy model. Inventing the number would be worse than omitting it. No topology map, no hop list, no jargon, and no figures the device did not actually observe.

### Hidden: Advanced

Reachable through a long-press on the title. Contains transport toggles, the three-position energy slider, LoRa region and device pairing, duress setup, wipe threshold, export/import bundles, and the safety-number verification screen. A normal user never opens it.

### Accessibility and localisation

- Full screen-reader labels, dynamic type, minimum 4.5:1 contrast, and touch targets of **at least 48 dp on Android and 44 pt on iOS** — the two platforms use different units and different minima, and quoting only the Android figure would have failed Apple's guideline by a hair on every button.
- UI strings in English in the source, externalised for translation from day one. Launch languages: English, Spanish, Arabic, Persian (Farsi), Russian, Ukrainian, **Chinese (Simplified)**, Portuguese (Brazil), French. RTL layouts supported for Arabic and Persian.

"Mandarin", as an earlier draft had it, names a spoken variety and says nothing about which script to ship. Written Chinese needs a script decision — Simplified for mainland readers, Traditional for Taiwan and Hong Kong — and the two are not interchangeable.

---

## 13. Repository layout

```
quietwire/
├── flake.nix                        # reproducible toolchain
├── Cargo.toml                       # workspace root
├── crates/
│   ├── quietwire-crypto/            # primitives, key hierarchy, zeroization
│   ├── quietwire-e2e/               # X3DH hybrid, Double Ratchet, epoch tags
│   ├── quietwire-packet/            # Cell512, padding, cover traffic, replay
│   ├── quietwire-route/             # Spray-and-Wait, encounter utility, GCS digests
│   ├── quietwire-store/             # SQLCipher + field AEAD, duress, wipe
│   ├── quietwire-transport/         # Transport trait + adapters
│   │   ├── ble/
│   │   ├── wifidirect/
│   │   ├── lora/
│   │   ├── reticulum/
│   │   └── sneakernet/
│   ├── quietwire-core/              # orchestration, public API surface
│   └── quietwire-ffi/               # UniFFI definitions + generated bindings
├── apps/
│   ├── android/                     # Kotlin + Jetpack Compose
│   ├── ios/                         # Swift + SwiftUI
│   ├── desktop/                     # Tauri 2 + Svelte 5
│   └── node/                        # headless relay daemon (Rust, for RPi/server)
├── tools/
│   ├── sim/                         # Python 3.12 network simulator (ONE-style)
│   ├── fuzz/                        # cargo-fuzz targets
│   └── provision/                   # Python RPi/RNode provisioning
├── LICENSES/                        # full texts, REUSE 3.2 (§19.1)
├── LICENSE NOTICE TRADEMARK.md
├── SECURITY.md CONTRIBUTING.md CODE_OF_CONDUCT.md CODEOWNERS MAINTAINERS.md
├── .allowed_signers rust-toolchain.toml deny.toml clippy.toml
├── docs/
│   ├── PROTOCOL.md                  # normative wire specification
│   ├── THREAT_MODEL.md
│   ├── AUDIT/                       # published audit reports
│   └── adr/                         # architecture decision records
└── .github/                         # workflows, templates, settings.yml (§19.8)
```

---

## 14. Step-by-step build plan

Timeline assumes **one experienced developer full time**, with specialists contracted for the audit and the iOS work. Halve the calendar with a team of three.

### Phase 0 — Foundations (weeks 1–2)

```bash
# Toolchain — pin it, then make the pin the default so targets attach to it
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup toolchain install "$(grep -oP 'channel = "\K[^"]+' rust-toolchain.toml)"
rustup default "$(grep -oP 'channel = "\K[^"]+' rust-toolchain.toml)"   # targets install per-toolchain
rustup target add aarch64-linux-android armv7-linux-androideabi \
                  x86_64-linux-android aarch64-apple-ios \
                  aarch64-apple-ios-sim aarch64-apple-darwin \
                  x86_64-apple-darwin x86_64-pc-windows-msvc

cargo install cargo-nextest cargo-fuzz cargo-audit cargo-deny \
              cargo-auditable cargo-mutants cargo-llvm-cov \
              cargo-vet cargo-geiger cargo-public-api cargo-ndk
```

Four practical notes an earlier draft skipped:

- `rustup target add` attaches targets to the **active** toolchain, so `rustup default` must be set first or the pinned toolchain ends up without them. Reading the version from `rust-toolchain.toml` rather than hardcoding it keeps this snippet from rotting the first time the pin advances.
- Android targets additionally need the NDK and `cargo-ndk`; `ANDROID_NDK_HOME` must be exported before any Android build.
- `x86_64-pc-windows-msvc` cannot be cross-compiled from Linux without the MSVC toolchain. Windows artifacts are built on a Windows CI runner; the target is listed so `cargo check` runs locally, not so release binaries are produced there.
- **There is no global `uniffi-bindgen` to install.** UniFFI 0.28 expects a small bindgen binary *inside the workspace* (`crates/quietwire-ffi/src/bin/uniffi-bindgen.rs`) so the generator version always matches the runtime version. Installing a global one is the most common way to ship mismatched bindings.

**Deliverables**
- Cargo workspace with all crates stubbed and CI green.
- `flake.nix` producing bit-identical builds on two different machines. Verify by comparing SHA-256 of the artifacts.
- `cargo-deny` policy: deny all crates without a permissive licence, deny unmaintained crates, deny duplicate versions of crypto dependencies.
- ADR-0001 through ADR-0012 recording every decision in §3.

**Repository and signing, before the first commit** (§19.8, §19.9). This is listed here and not later because an unsigned initial commit can only be fixed by rewriting history, which is painful the moment anyone has cloned:

```bash
# hardware signing key, then verify it actually signs before git init
ssh-keygen -t ed25519-sk -O resident -O verify-required -C "quietwire signing"
git init
git config user.name  "janpenitent"
git config user.email "janpenitent@users.noreply.github.com"
git config gpg.format ssh
git config user.signingkey ~/.ssh/id_ed25519_sk.pub
git config commit.gpgsign true
git config tag.gpgsign true
# add the key to github.com/settings/keys as BOTH an authentication key
#   and a SIGNING key — adding it only as an authentication key is the
#   single most common reason commits still show Unverified
# turn on Vigilant Mode at github.com/settings/keys
git commit -s -m "Initial commit" --allow-empty
git log --show-signature        # must print "Good \"git\" signature"
```

Then apply the repository settings and rulesets in §19.8, commit `.github/settings.yml` so the configuration is reviewable and drift-checked (`QW-C-SYS-350`), and add the REUSE headers and `LICENSES/` directory to every file from the start — retrofitting SPDX headers across a finished codebase is a day nobody enjoys.

**Exit criterion:** `nix build` on a clean machine produces a binary whose hash matches CI; `git log --pretty='%G?'` returns `G` for every commit; `reuse lint` passes; the branch rulesets are in place with administrators included.

### Phase 1 — Cryptographic core (weeks 3–8)

1. `quietwire-crypto`: key hierarchy, Argon2id parameters, HKDF labels, locked and wiped key pages, `Zeroizing` for transient buffers.
2. `quietwire-e2e`: hybrid X3DH, then the Double Ratchet.
3. Implement **every** test vector from the Signal specification. Add ML-KEM-768 vectors from NIST FIPS 203.
4. `cargo fuzz` targets for: cell parsing, ratchet header parsing, X3DH bundle parsing, GCS decoding. Run each for 24 hours minimum.
5. Property tests with `proptest`: encrypt→decrypt round-trips under arbitrary reordering, arbitrary loss, arbitrary duplication.
6. Constant-time verification with `dudect-bencher` on every secret-dependent branch.

**Exit criterion:** 100 % of Signal test vectors pass; **24 fuzz-hours per target** with zero crashes, hangs or leaks — not "72 cumulative across all targets", which an earlier draft specified and which is materially weaker than the §17 standard; no non-constant-time operation on secret data; `QW-U-CRY-046`, the meta-test proving the timing harness itself works, passes.

**AUD-1, the cryptographic design review, belongs here — at the end of this phase, around week 9.** Scheduling it only at T-12 as the §18.14 calendar implies is a planning error: the protocol is finished at week 8, and a design flaw found at week 40 invalidates every layer built on top of it. The design review runs against `PROTOCOL.md` before the packet, storage and transport layers exist. The later slot in §18.14 is for **re-review of changes**, not first contact.

### Phase 2 — Packet, storage and routing (weeks 9–14)

1. `quietwire-packet`: `Cell512` with exact byte layout from §6, padding, Poisson cover-traffic generator, exponential delay scheduler, replay cache.
2. `quietwire-store`: SQLCipher integration, field AEAD, dual-store duress logic, constant-time dual unwrap, wipe.
3. `quietwire-route`: Binary Spray-and-Wait, encounter-utility scoring (§8.2), GCS digests, cost function, energy budget.
4. `tools/sim`: a Python discrete-event simulator modelling 50–5 000 nodes with realistic mobility (Working Day Movement Model) and realistic radio ranges. Measure delivery ratio, latency distribution, overhead ratio, energy per delivered message.

**Exit criterion:** in a 500-node city simulation, **≥ 88 % delivery within 6 hours** with ≤ 8 copies per message; the two store files are statistically indistinguishable under filesystem forensics.

The figure is 88 %, not the 92 % an earlier draft carried over from the PRoPHET literature. Encounter-utility routing (§8.2) gives up destination knowledge deliberately, and published DTN results put the cost at 10–20 % of delivery ratio at a fixed deadline. Keeping a gate borrowed from a different algorithm would have meant either failing it for the right reasons or quietly relaxing it later. The number is set once, against the design actually being built, and §17.4 carries the same figure.

### Phase 3 — Transports (weeks 15–24)

Order matters — build the easiest first so the rest of the stack can be exercised.

1. **Sneakernet** (week 15). Trivially testable, and immediately proves the DTN model works.
2. **Reticulum bridge** (weeks 16–17). Instantly gives LoRa, packet radio and an existing network to test against.
3. **LoRa direct** (weeks 18–19). RNode serial protocol, duty-cycle interlock, link-layer framing.
4. **BLE desktop** (weeks 20–21) with `btleplug`, Linux and Windows first.
5. **BLE mobile** (weeks 22–23). Kotlin and Swift native layers feeding the Rust core.
6. **Wi-Fi Direct** (week 24).

**Field tests, mandatory, not optional:**
- Two RNodes at 1 km, 5 km and 15 km line of sight. Record RSSI/SNR against delivery rate for each spreading factor.
- Three-hop LoRa chain across a city.
- Ten phones in a room: measure discovery time, throughput and battery drain over 8 hours.
- A message carried on a phone from Spain to South America and delivered on arrival. **This is the acceptance test for the intercontinental requirement.**

**Exit criterion:** a message delivered end to end over each medium, and the intercontinental sneakernet test passes.

### Phase 4 — Applications (weeks 25–38)

1. `quietwire-ffi` UniFFI interface definitions; generate Kotlin, Swift and Python bindings; wire them into CI so binding drift breaks the build.
2. **Android** (weeks 26–30): Compose UI, foreground relay service, StrongBox integration, BLE/Wi-Fi Direct native layer, battery-optimisation onboarding.
3. **Desktop** (weeks 31–34): Tauri 2, Svelte 5, system tray relay mode, the `127.0.0.1` local web UI bound to loopback with an origin-locked token.
4. **iOS** (weeks 35–38): SwiftUI, Core Bluetooth central + peripheral, Secure Enclave, background modes, and an honest in-app notice about iOS relay limitations.
5. **Headless node** (parallel): a single static binary for Raspberry Pi and servers, `systemd` unit, no UI, relay only.

**Exit criterion:** the same conversation is readable and continuable across Android, iOS and desktop; a Raspberry Pi with an RNode relays between two isolated BLE islands.

### Phase 5 — Hardening and audit (weeks 39–48)

1. Internal red team: attempt the full A1–A8 list from §2.
2. **External security audit.** Run the programme in §18 — selection (§18.2), scope (§18.3), rules of engagement (§18.4) and the mandated checklists (§18.6). The schedule in §18.14 places audits at T-16 to T-0 weeks relative to release.
3. Remediate to the service levels in §18.9. Publish every report in full per §18.11.
4. Reproducible-build verification by a third party.
5. Accessibility audit and full localisation pass.

**Exit criterion:** zero unresolved High or Critical findings; the published audit report is linked from the app's About screen.

### Phase 6 — Release (weeks 49–52)

- Google Play (with a clear declaration of the foreground service and location permission rationale), F-Droid, and direct APK with published signature.
- Apple App Store. **Budget review time**: encrypted-messaging apps regularly face extra scrutiny; prepare the export-compliance documentation (§18) in advance.
- Microsoft Store, Homebrew cask, Flatpak, `.deb`, `.rpm`, AUR.
- Publish `PROTOCOL.md` as a normative specification so independent implementations are possible. A protocol only one program implements is not a protocol.

---

## 15. Hardware bill of materials

Minimum viable development set. Three items an earlier draft omitted are not optional: the attenuator kit, because `QW-E-TRN-220` specifies bench LoRa testing "with attenuators simulating path loss"; the power analyser, because `QW-N-SYS-320` through `QW-N-SYS-322` cannot be measured with platform battery statistics alone; and the shielded enclosure, because radio tests that are not isolated are not repeatable.

**The HackRF is not a spectrum analyser.** It is uncalibrated and cannot certify ERP or spurious emissions. It is bought for observation and debugging — confirming that the emission pattern looks as §9 predicts. Regulatory compliance is measured by the accredited laboratory in AUD-8, and no internal measurement substitutes for that. An earlier draft implied §17's duty-cycle test could be satisfied with this device; it cannot, and `QW-D-TRN-223` is an AUD-8 deliverable.

| Item | Qty | Unit | Total |
|---|---|---|---|
| Heltec LoRa32 V3 (SX1262, 868 MHz) for RNode | 4 | €28 | €112 |
| LilyGO T-Beam Supreme (GPS + LoRa, field testing) | 2 | €55 | €110 |
| 868 MHz antennas, 3 dBi + 5 dBi outdoor | 6 | €12 | €72 |
| Raspberry Pi 5 8 GB + PoE HAT + PSU + case + SD (fixed relay node) | 3 | €150 | €450 |
| Android test devices — oldest supported (API 26, secondhand), mid (API 33), newest (current) | 3 | €180 | €540 |
| iPhone — one current device, one capable of running the iOS 16 floor (secondhand) | 2 | €330 | €660 |
| Windows laptop | 1 | €600 | €600 |
| Mac mini M4 (required for iOS/macOS builds and signing) | 1 | €700 | €700 |
| USB SDR (HackRF One) for RF observation | 1 | €320 | €320 |
| SMA attenuator kit (10/20/30/40 dB) + 50 Ω dummy loads — required by `QW-E-TRN-220` | 1 | €90 | €90 |
| RF-shielded test enclosure (bench isolation for repeatable BLE/LoRa runs) | 1 | €280 | €280 |
| USB power analyser (Otii Arc or equivalent) — required by `QW-N-SYS-320`–`322` | 1 | €650 | €650 |
| Powered USB hub, OTG cables, SD cards, spare antennas, consumables | 1 | €180 | €180 |
| **Hardware subtotal** | | | **€4 764** |

---

## 16. Budget

| Item | Cost |
|---|---|
| Hardware (§15) | €4 764 |
| Apple Developer Program | €99 / year |
| Google Play developer account | €22 one-off |
| Microsoft Store developer account | €17 one-off |
| Windows OV/EV code-signing certificate, 3 years, **hardware token or cloud HSM** (mandatory since June 2023) | €1 200 |
| **External security audit** — single combined engagement, minimum viable posture. **The full programme in §18.14 costs €142 500 – €216 500 and is the correct figure; this line is the floor, not the target** | **€25 000 – €60 000** |
| Reproducible-build verification (independent) | €2 000 |
| Accessibility audit | €1 500 |
| Localisation, 9 languages, professional | €4 000 |
| Legal review (EU dual-use export, national crypto law) | €3 000 – €8 000 |
| Domain, signing infrastructure, CI | €600 / year |
| **Subtotal** | **€42 202 – €82 202** |
| Contingency, 20 % of subtotal | €8 440 – €16 440 |
| **Total year one** | **€50 642 – €98 642** |

The earlier draft quoted "≈ €54 000 – €95 000" against a flat €9 000 contingency. The arithmetic did not hold at either end: the low column summed to about €49 000 and the high to about €96 000. The figures above are the actual sums, with the contingency expressed as a percentage of each end rather than a single number that is wrong at both.

**This table is the minimum-viable posture and it does not fund §18.** Adding the full audit programme (§18.14, €142 500 – €216 500) in place of the single combined audit line gives a realistic year-one total of **€165 000 – €250 000** excluding salaries. Presenting the smaller figure without saying so would be the kind of quiet omission this document is supposed to avoid.

Plus engineering time: roughly **12 developer-months** for one senior generalist, or 4–5 calendar months with a team of three (one Rust/crypto, one mobile, one embedded/RF).

The audit line is not optional and is not the place to save money. An unaudited encrypted messenger is a liability, not a product.

---

## 17. Testing and verification

This is a normative section. **A release is blocked unless every gate below is green.** There are no advisory tests: a test either gates a release or it is deleted.

### 17.0 Test taxonomy and identifiers

Every test carries a stable identifier `QW-<LEVEL>-<AREA>-<NNN>` so it can be referenced from audit reports, bug tickets and the release checklist.

| Level | Code | Scope | Runs | Max duration |
|---|---|---|---|---|
| Unit | `U` | One function or type, no I/O | Every commit | < 90 s total |
| Property | `P` | Invariants over generated inputs | Every commit | < 8 min |
| Fuzz | `F` | Untrusted-input parsers | Smoke on commit, 24 h nightly, 72 h pre-release | continuous |
| Mutation | `M` | Test-suite quality | Nightly | < 6 h |
| Integration | `I` | Two or more crates together | Every commit | < 12 min |
| Deterministic simulation | `S` | Whole node under adversarial network | Every commit (seeded), nightly (random seeds) | < 25 min |
| System / E2E | `E` | Real binaries, real transports, multiple devices | Nightly + pre-release | < 2 h |
| Adversarial / red team | `X` | Threat model A1–A8 | Pre-release + quarterly | manual |
| Field | `D` | Physical radio, real distance, real people | Per phase gate, quarterly after launch | days |
| Non-functional | `N` | Performance, battery, memory, binary size | Nightly | < 90 min |
| User interface | `Y` | Screen behaviour, accessibility, localisation | Every commit | < 15 min |
| Supply chain | `C` | Build reproducibility, dependencies, provenance | Every commit + release | < 20 min |

`AREA` codes: `CRY` crypto, `E2E` session, `PKT` packet, `RTE` routing, `STO` storage, `TRN` transport, `COR` core, `FFI` bindings, `APP` application, `SYS` system-wide.

### 17.1 Coverage and quality gates

| Metric | Tool | Threshold | Applies to |
|---|---|---|---|
| Line coverage | `cargo-llvm-cov` | ≥ 95 % | `quietwire-crypto`, `-e2e`, `-packet`, `-store` |
| Line coverage | `cargo-llvm-cov` | ≥ 88 % | `-route`, `-transport`, `-core` |
| Branch coverage | `cargo-llvm-cov` | ≥ 90 % | all security crates |
| **Mutation score** | `cargo-mutants` | **≥ 92 % caught** | `-crypto`, `-e2e`, `-packet`, `-store` |
| Mutation score | `cargo-mutants` | ≥ 80 % caught | `-route`, `-core` |
| Unsafe blocks | `cargo-geiger` | 0 in security crates; each one elsewhere needs a `// SAFETY:` proof and a named reviewer | workspace |
| Panics in library code | clippy `panic`, `unwrap_used`, `expect_used` denied | 0 | all crates except tests and binaries |
| Clippy | `-D warnings -W clippy::pedantic` | 0 warnings | workspace |
| Public API drift | `cargo-public-api` | no undocumented change | `-core`, `-ffi` |
| Flaky tests | 200 consecutive nextest runs of the **new and changed** tests; 20 runs of the whole suite nightly | 0 failures | per PR / nightly |

**Mutation testing is the real gate.** High line coverage with weak assertions is the classic way a cryptographic codebase ships a hole. If `cargo-mutants` can flip a comparison operator in the ratchet and every test still passes, the tests are wrong, not the mutant.

### 17.2 Crypto — `quietwire-crypto`, `quietwire-e2e`

#### Known-answer tests (must be 100 %, no exceptions)

| ID | Test | Source of vectors |
|---|---|---|
| `QW-U-CRY-001` | X25519 scalar multiplication | RFC 7748 §5.2, all vectors, plus the 1 000 000-iteration chain |
| `QW-U-CRY-002` | X25519 rejects low-order points | RFC 7748 §6.1 + the 7 canonical small-order points |
| `QW-U-CRY-003` | Ed25519 sign/verify | RFC 8032 §7.1 |
| `QW-U-CRY-004` | Ed25519 rejects non-canonical S | Ed25519 "cofactorless" edge-case corpus (Chalkias et al.) |
| `QW-U-CRY-005` | XChaCha20-Poly1305 | RFC 8439 + draft-irtf-cfrg-xchacha vectors |
| `QW-U-CRY-006` | HKDF-SHA512 | RFC 5869 |
| `QW-U-CRY-007` | BLAKE3 and BLAKE3-keyed | official `test_vectors.json`, all 35 input lengths |
| `QW-U-CRY-008` | Argon2id | RFC 9106 §5.3 |
| `QW-U-CRY-009` | ML-KEM-768 keygen/encaps/decaps | NIST FIPS 203 ACVP vectors, all 100 |
| `QW-U-CRY-010` | ML-KEM-768 decapsulation of malformed ciphertext returns implicit-reject, never an error | FIPS 203 §7.3 |
| `QW-U-E2E-011` | X3DH agreement | Signal spec vectors, extended with our PQ leg |
| `QW-U-E2E-012` | Double Ratchet message sequence | Signal spec vectors |

#### Argon2 parameter enforcement

- `QW-U-CRY-020` — the compiled-in parameters are exactly m=262144 KiB, t=4, p=2 on mobile and m=1048576 KiB, t=4, p=2 on desktop. A test asserts the literal constants; changing them requires changing the test, which requires review.
- `QW-N-CRY-021` — derivation takes **≥ 400 ms on the fastest supported device** (so the work factor is real even on the best hardware an attacker or user has) and **≤ 3 s on the slowest supported device** (so unlocking stays usable on the oldest phone). An earlier draft had these two bounds attached to the wrong devices, which would have passed a build whose parameters had been silently weakened. Too fast on the fastest device means the parameters were reduced; too slow on the slowest means the product is unusable.

#### Constant-time verification

`QW-U-CRY-030` … `QW-U-CRY-045`, one per secret-dependent operation:

- Method: `dudect-bencher` with 10⁷ measurements per operation, Welch's t-test, **|t| < 4.5 required**.
- Also compiled under `valgrind --tool=memcheck` with `ctgrind` annotations marking secrets as uninitialised, so any branch or memory index on a secret is reported.
- Covered operations: AEAD tag comparison, epoch-tag map lookup, duress DEK unwrap, password verification, skipped-key lookup, safety-number comparison, and every `PartialEq` on a secret type.
- `QW-U-CRY-046` — a deliberate mutant (replace `subtle::ConstantTimeEq` with `==`) **must** make this suite fail. If it does not, the timing harness itself is broken. This meta-test runs in CI.

#### Memory hygiene

- `QW-U-CRY-050` — after `drop`, every secret buffer is all-zero. Verified by reading back the raw allocation through a custom test allocator.
- `QW-U-CRY-051` — no secret type implements `Debug`, `Display`, `Serialize` or `Clone` without an explicit audited opt-in. Enforced by a compile-fail test with `trybuild`.
- `QW-U-CRY-052` — a full core dump of an unlocked process, grepped for known test key material, yields hits only inside `mlock`ed regions; after lock, zero hits.
- `QW-U-CRY-053` — Miri run over the whole crypto crate: no undefined behaviour, no uninitialised reads.

#### Property tests

| ID | Property |
|---|---|
| `QW-P-E2E-060` | For any message sequence and any permutation of delivery order, every message decrypts exactly once to the correct plaintext |
| `QW-P-E2E-061` | For any subset of dropped messages, subsequent messages still decrypt (skipped-key handling) |
| `QW-P-E2E-062` | Duplicated ciphertext decrypts once and is rejected thereafter |
| `QW-P-E2E-063` | Any single-bit flip anywhere in a ciphertext causes authentication failure and **no** plaintext output |
| `QW-P-E2E-064` | After a simulated full state compromise at time *t*, messages before *t* remain undecryptable with the compromised state (forward secrecy) |
| `QW-P-E2E-065` | After a compromise at *t*, one completed DH ratchet round trip makes subsequent messages undecryptable by the attacker (post-compromise security) |
| `QW-P-E2E-066` | Two independent sessions between the same pair never derive the same message key |
| `QW-P-E2E-067` | Skipped-key store never exceeds 1 000 per chain / 10 000 total, and eviction is oldest-first |
| `QW-P-E2E-068` | Sending is refused after 2 000 messages without a DH ratchet |
| `QW-P-E2E-068b` | Given a full device compromise at epoch *e*, tags are derivable only for epochs *e−2* to *e+2*; those from *e−3* and earlier are unreachable from the seized state (§5.5 tag ratchet) |
| `QW-P-CRY-069` | `unwrap(wrap(k)) == k` for all key types, and `unwrap` with a wrong KEK always fails |

#### Formal verification

- `QW-X-E2E-070` — the hybrid X3DH handshake is modelled in **ProVerif** and independently in **Verifpal**. Both must prove: secrecy of `SK`, mutual authentication, forward secrecy, and resistance to unknown-key-share. Models live in `docs/formal/` and are re-checked in CI.
- `QW-X-E2E-071` — the Noise `XX` usage is checked against the **Noise Explorer** generated model for the exact pattern and cipher suite in use.
- `QW-X-E2E-072` — a **Tamarin** model of the epoch-tag mechanism proves that an observer without `SK_session` cannot link two tags from different epochs to the same session.

#### Fuzzing

| ID | Target | Corpus seed | Pre-release budget |
|---|---|---|---|
| `QW-F-CRY-080` | Prekey-bundle parser | valid bundles + mutations | 72 h |
| `QW-F-E2E-081` | Ratchet header parser | captured headers | 72 h |
| `QW-F-E2E-082` | Full inbound-message state machine (stateful fuzzing with `arbitrary`-driven action sequences) | recorded sessions | 72 h |
| `QW-F-CRY-083` | Safety-number renderer | random identities | 24 h |

All targets run with ASan, UBSan and LeakSanitizer. Coverage-guided corpus is committed and grows monotonically. **Any crash, hang > 1 s, or OOM is a release blocker**, regardless of exploitability assessment.

### 17.3 Packet layer — `quietwire-packet`

| ID | Test | Assertion |
|---|---|---|
| `QW-U-PKT-100` | Cell size | `serialize(cell).len() == 512` for **every** possible content type and body length, including 0 and 365 |
| `QW-U-PKT-101` | Byte layout | Each field occupies exactly the offsets in §6.1. Asserted against a hand-written hex fixture, not against the serializer itself |
| `QW-U-PKT-102` | Reserved bits | Bits 3–7 of `flags` are uniformly random across 10⁶ generated cells (chi-squared, p > 0.01) |
| `QW-U-PKT-102b` | **No meaning in cleartext flags** | A structural test asserts that no code reads or writes a semantic value in the `flags` byte; all 8 bits are drawn from the CSPRNG. Protects the §6.1 correction from regressing |
| `QW-U-PKT-103` | Padding | Padding bytes are uniformly random, never zeros, never a repeating pattern (chi-squared + serial correlation) |
| `QW-U-PKT-104` | Decoy indistinguishability | Given 10 000 real and 10 000 decoy cells, a gradient-boosted classifier trained on the raw bytes achieves accuracy in [0.49, 0.51] |
| `QW-U-PKT-105` | TTL decrement | Relaying decrements exactly 1; a cell at TTL 0 is dropped, never forwarded |
| `QW-U-PKT-106` | Mutable fields excluded from E2E MAC | Altering `ttl`/`copies` does not break E2E authentication, but does break the hop-to-hop Noise MAC |
| `QW-P-PKT-107` | Replay cache | No message ID is accepted twice within the 24 h window, across 10⁶ generated IDs, under arbitrary interleaving |
| `QW-P-PKT-108` | Replay cache bounds | Memory stays under the configured cap under adversarial ID flooding |
| `QW-U-PKT-109` | **Tag uniqueness and directionality** | Over 10⁶ generated cells no tag repeats; the A→B and B→A tag streams for one session share no value; a tag stream is indistinguishable from random by the NIST SP 800-22 suite |
| `QW-U-PKT-109b` | Tag window resynchronisation | After an arbitrary loss burst up to 10⁴ cells, the resynchronisation path in §5.5 restores matching within 9 cells, and the resync cell is byte-indistinguishable from any other |
| `QW-U-PKT-110` | Cover-traffic distribution | Inter-emission gaps over a 24 h simulated run fit Exponential(λ=1/90 s); Kolmogorov–Smirnov p > 0.05 |
| `QW-U-PKT-111` | **Emission indistinguishability (BLE / Wi-Fi only)** | The emission time series for a silent node and a node sending 200 messages/day are statistically indistinguishable: KS test p > 0.05 **and** a classifier on inter-arrival features gets ≤ 0.52 accuracy. **Not asserted on LoRa**, where §9 disables cover traffic; `QW-U-PKT-111b` instead asserts that no cover cell is ever generated on a LoRa transport |
| `QW-U-PKT-111b` | No cover traffic on LoRa | Over a 7-day simulated run with a LoRa transport active, the count of generated decoy cells is exactly zero, and the duty-cycle ledger never exceeds 1 % in any rolling hour (§7.3, §9) |
| `QW-U-PKT-112` | Forwarding delay | Delays fit Exponential(mean 4 s); no correlation between ingress order and egress order (Spearman \|ρ\| < 0.05) |
| `QW-U-PKT-113` | Batch shuffling | Batches of 16 are uniformly permuted (frequency test over 10⁵ batches) |
| `QW-F-PKT-114` | Cell parser fuzz | 72 h, zero crashes on arbitrary 0–4096 byte inputs |
| `QW-F-PKT-115` | Fragment reassembler fuzz | 72 h, including overlapping, duplicated, out-of-range and contradictory fragment indices |
| `QW-U-PKT-115b` | Reassembly caps | Under a hostile peer emitting endless fragment-40 000-of-nothing cells, incomplete sets never exceed 64 per contact, 8 MB total, or 6 hours of age; the sweep uses the eviction index and never full-scans (§10.2) |
| `QW-U-E2E-117` | Four-cell session init | A `session_init` set is exactly 4 cells; 3 is rejected as incomplete; partial, reordered and cross-handshake fragment mixes never produce a session |
| `QW-U-PKT-116` | Reassembly hostility | A malicious sender cannot cause unbounded memory growth, index-out-of-bounds, or reassembly of fragments from different messages |

### 17.4 Routing — `quietwire-route`

| ID | Test | Gate |
|---|---|---|
| `QW-U-RTE-130` | Binary Spray-and-Wait split | Node with *n* copies gives `floor(n/2)`, keeps `ceil(n/2)`; total copies in the network is **never** > 8 across 10⁵ random encounter sequences |
| `QW-U-RTE-131` | Wait mode | A node with 1 copy forwards only to the destination |
| `QW-U-RTE-132` | Encounter-utility scoring | `U(peer)` matches §8.2 to 1e-9 for 10⁴ random encounter histories; output is always in [0, 1] |
| `QW-U-RTE-133` | Utility aging | The EWMA decays monotonically, never leaves [0, 1], and survives a 1-year gap and backwards clock jumps |
| `QW-U-RTE-134` | Hostile self-reporting | Caps hold: no peer can raise its own utility above the ceiling by lying about degree or mobility; `relay_reliability` cannot be self-asserted at all |
| `QW-U-RTE-134b` | **No destination state exists** | A structural test asserts that no routing table, index or cache anywhere in the workspace is keyed on a destination identifier or cell tag. This is the test that keeps §8.2's guarantee from silently regressing |
| `QW-U-RTE-135` | GCS digest | False-positive rate ≤ 1 % measured over 10⁶ queries; encoded size ≤ 1.2 kB for 1 000 entries; never a false negative |
| `QW-F-RTE-136` | GCS decoder fuzz | 72 h on arbitrary bytes, zero crashes, zero unbounded allocation |
| `QW-U-RTE-137` | Cost function | Monotone in each input; the ordering of the transport table in §8.3 is preserved for all inputs |
| `QW-U-RTE-138` | Duty-cycle interlock | Under an adversarial send schedule, LoRa airtime never exceeds 1 % in any rolling 60-minute window. Asserted over 10⁵ randomised schedules |
| `QW-U-RTE-139` | Region gating | Transmission on a frequency not permitted for the configured region is impossible; the API returns an error, and a compile-fail test prevents bypassing the gate |
| `QW-U-RTE-140` | Cache eviction | LRU by `age × (1/copies)`; cache never exceeds the configured byte cap under flooding |
| `QW-U-RTE-141` | Age limit | A cell older than the max age is dropped and never forwarded |

#### Simulation gates — `quietwire-sim`

Deterministic, seeded, reproducible. Every failure produces a seed that replays the exact scenario.

| ID | Scenario | Gate |
|---|---|---|
| `QW-S-RTE-150` | 500 nodes, Working Day Movement Model, 24 h | **≥ 88 %** delivery within 6 h; overhead ≤ 8 copies/message (re-baselined for encounter-utility routing, §8.2) |
| `QW-S-RTE-151` | 50 nodes, sparse rural, 72 h | ≥ 82 % delivery within 48 h |
| `QW-S-RTE-152` | 5 000 nodes, dense urban | No node exceeds its memory or energy budget; delivery **≥ 86 %** in 6 h |
| `QW-S-RTE-153` | Network partition for 12 h then reconnect | 100 % of queued messages delivered after reconnection, zero duplicates surfaced to the user |
| `QW-S-RTE-154` | 30 % of nodes are pure leeches (accept, never relay) | Delivery ratio degrades by ≤ 12 % |
| `QW-S-RTE-155` | Sybil: 200 fake nodes injected | Delivery ratio degrades by ≤ 15 %; honest nodes' copy budgets are not exhausted |
| `QW-S-RTE-156` | Black hole: 10 % of nodes silently drop everything | Delivery ≥ 80 % |
| `QW-S-RTE-157` | Clock skew ±2 h across nodes, plus 5 % of nodes with clocks off by 30 days | Epoch-tag matching still succeeds within the ±2 h window; no session breakage |
| `QW-S-RTE-158` | Adversary replays every cell it sees, 100× | Zero duplicate delivery; memory bounded |
| `QW-S-RTE-159` | Byzantine relay forging TTL/copies | Damage confined to that relay's neighbours; network-wide copy count still bounded |
| `QW-S-SYS-160` | Chaos: random node crashes, disk-full, power loss mid-write, at 1 000 randomised injection points | No corruption; every restart yields a consistent store |
| `QW-S-SYS-161` | Power loss during DEK rewrap, every byte offset | Either the old or the new wrapped DEK is valid. **Never both invalid.** 100 % of offsets tested exhaustively |

### 17.5 Storage — `quietwire-store`

| ID | Test | Gate |
|---|---|---|
| `QW-U-STO-170` | Entropy of the database file | Shannon entropy > 7.98 bits/byte; NIST SP 800-22 suite passes; `file(1)` cannot identify the format |
| `QW-U-STO-171` | No plaintext anywhere | A 200 MB store containing 10 000 known-plaintext messages is grepped for every plaintext token. **Zero hits.** Also checked in WAL, journal, temp files, and the OS swap file |
| `QW-U-STO-172` | Field AEAD AAD binding | Moving a ciphertext blob to a different row or column makes decryption fail |
| `QW-U-STO-173` | Schema leaks nothing | Row counts, index sizes and page counts are identical between a store with 1 000 messages and a decoy store padded to the same profile |
| `QW-U-STO-174` | **Duress indistinguishability** | Two store files always exist, written on the same schedule. Given two device images, one where the user set a duress password and one where they did not, an evaluator with full filesystem access and the source code cannot distinguish them by file size, page count, modification time, growth pattern or entropy. Formalised as: byte-level entropy, file sizes, page counts, timestamps and row counts all within noise. **Independently re-tested by the external auditor (`QW-X-STO-174b`)** |
| `QW-U-STO-175` | Constant-time dual unwrap | Unlock timing for correct-real, correct-duress and wrong password is indistinguishable: dudect \|t\| < 4.5 over 10⁶ trials |
| `QW-U-STO-176` | Store isolation | While one store file is open, no code path can obtain a handle to the other. Enforced at the type level — the handle does not exist in that process state — and verified by a test that attempts every public API method from each context |
| `QW-U-STO-176b` | Wipe destroys both slots | After a fail-counter wipe, **neither** password opens anything, and the device is byte-indistinguishable from a fresh install. An earlier design wiped only one slot, which proved a second had existed |
| `QW-U-STO-177` | Wipe on failure | After N failures, the wrapped DEK, salt and all tables are unrecoverable. Verified by attempting decryption with the correct password afterwards: must fail |
| `QW-U-STO-178` | Wipe atomicity | Power loss at any point during a wipe leaves the store unrecoverable, never partially readable. All byte offsets tested |
| `QW-U-STO-179` | Backoff | Failure *n* delays by `min(2^n, 300)` seconds; the counter survives process restart, app reinstall (where the OS permits) and clock manipulation |
| `QW-U-STO-179b` | Biometric never opens from cold | With hardware sealing enabled, the password is still required after boot, after any fail-counter increment, and after 24 h without one. Asserted on Android and iOS against the real keystore |
| `QW-U-STO-180` | Lock on background | DEK is zeroized within the configured grace period; verified by core-dump inspection |
| `QW-U-STO-181` | Send requires unlock | Every send path returns `Locked` when the DEK is absent. Tested by calling all 47 public API methods in the locked state |
| `QW-U-STO-182` | Migration | Every schema version *n* → *n+1* migration is tested with a fixture database, forwards and (where supported) backwards; a failed migration never destroys data |
| `QW-P-STO-183` | Crash consistency | Under `madsim`-injected crashes at arbitrary points, the store always reopens consistently across 10⁴ seeds |
| `QW-N-STO-184` | Scale | 1 000 000 messages: conversation open < 150 ms, search < 500 ms, database < 900 MB |
| `QW-N-STO-184b` | Unlock latency | **< 4 s end to end on the slowest supported device**, of which up to 3 s is Argon2id by design. An earlier draft demanded "< 2 s", which is arithmetically impossible alongside `QW-N-CRY-021` and would have forced someone to weaken the KDF to pass a performance gate — exactly the failure mode that gate exists to prevent |

### 17.6 Transports — `quietwire-transport`

| ID | Test | Gate |
|---|---|---|
| `QW-U-TRN-200` | Trait conformance suite | A single generic test battery runs against **every** adapter. Adding a transport without passing it is a compile error |
| `QW-I-TRN-201` | Loopback adapter | Full stack A→B over an in-process transport; 10⁶ messages, zero loss, zero corruption |
| `QW-I-TRN-202` | Lossy adapter | 50 % packet loss, 30 % duplication, 2 s jitter, reordering: all messages eventually delivered exactly once |
| `QW-I-TRN-203` | Noise XX handshake | Interop against the `snow` reference and against a second independent Noise implementation |
| `QW-X-TRN-204` | MITM on the link | An attacker relaying and modifying the Noise stream is always detected; no plaintext ever emitted |
| `QW-E-TRN-210` | BLE — Linux ↔ Linux, Android ↔ Android, Android ↔ Linux, iOS ↔ Android, iOS ↔ iOS | Discovery < 30 s; a message crosses each pair |
| `QW-E-TRN-211` | BLE — L2CAP fallback to GATT | Forced downgrade still delivers |
| `QW-E-TRN-212` | BLE — 10 devices, one room, 8 h | No crashes, no connection leaks, discovery time stays < 60 s |
| `QW-E-TRN-213` | BLE — UUID rotation | The advertised service UUID changes daily; two captures 48 h apart cannot be linked to the same device by UUID |
| `QW-E-TRN-214` | Wi-Fi Direct bulk sync | 1 000 cells transferred in < 60 s |
| `QW-E-TRN-220` | LoRa — bench, SF7 through SF12 | Every cell delivered at 0 m with attenuators simulating path loss |
| `QW-D-TRN-221` | LoRa — field at 1 km, 5 km, 15 km line of sight | RSSI/SNR vs delivery curve recorded for each SF; ≥ 95 % delivery at the rated range for the chosen SF |
| `QW-D-TRN-222` | LoRa — 3-hop city chain | End-to-end delivery < 10 min |
| `QW-D-TRN-223` | **Duty cycle measured on-air** with a spectrum analyser | ≤ 1 % in any rolling hour. This is a legal requirement, measured physically, not merely asserted in software |
| `QW-D-TRN-224` | Out-of-band emissions, ERP | Within ETSI EN 300 220 limits, measured with the HackRF and a calibrated attenuator |
| `QW-I-TRN-230` | Reticulum bridge | A QUIETWIRE cell survives a round trip through a Reticulum network unmodified; our E2E layer is never stripped |
| `QW-I-TRN-231` | Reticulum interop | A community LXMF propagation node relays our traffic without being able to decrypt it. Verified by instrumenting the node |
| `QW-I-TRN-240` | Sneakernet bundle | Export → import round trip preserves everything; a truncated or corrupted bundle is rejected, never partially applied |
| `QW-I-TRN-241` | Animated QR / RaptorQ | Payload recovers from any 60 % random subset of frames, over 10⁴ random subsets |
| `QW-E-TRN-242` | Printed paper message | Scanned from paper under 200 lux, 500 lux and 1 000 lux, at 15°, 30° and 45° angles, with a 5-year-old mid-range phone camera. ≥ 95 % first-attempt success |
| `QW-E-TRN-243` | NFC contact exchange | Round trip on 3 Android SKUs and iPhone |

### 17.7 Bindings and applications

| ID | Test | Gate |
|---|---|---|
| `QW-U-FFI-250` | Binding drift | Generated Kotlin/Swift/Python bindings are byte-identical to the committed ones. A drift breaks CI |
| `QW-I-FFI-251` | Round-trip through each binding | Every public type survives Rust → Kotlin → Rust, Rust → Swift → Rust, Rust → Python → Rust unchanged, including all error variants |
| `QW-I-FFI-252` | Panic safety | A panic in Rust surfaces as a typed error in Kotlin/Swift, never as a process abort |
| `QW-I-FFI-253` | Secret lifetime across the boundary | No secret is ever copied into a managed-language heap. Verified by heap dump inspection on Android and iOS |
| `QW-Y-APP-260` | Unlock screen | Exactly one input and one button; no "forgot password" affordance exists anywhere in the view hierarchy (asserted, not eyeballed) |
| `QW-Y-APP-261` | Status dot semantics | Each of the four states renders the specified colour and the specified sentence, in all 9 languages |
| `QW-Y-APP-262` | Screenshot tests | Paparazzi (Android), swift-snapshot-testing (iOS), Playwright (desktop/local web) across light/dark, 5 font scales, 4 screen widths. Any pixel diff blocks merge until reviewed |
| `QW-Y-APP-263` | **Accessibility** | Every interactive element has a content description; contrast ≥ 4.5:1 measured programmatically; touch targets ≥ 48 dp on Android and ≥ 44 pt on iOS; full TalkBack and VoiceOver walkthrough of all three screens with zero traps |
| `QW-Y-APP-264` | Pseudo-localisation | With strings expanded 40 % and wrapped in accents, no truncation, no clipping, no overlap on any screen |
| `QW-Y-APP-265` | RTL | Arabic and Farsi layouts mirror correctly; no hardcoded left/right |
| `QW-Y-APP-266` | No jargon | A lint over all user-facing strings rejects a banned-word list: "hop", "node", "mesh", "packet", "TTL", "ratchet", "AEAD", "epoch", outside the Advanced screen |
| `QW-Y-APP-267` | Screenshot/recording protection | `FLAG_SECURE` on Android; the iOS app blurs on backgrounding. Verified by attempting a screenshot in an instrumented test |
| `QW-Y-APP-268` | Notification leakage | Message content never appears in a notification, on the lock screen, in the app switcher, or in system logs. Asserted by scanning logcat and the recents thumbnail |
| `QW-E-APP-270` | Cross-platform conversation | The same conversation is continued across Android → iOS → desktop; ratchet state stays consistent |
| `QW-E-APP-271` | Onboarding | A first-time user, given only the app, completes install → password → contact scan → first message in < 3 minutes, unaided. **Measured with 10 non-technical testers; ≥ 8 must succeed** |
| `QW-E-APP-272` | Duress usability | 5 testers set up a duress password and, under simulated pressure, open the decoy store without visible hesitation |

### 17.8 Adversarial suite — mapped to the threat model

Each row of §2 gets an executable test, plus a manual red-team exercise before each release.

| ID | Threat | Test |
|---|---|---|
| `QW-X-SYS-300` | **A1** Passive relay | Instrumented relay logs everything it handles for 72 h in a 20-node mesh. Assert: zero plaintext, zero stable identifier, zero ability to count how many distinct conversations passed through it |
| `QW-X-SYS-301` | **A2** Active relay | A relay that modifies, drops, reorders, replays and injects. Assert: modified cells are rejected; dropped cells are recovered by other copies; injected cells never decrypt; the user-visible outcome is correct |
| `QW-X-SYS-302` | **A3** Global passive observer | Full radio capture of a 20-node mesh for 24 h. An analyst with the capture, the source code, and the protocol spec — but no keys — must fail to determine: who sent anything, who received anything, how many real messages existed (±50 %), or when any user was active. Scored as a formal exercise with a written report |
| `QW-X-SYS-303` | **A4** Sybil | 200 attacker nodes vs 100 honest. Gate as in `QW-S-RTE-155`, re-run against the real binaries |
| `QW-X-SYS-304` | **A5** Device seizure | A powered-off device is imaged and handed to an independent forensic examiner with commercial tooling (Cellebrite-class) and unlimited time. Assert: zero message content, zero contact names, zero conversation count recovered |
| `QW-X-SYS-305` | **A6** Coercion | The examiner is additionally given the duress password. Assert: they obtain the decoy store and cannot demonstrate that a second store exists |
| `QW-X-SYS-306` | **A7** Harvest-now-decrypt-later | Simulated total break of X25519 (attacker is given all X25519 private keys). Assert: sessions remain secure via the ML-KEM leg. Then the reverse: total break of ML-KEM, secure via X25519 |
| `QW-X-SYS-307` | **A8** MITM at enrollment | An attacker substitutes their own prekey bundle during remote enrollment. Assert: safety numbers differ, the UNVERIFIED banner appears, and no automatic trust is granted |
| `QW-X-SYS-308` | Malicious peer input | A peer sends every malformed structure the fuzzer found, plus 10⁶ random cells. Assert: no crash, no memory growth beyond the cap, no state corruption |
| `QW-X-SYS-309` | Resource exhaustion | A peer attempts to fill the relay cache, the skipped-key store and the replay cache simultaneously. Assert: all stay within caps; the device remains usable |
| `QW-X-SYS-310` | Downgrade | An attacker attempts to force a non-PQ handshake, a weaker cipher, or an older protocol version. Assert: refused. There is no negotiation path to a weaker suite |
| `QW-X-SYS-311` | Clock attack | Time set forward 10 years, back 10 years, and oscillating. Assert: no key reuse, no session break, no silent acceptance of expired material |
| `QW-X-SYS-312` | Side channel on mobile | Power and EM traces during unlock on a reference Android device. Assert: no key-dependent signal detectable in 10⁴ traces |

### 17.9 Non-functional gates

| ID | Metric | Gate | Measured on |
|---|---|---|---|
| `QW-N-SYS-320` | Battery, Balanced mode | ≤ 6 % / 24 h | 3 Android SKUs, Batterystats, 24 h soak, 3 runs |
| `QW-N-SYS-321` | Battery, Saver mode | ≤ 2.5 % / 24 h | same |
| `QW-N-SYS-322` | Battery, Maximum reach | ≤ 18 % / 24 h | same |
| `QW-N-SYS-323` | RAM, idle relay | ≤ 90 MB RSS | Android API 26 reference device |
| `QW-N-SYS-324` | Memory growth | < 1 % RSS growth over a 7-day soak | headless node on RPi |
| `QW-N-SYS-325` | Cold start to unlock prompt | ≤ 800 ms | Android API 26 |
| `QW-N-SYS-326` | Send latency, local BLE | ≤ 2 s, p95 | field |
| `QW-N-SYS-327` | Cells processed | ≥ 400 cells/s | reference mobile CPU |
| `QW-N-SYS-328` | Binary size | Android APK ≤ 28 MB; desktop ≤ 20 MB | release build |
| `QW-N-SYS-329` | Benchmark regression | No crypto or packet benchmark regresses > 5 % vs the previous release | `criterion`, CI-tracked |

### 17.10 Supply chain

| ID | Test | Gate |
|---|---|---|
| `QW-C-SYS-340` | Reproducible build | Two independent machines, different OS, produce bit-identical artifacts. Compared by SHA-256 and by `diffoscope` when they differ |
| `QW-C-SYS-341` | Third-party reproduction | An external party reproduces the release from source and publishes a matching hash **before** the release is announced |
| `QW-C-SYS-342` | `cargo audit` | Zero known vulnerabilities |
| `QW-C-SYS-343` | `cargo deny` | No non-permissive licence, no unmaintained crate, no duplicate versions of any crypto dependency |
| `QW-C-SYS-344` | `cargo vet` | Every dependency in the security crates is audited or delegated to a trusted audit set |
| `QW-C-SYS-345` | SBOM | CycloneDX SBOM generated and signed for every release |
| `QW-C-SYS-346` | Provenance | SLSA level 3 attestation published |
| `QW-C-SYS-347` | Dependency diff review | Any new transitive dependency in a security crate requires named human sign-off recorded in the PR |
| `QW-C-SYS-348` | Signature verification | The published APK, `.dmg`, `.msi` and `.deb` verify against the published signing keys; key fingerprints are published in three independent places |
| `QW-C-SYS-349` | REUSE compliance | `reuse lint` passes; every file has SPDX headers and all licence texts are in `LICENSES/` |
| `QW-C-SYS-350` | Repository configuration | The rulesets, merge strategies and settings in §19.8 match the committed `.github/settings.yml`; drift fails the build |
| `QW-C-SYS-351` | **Whole-history signature walk** | `git log --pretty='%G?'` returns `G` or `U` for **every** commit reachable from `main` and from every `release/*` branch. One unsigned commit anywhere fails the release |
| `QW-C-SYS-352` | Signed tags | The release workflow refuses to run on a tag that fails `git verify-tag` |
| `QW-C-SYS-353` | DCO | Every commit carries a `Signed-off-by` line whose email matches the verified signing identity |

### 17.11 Continuous integration pipeline

```
on: push
  ├─ stage 1  (~4 min)   fmt · clippy -D warnings · cargo deny · cargo audit
  ├─ stage 2  (~9 min)   cargo nextest (unit + property + integration)
  ├─ stage 3  (~6 min)   KAT suite · trybuild compile-fail · Miri on crypto crates
  ├─ stage 4  (~12 min)  deterministic simulation, 200 fixed seeds
  ├─ stage 5  (~5 min)   fuzz smoke, 60 s per target
  ├─ stage 6  (~15 min)  UI tests + screenshot diffs, all platforms
  ├─ stage 7  (~8 min)   llvm-cov, coverage gates enforced
  └─ stage 8  (~18 min)  reproducible-build check on two runners
                          — merge queue only, not every push: 18 minutes on
                            every commit to a branch would make the check the
                            thing people learn to route around

on: nightly
  ├─ fuzz 24 h per target
  ├─ cargo-mutants full workspace
  ├─ simulation with 5 000 random seeds
  ├─ 24 h battery soak on the device farm
  └─ 7-day memory soak (rolling)

on: release-candidate
  ├─ fuzz 72 h per target
  ├─ full adversarial suite QW-X-*
  ├─ field tests QW-D-*
  ├─ external reproduction
  └─ manual release checklist (§17.13)
```

**Flaky-test policy:** a test that fails intermittently is either fixed within 48 hours or deleted. It is never retried, never marked "allowed to fail", and never quarantined indefinitely. A test that cannot be trusted is worse than no test, because it trains the team to ignore red.

### 17.12 Test data discipline

- **No real key material in the repository, ever.** All fixtures use keys generated from a fixed seed and marked `TEST_ONLY_` in the type name.
- A pre-commit hook plus a CI scan (`gitleaks` + a custom entropy scanner) blocks any commit containing a high-entropy blob outside `tests/fixtures/`.
- Test vectors from external specifications are committed verbatim with their source URL and a SHA-256 of the original file, so a tampered vector set is detectable.
- The fuzzing corpus is committed and grows monotonically; corpus entries are never deleted, only minimised.

### 17.13 Release acceptance checklist

A build ships only when **every** line is signed off by a named person:

- [ ] All `QW-U-*`, `QW-P-*`, `QW-I-*` green; zero skipped
- [ ] Coverage and mutation gates met (§17.1)
- [ ] 72 h fuzz per target: zero crashes, zero hangs, zero leaks
- [ ] Constant-time suite passes, **including** the meta-test `QW-U-CRY-046`
- [ ] Formal models re-verified; no proof regressions
- [ ] All simulation gates `QW-S-*` met
- [ ] Full adversarial suite `QW-X-*` executed, with written findings
- [ ] Forensic examination `QW-X-SYS-304/305` performed by an independent party this cycle
- [ ] Field tests `QW-D-*` executed for every medium
- [ ] On-air duty cycle and ERP measured and within legal limits
- [ ] Non-functional gates `QW-N-*` met; no benchmark regression > 5 %
- [ ] Accessibility audit passed; all 9 languages checked for truncation
- [ ] Reproducible build confirmed by an independent third party
- [ ] SBOM and SLSA attestation published and signed
- [ ] External audit report published; **zero unresolved High or Critical findings**
- [ ] `PROTOCOL.md` updated and matching the implementation (verified by the KAT suite being generated from the spec, not from the code)
- [ ] Changelog names every security-relevant change

### 17.14 Post-launch

- **Quarterly:** re-run the full adversarial suite and the field tests. Threat models rot.
- **Annually:** a fresh external audit, with a different firm from the previous year. Rotating auditors catches what a familiar reviewer stops seeing.
- **Continuously:** a public security contact, a published disclosure policy with a 90-day timeline, and a bug bounty (suggested scale: €500 low, €2 000 medium, €8 000 high, €25 000 critical for a practical break of the E2E layer or the at-rest encryption).
- **Every release:** publish the test report alongside the binary. A security claim without published evidence is marketing.

---

## 18. Security audit programme

The test suite in §17 proves the system does what we believe it does. **The audit exists to find out whether what we believe is wrong.** These are different activities and neither substitutes for the other.

This section is a normative, executable audit programme: who audits, what they are given, what they must look at, item by item, how findings are scored, how fast they must be fixed, and what blocks a release. It is written so that an external firm can be handed §18 as the statement of work with no further negotiation.

### 18.0 Governing principles

1. **Adversarial, not confirmatory.** The auditor is paid to break the system, not to certify it. A report with no findings is treated as evidence of an inadequate audit, not of a perfect product, and triggers a scope review.
2. **Full disclosure to the auditor.** Source, design documents, threat model, test suite, previous audit reports, known weaknesses, internal disagreements, and the list of things the team is worried about. Withholding anything corrupts the result.
3. **Publication is non-negotiable.** Every report is published in full, including findings that were not fixed. The contract says so before it is signed. An auditor who requires the right to suppress the report is not engaged.
4. **Auditor rotation.** No firm performs two consecutive annual audits. Familiarity breeds blind spots, and a second pair of eyes finds what the first stopped seeing.
5. **No self-certification.** The team never audits its own work and calls it an audit. Internal review (§18.12) is a control, not an audit.
6. **Findings are public even when embarrassing.** Especially when embarrassing.

### 18.1 Audit types and cadence

| # | Audit | Performed by | Cadence | Duration | Blocks release |
|---|---|---|---|---|---|
| AUD-1 | **Cryptographic design review** | Academic cryptographer or specialist firm | Once before v1.0, then on any protocol change | 2–3 weeks | Yes |
| AUD-2 | **Cryptographic implementation review** | Security firm, crypto specialism | Annual + on any change to `-crypto`/`-e2e` | 3–4 weeks | Yes |
| AUD-3 | **Application and platform security review** | Security firm, mobile specialism | Annual | 3–4 weeks | Yes |
| AUD-4 | **Formal verification review** | Formal-methods specialist | Once before v1.0, re-checked on protocol change | 2 weeks | Yes |
| AUD-5 | **Forensic / anti-forensic evaluation** | Digital forensics lab | Annual | 1–2 weeks | Yes |
| AUD-6 | **Red team, full scope** | Offensive security firm | Annual | 2 weeks | Yes |
| AUD-7 | **Supply chain and build integrity audit** | Independent reproducer + firm | Every release | 3 days | Yes |
| AUD-8 | **RF and regulatory compliance** | Accredited EMC/radio test house | Once per hardware profile, re-test on firmware change | 1 week | Yes (for LoRa builds) |
| AUD-9 | **Privacy and data-protection review** | Privacy counsel | Once before v1.0, then on any data-handling change | 1 week | Yes |
| AUD-10 | **Export control and crypto-law review** | Trade/tech counsel | Once before v1.0, annual refresh | 1–2 weeks | Yes |
| AUD-11 | **Accessibility audit** | Accessibility specialist | Once before v1.0, annual | 1 week | Yes |
| AUD-12 | **Internal continuous audit** | Engineering team, four-eyes | Every commit | continuous | Yes |
| AUD-13 | **Bug bounty** | The public | Continuous after v1.0 | — | No |

### 18.2 Auditor selection and qualification

**Mandatory qualification criteria.** A firm is eligible only if it can evidence all of:

| ID | Criterion |
|---|---|
| `QUAL-01` | At least three published audits of end-to-end encrypted messaging or comparable cryptographic systems, publicly available and readable |
| `QUAL-02` | Demonstrated Rust expertise, specifically `unsafe` review and side-channel analysis in Rust |
| `QUAL-03` | Named individual reviewers, with CVs, assigned before contract signature — not "a team will be allocated" |
| `QUAL-04` | Willingness to contract for full public disclosure of the report, unredacted except for live unfixed critical findings during the embargo window |
| `QUAL-05` | No commercial relationship with the project, its funders, or any dependency vendor. Declared in writing |
| `QUAL-06` | Capacity to perform on-device analysis on Android and iOS, including runtime instrumentation |
| `QUAL-07` | Willingness to be named in the published report |

**Candidate pool** (illustrative, all meeting the criteria at time of writing): Cure53, Trail of Bits, NCC Group Cryptography Services, Radically Open Security, Quarkslab, Least Authority, Kudelski Security, Include Security. AUD-1 and AUD-4 may alternatively go to an academic group (e.g. a university applied-cryptography chair) under a consultancy contract.

**Selection process**

1. Issue §18 as the RFP. Request: named reviewers, day rate, effort allocation per area from §18.3, two reference audits, and conflict-of-interest declaration.
2. Score bids on: relevance of prior work (40 %), named reviewer seniority (30 %), proposed methodology depth (20 %), price (10 %). **Price is deliberately the smallest weight.**
3. Reject any bid that proposes fewer than 50 % of person-days on manual review versus tooling.
4. Contract, with §18.4 and §18.5 annexed verbatim.

**Rotation register.** A file `docs/AUDIT/ROTATION.md` records which firm did which audit in which year. A firm may not be selected if it performed the same audit type in the immediately preceding cycle.

### 18.3 Scope

**In scope, with mandated minimum effort allocation.** Percentages are of total person-days and are contractual floors.

| Area | Artefacts | Min. effort | Rationale |
|---|---|---|---|
| Cryptographic protocol design | `docs/PROTOCOL.md`, `docs/formal/` | 15 % | A design flaw cannot be patched away |
| `quietwire-crypto`, `quietwire-e2e` | Source, tests, benchmarks | 20 % | The core of every guarantee |
| `quietwire-store` | Source, schema, key hierarchy, duress logic | 12 % | Device seizure is the most likely real-world attack |
| `quietwire-packet` | Source, cover traffic, padding, replay | 10 % | Carries the metadata guarantees |
| `quietwire-transport` (parsers) | All adapters, with emphasis on untrusted input | 10 % | The attack surface exposed to strangers |
| `quietwire-route` | Source, DoS resistance, resource bounds | 6 % | Availability and resource exhaustion |
| `quietwire-ffi` + platform layers | Kotlin, Swift, Tauri IPC | 12 % | Where secrets leak into managed heaps |
| Platform hardening | Manifests, entitlements, keystore usage | 8 % | Classic source of trivial full compromise |
| Build, supply chain, release | `flake.nix`, CI, signing, dependencies | 5 % | Compromise here defeats everything else |
| Test-suite adequacy review | §17 in full | 2 % | Auditing the auditors of the code |

**Explicitly out of scope** (and stated in the report so readers are not misled):

- The security of the underlying operating systems and their secure elements.
- Physical attacks on hardware secure elements (fault injection, decapping).
- Compromised endpoint devices (malware, keyloggers, hostile OS builds).
- The Reticulum reference implementation itself, beyond our integration boundary. Reticulum's own security is separately assessed and its trust assumptions are documented.
- Social engineering of individual users, beyond the UX-security review in §18.6.K.

**Codebase size for estimation** (updated per audit, current figures published in the RFP): approximately 34 000 lines of Rust in security crates, 11 000 in transport adapters, 9 000 Kotlin, 7 000 Swift, 6 000 TypeScript/Svelte, plus vendored SQLCipher.

### 18.4 Rules of engagement

| ID | Rule |
|---|---|
| `ROE-01` | Auditor receives full read access to the private repository, including history, CI logs, and internal design discussions |
| `ROE-02` | Auditor receives a dedicated test mesh: 6 pre-provisioned devices (2 Android, 1 iOS, 1 Windows, 1 Linux, 1 Raspberry Pi) and 4 RNodes, shipped before kickoff |
| `ROE-03` | Auditor receives all §17 test artefacts, fuzzing corpora, simulation seeds, and the last two audit reports |
| `ROE-04` | Auditor receives a written **"what worries us"** memo from the engineering team listing every known weak point, unresolved doubt and shortcut taken. This is mandatory and is published with the report |
| `ROE-05` | **Critical findings are reported within 24 hours of discovery**, not held for the final report |
| `ROE-06` | No production user data exists, so none is shared. All test data is synthetic |
| `ROE-07` | Auditor may not publish before the agreed embargo ends; the project may not delay publication beyond 90 days from report delivery under any circumstance |
| `ROE-08` | All auditor communications use the project's own PGP keys or an agreed encrypted channel; findings are never sent in plaintext email |
| `ROE-09` | Weekly 60-minute synchronisation call; engineering answers questions within 1 business day |
| `ROE-10` | Auditor keeps a time log per area, published in the report, so readers can judge depth |
| `ROE-11` | The engineering team does not push changes to audited code during the audit window except to fix a reported Critical. Branch is frozen and tagged |
| `ROE-12` | Auditor destroys all copies of the source 90 days after report delivery, certified in writing |

### 18.5 Deliverables

Every audit produces, as contractual deliverables:

1. **Executive summary** — one page, readable by a non-specialist, stating plainly whether the system's claims hold.
2. **Findings register** — each finding with: unique ID, title, severity (§18.8), affected component and line references, full technical description, **reproduction steps that actually reproduce**, proof-of-concept code where applicable, impact analysis, and recommended remediation.
3. **Coverage statement** — what was examined, how deeply, in hours, per area from §18.3. Explicitly including what was *not* examined and why.
4. **Methodology statement** — tools, techniques, manual review approach.
5. **Positive observations** — controls found to be effective. Useful for readers and honest.
6. **Test-suite adequacy assessment** — which §17 tests the auditor considers weak, missing, or misleading.
7. **Machine-readable findings** — JSON, so findings can be tracked in the issue tracker automatically.
8. **Re-test report** after remediation, confirming each fix, with the same rigour as the original finding.

### 18.6 Mandated methodology and review checklists

Every checklist item below is a contractual review obligation. The auditor marks each **Pass / Fail / Not applicable / Not reviewed**, with a justification for the last two. Items marked "Not reviewed" without justification are a breach of contract.

---

#### A. Cryptographic protocol design — `AUD-CRY-Axxx`

| ID | Review item |
|---|---|
| `A001` | Every HKDF `info` label in the system is enumerated and proven unique. No two derivations can collide |
| `A002` | Domain separation exists between every protocol context (X3DH, root chain, message chain, epoch tag, storage, link) |
| `A003` | No key is ever used for two purposes (signing vs key agreement vs wrapping) |
| `A004` | The hybrid PQ combiner is KDF-based over the concatenation of both secrets; it is **not** XOR, and remains secure if either component is fully broken |
| `A005` | The full handshake transcript is bound into the derived key. Transcript includes identities, prekeys, ciphertexts and version |
| `A006` | Unknown-key-share resistance is argued explicitly |
| `A007` | Identity misbinding attacks are analysed for both the in-person and the remote enrollment flows |
| `A008` | There is no version, cipher or parameter negotiation. Downgrade is structurally impossible, not merely refused |
| `A009` | ML-KEM implicit rejection semantics are correct: a malformed ciphertext yields a pseudorandom shared secret, never an error that distinguishes |
| `A010` | Ephemeral keys are provably deleted before the next message is processed; the deletion point is identified in the code |
| `A011` | One-time prekey exhaustion degrades safely (falls back to signed prekey) and the security consequence is documented |
| `A012` | Signed prekey rotation interval (7 days) is justified against the forward-secrecy claim |
| `A013` | Replay protection exists independently at the E2E layer and the link layer; neither relies on the other |
| `A014` | Out-of-order delivery cannot be exploited to force key reuse, chain reset or skipped-key exhaustion |
| `A015` | The skipped-key cap (1 000 / 10 000) is analysed as a DoS vector: what does an attacker achieve by forcing eviction? |
| `A016` | The 2 000-message chain limit is analysed: can an attacker force a peer into a stuck state? |
| `A017` | Epoch tags are proven unlinkable across epochs without the session key |
| `A018` | Epoch tag collisions (16 bytes, birthday bound) are analysed against the expected number of contacts and epochs |
| `A019` | The ±2 h clock-skew window is analysed: what does an attacker with clock control achieve? |
| `A020` | Trial decryption cannot be used as an oracle: a failed tag lookup and a failed decryption are indistinguishable to an observer, in time and in behaviour |
| `A021` | Sealed sender does not leak the sender through the ratchet public key across messages |
| `A022` | The Noise `XX` pattern selection is correct for the property required (mutual authentication with identity hiding) |
| `A023` | Link-layer and E2E-layer keys are provably independent |
| `A024` | Safety numbers are computed over a canonical, order-independent encoding; two devices always compute the same value |
| `A025` | The 60-digit safety number's collision resistance is calculated and stated |
| `A026` | Nonce generation is from the OS CSPRNG, never a counter, never derived from state. Collision probability over the system's lifetime is calculated and stated |
| `A027` | AEAD associated data covers every field whose modification would change meaning |
| `A028` | Fields deliberately outside the E2E MAC (`ttl`, `copies`) are analysed: exactly what can a hostile relay achieve by forging them, and is that bounded? |
| `A029` | The protocol is analysed under an attacker who controls the entire network, not merely observes it |
| `A030` | Multi-device and re-installation scenarios are analysed (even though v1.0 is single-device, the failure mode must be safe) |
| `A031` | Key compromise impersonation resistance is argued |
| `A032` | The protocol specification in `PROTOCOL.md` is complete enough that an independent implementer could build an interoperable, secure client. Gaps are findings |
| `A033` | The per-message tag stream is directional: no tag value ever appears in both directions of a session, and two devices in one conversation never emit the same tag |
| `A034` | The tag resynchronisation path (§5.5) cannot be used as an oracle, cannot be forced by an attacker, and does not reset any key material |
| `A035` | The link pseudonym (§5.6) is unlinkable to the identity keys and to the previous day's pseudonym |
| `A036` | The first-message three-cell `session_init` set cannot be exploited by partial delivery, reordering or mixing fragments from two different handshakes |

---

#### B. Cryptographic implementation — `AUD-CRY-Bxxx`

| ID | Review item |
|---|---|
| `B001` | Implementation matches `PROTOCOL.md` exactly. Every divergence is a finding, even if the divergence is harmless |
| `B002` | No secret-dependent branch anywhere. Verified by manual review **and** by `ctgrind`/`valgrind` instrumentation, not by tooling alone |
| `B003` | No secret-dependent memory index or table lookup |
| `B004` | All comparisons on secret data use `subtle::ConstantTimeEq`. Every `==` on a secret type is a finding |
| `B005` | AEAD tag verification precedes any use of plaintext; no plaintext is released on authentication failure, not even into a buffer that is later cleared |
| `B006` | Every secret buffer is zeroized on drop, **including on the error and panic paths**. Auditor must verify by forcing panics |
| `B007` | No secret type derives `Debug`, `Display`, `Clone`, `Serialize` or `Hash` without documented justification |
| `B008` | Secrets are `mlock`ed where the platform allows; where it does not, the exposure is documented |
| `B009` | CSPRNG is the OS source via `getrandom`. No userspace PRNG is used for any key or nonce |
| `B010` | **Fork safety**: after `fork()`, the child cannot reuse parent RNG state |
| `B011` | **VM snapshot / clone safety**: if a device image is cloned or restored from a snapshot, the RNG and any counter-based state cannot repeat. This is a classic total break and must be explicitly analysed |
| `B012` | RNG failure is fatal and loud. A failed `getrandom` never silently falls back to anything |
| `B013` | Integer arithmetic is overflow-checked in release builds (`overflow-checks = true` verified in the release profile) |
| `B014` | No `unwrap`, `expect`, `panic!`, `unreachable!`, `todo!` or slice indexing in library code paths reachable from untrusted input |
| `B015` | Every `unsafe` block carries a `// SAFETY:` justification that is correct, not merely present. Auditor evaluates the argument |
| `B016` | Miri is clean across the crypto crates; any suppression is justified |
| `B017` | Key material never crosses the FFI boundary into a managed heap. Verified by heap dump on Android and iOS |
| `B018` | Error types do not leak secret-dependent information, including through error message length or variant selection |
| `B019` | Logging, tracing and metrics contain no secret, no plaintext, no identity, and no epoch tag. Every log call site in security crates is individually reviewed |
| `B020` | Debug assertions do not change security-relevant behaviour between debug and release builds |
| `B021` | Compiler optimisation cannot elide zeroization. Verified by disassembly of the release binary for at least three representative cases |
| `B022` | Stack-allocated intermediate secrets are cleared; auditor checks for copies left by the compiler in spill slots |
| `B023` | The dependency versions of all crypto crates are pinned exactly, and their advisory history is reviewed |
| `B024` | Vendored C code (SQLCipher, and any transitively vendored OpenSSL/libsodium) is version-pinned, CVE-checked, and its build flags reviewed for hardening (`-D_FORTIFY_SOURCE`, stack protector, RELRO, PIE) |
| `B025` | Test-only code paths cannot be reached in a release build. Verified structurally, not by convention |

---

#### C. Packet, privacy and traffic analysis — `AUD-PKT-Cxxx`

| ID | Review item |
|---|---|
| `C001` | Cell serialisation is exactly 512 bytes for every reachable input. Auditor attempts to construct a counterexample |
| `C002` | Padding is drawn from the CSPRNG and is statistically indistinguishable from the ciphertext it pads |
| `C003` | Reserved flag bits are randomised and carry no implicit signal |
| `C004` | Decoy cells are indistinguishable from real cells at the byte level, in generation timing, and in downstream handling. Auditor performs an independent classification experiment |
| `C005` | The cover-traffic scheduler cannot be perturbed by user activity in an observable way. Auditor attempts a timing-correlation attack with full radio capture |
| `C006` | Forwarding delay is drawn per cell, independently, from the CSPRNG. No shared state creates correlation |
| `C007` | Batch shuffling uses a uniform permutation from the CSPRNG (Fisher–Yates, correctly implemented — off-by-one here is a classic bug) |
| `C008` | Cell handling time does not vary between "for me" and "not for me". Auditor measures |
| `C009` | The epoch-tag lookup is constant-time with respect to the number of contacts and to whether a match occurs |
| `C010` | Retransmission behaviour does not leak whether a message was real |
| `C011` | Error and drop behaviour does not create an observable signal (for example, a node that drops malformed cells faster than valid ones) |
| `C012` | Fragmentation does not leak message length beyond the granularity of a cell |
| `C013` | Acknowledgement traffic does not create a distinguishable pattern linking sender and recipient |
| `C014` | BLE advertisement UUID rotation is unlinkable; the MAC randomisation interaction with the OS is analysed |
| `C015` | Discovery and connection patterns do not fingerprint a device across time or location |
| `C016` | The auditor performs an intersection-attack feasibility analysis against the cover-traffic parameters and states how long an observer would need |

---

#### D. Storage, key management and anti-forensics — `AUD-STO-Dxxx`

| ID | Review item |
|---|---|
| `D001` | The implemented key hierarchy matches §5.7 exactly; auditor traces every key from password to use |
| `D002` | The DEK is never written to disk unwrapped, including in temp files, swap, hibernation images, crash dumps and core files |
| `D003` | Argon2id parameters in the release binary match the specification. Auditor verifies in the compiled artefact, not the source |
| `D004` | Salt is 32 bytes from the CSPRNG, unique per installation, never reused after a wipe |
| `D005` | Wrapped DEK, salt and fail counter are stored such that tampering is detected |
| `D006` | The fail counter cannot be reset by clearing app data, reinstalling, manipulating the clock, or restoring a backup |
| `D007` | Dual unwrap (real/duress) is constant-time in total, including all error handling and all allocation |
| `D008` | **Duress store forensic equivalence**: auditor performs an independent forensic comparison of two device images and attempts to determine whether a duress store exists. This is the single most important item in section D |
| `D009` | No code path, log, metric, file timestamp, database page count, row count or allocation pattern reveals the existence of the second store |
| `D010` | Store isolation is enforced at the type level, not by a runtime check that could be bypassed. Auditor attempts to reach real-store data from the duress context through every public API |
| `D011` | Field AEAD associated data binds table, row and column; auditor attempts a blob relocation attack |
| `D012` | SQLite `temp_store = MEMORY`, `secure_delete = ON`, and WAL/journal files are encrypted or absent |
| `D013` | Android: `allowBackup="false"`, `dataExtractionRules` deny everything, no auto-backup, no Google Drive backup path |
| `D014` | Android: Keystore usage requires user authentication, uses StrongBox where available, and key attestation is verified |
| `D015` | iOS: file protection class is `NSFileProtectionComplete`; Keychain items use `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` with `kSecAttrSynchronizable = false` |
| `D016` | iOS: the app is excluded from iCloud and iTunes backup |
| `D017` | Desktop: the database location, permissions and any OS indexing (Spotlight, Windows Search) exposure are reviewed |
| `D018` | No crash reporter, analytics SDK, or telemetry exists in any build. Auditor verifies by binary inspection, not by asking |
| `D019` | Clipboard usage is absent or explicitly cleared; no message content can reach the system clipboard unintentionally |
| `D020` | Wipe is atomic with respect to power loss and leaves nothing recoverable |
| `D021` | Memory after lock contains no key material. Auditor takes a live memory dump and searches |
| `D022` | Schema migrations cannot downgrade encryption or silently rewrite data in a weaker form |
| `D023` | Exactly two store files exist from install, on every platform, whether or not a duress password was ever set, and both are written on the same schedule |
| `D024` | The vault blob is exactly 4 096 bytes with positional fields and no key names; its contents are indistinguishable from random |
| `D025` | The fail-counter wipe destroys **both** slots and both store files, and the resulting device is byte-indistinguishable from a fresh install |
| `D026` | SQLCipher is keyed raw (`PRAGMA key = "x'…'"`), not by passphrase, and `cipher_plaintext_header_size = 0` with an externally supplied salt leaves no plaintext header |
| `D027` | No plaintext enum or unbucketed timestamp survives anywhere in the schema; the auditor inspects a decrypted page image to confirm |

---

#### E. Transports and untrusted input — `AUD-TRN-Exxx`

| ID | Review item |
|---|---|
| `E001` | Every byte arriving from a peer is treated as hostile. Auditor traces each parser from entry point to first validation |
| `E002` | No parser allocates before validating a length field |
| `E003` | No parser recurses on attacker-controlled depth |
| `E004` | All parsers have bounded memory and bounded time for any input |
| `E005` | The Noise handshake implementation is used correctly: no key reuse across sessions, correct prologue, correct rekey handling |
| `E006` | A hostile peer cannot cause the session to fall back to an unencrypted or partially encrypted state |
| `E007` | Connection handling is free of resource leaks under abusive connect/disconnect patterns |
| `E008` | The LoRa duty-cycle interlock cannot be bypassed through any code path, including error recovery and retransmission |
| `E009` | Region gating cannot be bypassed; the auditor attempts to transmit out of band |
| `E010` | Sneakernet bundle parsing is hardened: a hostile `.qwb` file cannot achieve code execution, path traversal, zip-bomb expansion, or state corruption |
| `E011` | The RaptorQ decoder is hardened against malicious symbol sets |
| `E012` | QR scanning cannot be used to inject a hostile contact silently; every scan results in an explicit, understandable user confirmation |
| `E013` | NFC input is treated with the same hostility as radio input |
| `E014` | The Reticulum integration boundary is reviewed: nothing from Reticulum is trusted, and our E2E layer cannot be stripped or downgraded by a hostile Reticulum peer |
| `E015` | Transport adapters cannot observe plaintext; the trait boundary structurally prevents it |

---

#### F. Routing, availability and resource exhaustion — `AUD-RTE-Fxxx`

| ID | Review item |
|---|---|
| `F001` | Every cache, queue and map has a hard cap enforced in code |
| `F002` | An attacker cannot cause unbounded memory, disk or CPU growth through any input |
| `F003` | Copy budgets cannot be inflated by a hostile relay beyond the bound proven in §8 |
| `F004` | TTL cannot be incremented; the code path is reviewed for a signed/unsigned confusion |
| `F005` | Encounter-utility state cannot be poisoned to attract traffic to an attacker; caps and cross-checks hold (analysed and bounded) |
| `F006` | GCS digest exchange does not leak the set of messages a node holds beyond the intended false-positive rate |
| `F007` | Eviction policy cannot be manipulated to evict a specific victim's messages |
| `F008` | The energy budget cannot be exhausted remotely to cause battery drain as a denial of service |
| `F009` | Clock manipulation cannot cause permanent message loss or permanent session breakage |
| `F010` | Sybil and black-hole resistance claims are independently tested by the auditor, not accepted from our simulation |
| `F011` | **No routing state anywhere is keyed on a destination.** The auditor greps and reads for any table, cache or heuristic that could reconstruct conversation linkage from routing data. This is the structural guarantee behind §8.2 and the easiest one to lose by accident |
| `F012` | Self-reported utility inputs (degree, mobility, backlog) cannot be inflated beyond their caps, and no combination of lies lets a peer monopolise copies |

---

#### G. Bindings, applications and platform hardening — `AUD-APP-Gxxx`

| ID | Review item |
|---|---|
| `G001` | Android manifest: no exported activity, service, receiver or provider; every `android:exported` is explicit and false where possible |
| `G002` | Android: `FLAG_SECURE` set on every window containing message content |
| `G003` | Android: `filterTouchesWhenObscured` set to prevent tapjacking on destructive actions (wipe, duress setup) |
| `G004` | Android: all `PendingIntent` are immutable and explicit |
| `G005` | Android: no `WebView` anywhere in the app |
| `G006` | Android: the **airgap** flavour declares no `INTERNET` permission at all, verified in the merged manifest of the release APK; the **bridged** flavour declares it and its network security config forbids cleartext and pins the I2P/TCP endpoints. Neither flavour may contain code paths from the other |
| `G007` | Android: R8/ProGuard rules do not strip or reorder zeroization; the shrunk release binary is reviewed |
| `G008` | Android: `android:debuggable` false, no debug symbols, no test hooks in release |
| `G009` | iOS: entitlements are minimal; background modes limited to those required and justified |
| `G010` | iOS: the app blurs or covers content on `applicationWillResignActive`; verified by capturing the app-switcher snapshot |
| `G011` | iOS: no pasteboard exposure; `UIPasteboard` usage reviewed |
| `G012` | iOS: no third-party SDKs of any kind. Verified by binary inspection |
| `G013` | Jailbreak/root detection, if present, is documented as a speed bump and not relied upon for any security property |
| `G014` | Tauri: the allowlist is minimal; every enabled capability is justified |
| `G015` | Tauri: the CSP forbids remote content, inline script and `eval` |
| `G016` | Tauri: every IPC command is enumerated and reviewed as an attack surface from the web layer |
| `G017` | **Local web UI**: binds to `127.0.0.1` only, never `0.0.0.0`; rejects requests with a foreign `Origin` or `Host`; uses a per-session token; is not reachable from a page the user visits in another tab (DNS-rebinding resistant) |
| `G018` | Updater: signatures are verified before installation, with no downgrade path and no unsigned fallback |
| `G019` | The FFI surface is reviewed for type confusion, lifetime errors and error-handling gaps in both Kotlin and Swift |
| `G020` | No secret reaches a Kotlin `String` or Swift `String` (immutable, non-zeroizable, GC-managed). Any that does is a finding |
| `G021` | Notification content, lock-screen previews and OS-level message summaries never contain message text |
| `G022` | System logs (logcat, unified logging, Event Viewer) contain nothing sensitive under any condition, including crash |

---

#### H. UX-security review — `AUD-UX-Hxxx`

Security properties that depend on the user understanding something are security properties that depend on the interface. This area is routinely skipped by audits and routinely where real systems fail.

| ID | Review item |
|---|---|
| `H001` | The verified/unverified distinction is unmissable; an unverified conversation cannot be mistaken for a verified one at a glance |
| `H002` | Safety-number comparison is explained in language a non-technical user acts on correctly. Tested with real users, not assumed |
| `H003` | The four delivery states cannot be misread; in particular "travelling" cannot be mistaken for "delivered" |
| `H004` | The irreversibility of password loss is communicated once, clearly, and requires active acknowledgement |
| `H005` | The wipe-on-failure threshold is communicated with its consequence; accidental self-wipe risk is assessed |
| `H006` | Duress setup does not create a discoverable artefact in the UI, in settings, or in the accessibility tree |
| `H007` | The duress store is convincing: an examiner watching the user unlock cannot detect which store opened |
| `H008` | No security-relevant decision is buried behind a default the user will never see |
| `H009` | Error messages never blame the user and never tempt them into an insecure workaround |
| `H010` | Latency expectations are set honestly; a user must not conclude from the interface that a message failed when it is merely travelling |
| `H011` | The interface never displays a number the device did not observe. Specifically, nothing reports hop counts, carrier counts or a cell's position in the mesh, because none of that is knowable (§12) |
| `H012` | Block and Delete work silently, give the blocked party no signal, and survive app restart |
| `H013` | The backup-export warning (§11.6) is shown every time, not once, and the dialog refuses cloud-synced destinations |
| `H014` | A new identity for an existing contact is always surfaced as an alarming, unverified event and never silently accepted |

---

#### I. Supply chain and build integrity — `AUD-SUP-Ixxx`

| ID | Review item |
|---|---|
| `I001` | The release binary is reproduced independently by the auditor from the published source |
| `I002` | Every `build.rs` in the dependency tree is enumerated and manually reviewed. Build scripts execute arbitrary code at compile time and are a standard supply-chain vector |
| `I003` | Every procedural macro in the tree is enumerated and reviewed |
| `I004` | Dependencies with a single maintainer, recent ownership transfer, or low download count are flagged and justified |
| `I005` | `Cargo.lock` is committed and exact; no version ranges resolve at build time |
| `I006` | Vendored C sources match upstream at the pinned commit, verified by hash |
| `I007` | CI credentials, signing keys and release infrastructure access are reviewed; signing keys are in hardware tokens |
| `I008` | The CI configuration cannot be modified by a single person without review |
| `I009` | Published hashes, signatures and SBOM match the distributed artefacts on every channel (Play Store, App Store, F-Droid, direct download) |
| `I010` | The toolchain itself is pinned and its provenance documented |
| `I011` | Every commit in the repository history is signed and verified (`QW-C-SYS-351`); the auditor re-runs the walk independently |
| `I012` | Rebase merge is disabled at the repository level, not merely avoided by convention (§19.9) |
| `I013` | Vigilant mode is enabled on every maintainer account, so unsigned commits display as Unverified rather than unmarked |
| `I014` | Signing keys are hardware-backed and the backup key is in separate custody, verified by inspection rather than by assertion |
| `I015` | `reuse lint` passes; every file carries SPDX headers and all four licence texts are present in `LICENSES/` |

---

#### J. Documentation and claims review — `AUD-DOC-Jxxx`

| ID | Review item |
|---|---|
| `J001` | Every security claim in the README, the app, the website and the store listings is either substantiated or removed. Overclaiming is a finding |
| `J002` | The threat model's exclusions are stated prominently, not buried |
| `J003` | Known limitations (iOS relay weakness, sneakernet latency, intersection-attack resistance limits) are disclosed to users, not only to auditors |
| `J004` | `PROTOCOL.md` matches the implementation |
| `J005` | The privacy statement is accurate and complete |

---

#### K. Test-suite adequacy — `AUD-TST-Kxxx`

| ID | Review item |
|---|---|
| `K001` | Auditor identifies §17 tests whose assertions are weaker than their names imply |
| `K002` | Auditor identifies security properties from §2 with no corresponding test |
| `K003` | Auditor writes at least three new tests that the existing suite would have passed but should not have. These are contributed back and become part of the suite |
| `K004` | Mutation-testing results are reviewed: surviving mutants in security crates are examined individually |
| `K005` | Fuzzing corpora and coverage are reviewed for blind spots |

---

### 18.7 Specialist sub-audits

**AUD-4 Formal verification review.** The specialist verifies that the ProVerif, Verifpal, Tamarin and Noise Explorer models in `docs/formal/` actually model the protocol as implemented — the classic failure is a correct proof of the wrong model. Deliverable: a statement of what each model does and does not cover, and a list of implementation behaviours outside the models.

**AUD-5 Forensic evaluation.** An accredited digital forensics lab receives:
- Image A: a device with messages, no duress store.
- Image B: a device with messages and a duress store.
- Image C: a device after a wipe.
- Image D: a device seized while locked but powered on.

They receive the source code and the specification, unlimited time, and commercial tooling. They must attempt to (i) recover any message content, (ii) determine the number of contacts or conversations, (iii) determine whether a duress store exists, (iv) recover anything from image C, (v) extract keys from image D. Every success is a Critical or High finding.

**AUD-6 Red team.** Two weeks, full scope, assume-breach optional. Objectives in priority order: read one message not intended for them; identify who is talking to whom; cause a device to leak key material; deny service to the mesh; compromise the release pipeline. The team writes an attack narrative, not just a finding list.

**AUD-8 RF and regulatory.** An accredited test house measures, for each supported LoRa hardware profile and region: ERP, occupied bandwidth, spurious and out-of-band emissions, and duty cycle under worst-case software behaviour. Compliance with ETSI EN 300 220 (EU) and FCC Part 15.247 (US) is certified, not asserted.

**AUD-9 Privacy review.** Confirms that the architecture genuinely processes no personal data on behalf of any controller, that the app's own data handling on-device is accurately described, and that the privacy statement would survive a regulator reading it.

**AUD-10 Export control.** Confirms the applicability of the publicly-available-software exemption in EU Regulation 2021/821 and the US EAR TSU exception, in writing, with the filings made before release.

**AUD-11 Accessibility.** WCAG 2.2 AA against the desktop and local web UI; platform accessibility guidelines against Android and iOS. Includes a session with at least two users who rely on a screen reader daily.

### 18.8 Severity classification

Findings are scored with **CVSS v4.0 base**, adjusted by project-specific modifiers, because CVSS alone underrates cryptographic and metadata failures in a system like this.

**Escalation modifiers** (each raises severity by one band, cumulatively):

- The finding breaks confidentiality of message content for any party other than the intended recipient.
- The finding allows a relay or observer to link sender to recipient.
- The finding reveals the existence of the duress store.
- The finding allows key extraction from a locked or powered-off device.
- The finding is remotely triggerable by any peer without prior contact.
- The finding is in the release or signing pipeline.

**De-escalation modifiers**:

- Exploitation requires an already-compromised endpoint (within the excluded threat model).
- Exploitation requires physical access to an unlocked device.

| Band | Definition | Examples |
|---|---|---|
| **Critical** | Breaks a core guarantee for a realistic attacker | Message plaintext readable by a relay; key recovery from a seized device; duress store detectable; remote code execution from a peer cell |
| **High** | Materially weakens a guarantee, or breaks one under constrained conditions | Sender–recipient linkage by a regional observer; forward secrecy not achieved after compromise; a parser crash reachable from a peer; downgrade to a weaker suite |
| **Medium** | Weakens defence in depth, or a guarantee fails only in an unusual configuration | Non-constant-time comparison on a low-value secret; resource exhaustion causing temporary DoS; a log line containing an epoch tag |
| **Low** | Hardening gap with no demonstrated impact | Missing `-D_FORTIFY_SOURCE`; an unjustified `unsafe` comment; a dependency with a single maintainer |
| **Informational** | Observation, no security impact | Style, clarity, unused code |

**Disputes.** If the team and the auditor disagree on severity, **the auditor's rating is the one published**, with the team's response printed alongside it. The team does not get to downgrade its own findings.

### 18.9 Finding lifecycle and remediation service levels

```
Reported ──▶ Triaged (≤24 h) ──▶ Accepted / Disputed
                                      │
                                      ├─▶ Fixed ──▶ Re-tested by auditor ──▶ Closed
                                      ├─▶ Mitigated (with documented residual risk)
                                      └─▶ Accepted risk (Low/Informational only,
                                                        signed off by name, published)
```

| Severity | Triage | Fix | Release impact |
|---|---|---|---|
| Critical | 4 hours | **72 hours**, or the release is cancelled | **Blocks release. If already shipped, an emergency release goes out within 7 days and users are notified in-app** |
| High | 24 hours | 7 days | Blocks release |
| Medium | 3 days | 30 days | Blocks release unless a named person documents why not, published |
| Low | 7 days | 90 days, or documented acceptance | Does not block |
| Informational | 14 days | Best effort | Does not block |

**Every fix requires a regression test.** A finding cannot be closed without a new test in §17 that fails against the vulnerable code and passes against the fix, carrying the finding ID in its name (for example `QW-U-STO-174c_AUD2024_F07`). This is how an audit permanently improves the system rather than producing a one-time patch.

**Root-cause analysis.** Every Critical and High requires a written analysis of *why the class of bug was possible*, and a control that prevents the class — a lint, a type, a test, a review step. Fixing the instance without addressing the class is not an acceptable closure.

### 18.10 Evidence and reproduction standards

- Every finding must include reproduction steps that a third party can follow. **A finding that cannot be reproduced is downgraded to Informational** after a documented attempt.
- Proof-of-concept code is delivered in the agreed encrypted channel and published with the report once the finding is fixed.
- The auditor's environment (device models, OS versions, commit hash, toolchain) is recorded per finding.
- Findings are tied to a specific commit hash, not "current main".

### 18.11 Publication policy

For each audit, `docs/AUDIT/<year>-<type>-<firm>/` contains:

- The full report, unredacted.
- The engineering team's "what worries us" memo written before the audit.
- The team's written response to every finding, including disputes.
- The re-test report.
- The commit hashes audited and the commit hashes of each fix.
- Any findings accepted rather than fixed, with the named person who accepted them.

**Embargo:** publication within 30 days of the re-test report, or 90 days from the original report, whichever is sooner. An unfixed Critical may delay publication of that single finding only, never the report as a whole, and never beyond 90 days.

The app's About screen links to the most recent report. A user must be able to reach the audit from inside the product in two taps.

### 18.12 Internal continuous audit (AUD-12)

Between external audits, these controls run continuously. They are not an audit, but their absence would make the external audit meaningless.

| ID | Control |
|---|---|
| `INT-01` | Every commit to a security crate requires review by a second engineer who did not write it. Enforced by branch protection, not by convention |
| `INT-02` | Every commit touching `quietwire-crypto` or `quietwire-e2e` requires review by the designated cryptography reviewer specifically |
| `INT-03` | All commits are signed; unsigned commits are rejected |
| `INT-04` | A change to any Argon2, cipher, KDF or protocol constant requires two reviewers and an ADR |
| `INT-05` | A new dependency in a security crate requires an ADR, a `cargo vet` entry, and a manual read of its `build.rs` |
| `INT-06` | The threat model (§2) is reviewed every quarter and on every new transport or feature. A feature that changes the threat model cannot merge until §2 is updated in the same pull request |
| `INT-07` | A quarterly internal red-team day: the whole team spends one day trying to break the current build, findings logged like any other |
| `INT-08` | A security-relevant change requires the pull request to state which §17 tests cover it and which §18 checklist items it touches |
| `INT-09` | `docs/AUDIT/OPEN_QUESTIONS.md` is maintained continuously — the running "what worries us" list. It is never emptied for appearances |
| `INT-10` | Every dependency advisory (`cargo audit`) is triaged within 48 hours, including ones that do not apply, with the reason recorded |

### 18.13 Bug bounty (AUD-13)

Launched with v1.0, run on a self-hosted disclosure page (no platform intermediary holding reports).

| Severity | Reward | Examples |
|---|---|---|
| Critical | €25 000 | Practical decryption of a message by a non-recipient; key extraction from a locked device; detection of the duress store; remote code execution from a peer |
| High | €8 000 | Sender–recipient correlation by a regional observer; forward-secrecy break; remotely triggered crash |
| Medium | €2 000 | Resource exhaustion DoS; metadata leak of bounded scope |
| Low | €500 | Hardening gaps, information disclosure without impact |

**Rules:** 90-day coordinated disclosure; no legal action against good-faith researchers, stated in a safe-harbour clause; duplicates paid at 25 % to the second reporter if they add material detail; the researcher is credited by name unless they decline. Out of scope: attacks requiring a compromised OS, physical attacks on secure elements, social engineering of users, and denial of service by radio jamming.

### 18.14 Audit budget and schedule

| Audit | Effort | Cost estimate |
|---|---|---|
| AUD-1 Cryptographic design | 12–15 person-days | €14 000 – €22 000 |
| AUD-2 Crypto implementation | 18–22 person-days | €22 000 – €35 000 |
| AUD-3 Application and platform | 18–22 person-days | €20 000 – €32 000 |
| AUD-4 Formal verification | 8–10 person-days | €10 000 – €16 000 |
| AUD-5 Forensic evaluation | 6–10 person-days | €8 000 – €15 000 |
| AUD-6 Red team | 10 person-days | €14 000 – €20 000 |
| AUD-7 Supply chain (per release) | 2–3 person-days | €2 000 – €3 500 |
| AUD-8 RF and regulatory | accredited lab | €6 000 – €12 000 |
| AUD-9 Privacy review | 4 person-days | €3 000 – €5 000 |
| AUD-10 Export control | 6–10 person-days | €4 000 – €9 000 |
| AUD-11 Accessibility | 4 person-days | €1 500 – €3 000 |
| Re-test rounds (all audits) | — | €8 000 – €14 000 |
| Bug bounty reserve, year one | — | €30 000 |
| *(reserve top-up policy: a single Critical payout consumes most of it. The reserve is replenished to €30 000 within 30 days of any payout, or the programme is publicly paused rather than left advertising rewards it cannot pay)* | | |
| **Total, first cycle** | | **€142 500 – €216 500** |

This is substantially more than the figure in §16, which covered a single combined audit. **§16 is the minimum viable posture; §18 is the correct one.** Which is funded is a business decision, but it should be made knowingly rather than by accident.

If the full programme is not affordable at v1.0, the non-negotiable subset is **AUD-1, AUD-2, AUD-5 and AUD-10**, costing **€48 000 – €81 000**, with the remainder scheduled within twelve months and the gap disclosed publicly on the release page.

Two corrections to an earlier draft of this paragraph. Its subset arithmetic was wrong — AUD-2 + AUD-5 + AUD-7 + AUD-10 sums to €36 000 – €62 500, not the €38 000 – €67 500 quoted. And its choice of subset was wrong: it dropped **AUD-1, the design review**, which is the one audit whose findings cannot be patched later. A protocol flaw discovered after launch means every deployed client is wrong and every message ever sent under it is suspect. AUD-7, the per-release supply-chain check, is cheap enough to absorb into engineering time if it must be; AUD-1 is not something to economise on.

**Schedule relative to release**

```
Phase 1 wk 9   AUD-1 and AUD-4 run here, against PROTOCOL.md, BEFORE
               anything is built on the design (see §14, Phase 1)
Phase 1 wk 11  Design findings triaged; protocol frozen
─────────────  the calendar below is relative to release ─────────────
T-16 weeks  RFP issued for the remaining audits, firms selected, contracts signed
T-14        Devices and access shipped to auditors
T-12        AUD-1 and AUD-4 RE-review of every change since the freeze
T-10        Re-review findings triaged
T-9         AUD-2 and AUD-3 begin (code freeze on audited branch)
T-6         AUD-5 and AUD-6 begin
T-5         Draft reports delivered; remediation sprint begins
T-3         AUD-8, AUD-9, AUD-10, AUD-11
T-2         Re-tests complete; all High and Critical closed
T-1         AUD-7 supply chain; independent reproduction
T-0         Reports published, then release
```

The reports are published **before** the release, not after. Shipping first and publishing later inverts the purpose.

### 18.15 Go / no-go criteria

A release proceeds only if **all** of the following are true. Any single "no" stops it.

- [ ] AUD-1, AUD-2, AUD-3, AUD-4, AUD-5, AUD-6 complete for this major version
- [ ] Zero open Critical findings
- [ ] Zero open High findings
- [ ] Every Medium is either fixed or accepted in writing by a named person, published
- [ ] Every fixed finding has a regression test carrying its ID
- [ ] Every Critical and High has a published root-cause analysis and a class-level control
- [ ] Re-test report received and confirms every fix
- [ ] AUD-7 supply chain passed; independent reproduction confirmed
- [ ] AUD-8 regulatory certification in hand for every shipped radio profile
- [ ] AUD-9 and AUD-10 sign-offs in hand
- [ ] AUD-11 accessibility gates met
- [ ] All §17 gates green on the exact commit being shipped
- [ ] Reports published at `docs/AUDIT/` and linked from the app
- [ ] `OPEN_QUESTIONS.md` current and published
- [ ] Bug bounty live with a monitored disclosure channel

### 18.16 Re-audit triggers

Outside the annual cycle, a fresh audit of the affected area is mandatory when any of these occurs:

- Any change to the protocol, the key hierarchy, or a cryptographic primitive.
- Any new transport adapter.
- Any change to the duress or wipe logic.
- Any change to the build, signing or release pipeline.
- Any dependency change in a security crate that is not a patch-level bump of an already-audited crate.
- A Critical finding from any source, including the bug bounty.
- A relevant advisory against a primitive in use (for example, a practical attack on ML-KEM or X25519).
- A change of platform security model by Apple, Google or Microsoft that touches key storage or background execution.
- Two years elapsed since the last full audit, regardless of whether anything changed. Assumptions expire even when code does not.

---

## 19. Governance, licence and lifecycle

A review of the previous draft found this section missing entirely. The plan specified a protocol, a test suite and an audit programme, but never answered four questions that determine whether any of it survives contact with reality: under what licence the code is released, how a protocol upgrades in a network with no servers and no forced updates, what happens when a user's circumstances change, and who pays for the next audit.

### 19.1 Licence

| Artefact | Licence | SPDX identifier |
|---|---|---|
| All source code | **Apache License 2.0** | `Apache-2.0` |
| `PROTOCOL.md` and all specification documents | **Creative Commons Attribution 4.0 International** | `CC-BY-4.0` |
| Test vectors, fuzzing corpora, simulation seeds | **CC0 1.0 Universal** (public domain dedication) | `CC0-1.0` |
| Icons, illustrations, brand assets | **CC-BY-4.0**, with trademark reserved | `CC-BY-4.0` |

All four are **free software / free culture licences** recognised by both the Free Software Foundation and the Open Source Initiative. Nothing in the project is under a source-available-but-not-free licence, a non-commercial clause, or a "fair use" licence of the kind that has become fashionable and is neither free nor open.

**Why Apache-2.0 and not something stronger.** This is the decision most likely to be second-guessed, so the reasoning is written out rather than asserted.

1. **GPLv3 and AGPLv3 cannot be distributed on Apple's App Store.** This is not a theoretical concern: it is settled practice, established when VLC was removed in 2011 and confirmed repeatedly since. The App Store terms impose usage restrictions and DRM-bound distribution that conflict with GPLv3's anti-Tivoisation and additional-restrictions clauses, and a copyright holder can force removal. §14 Phase 6 requires an iOS release, and iOS users are exactly the population — journalists, lawyers, people in unfriendly places — this tool exists for. **A licence that removes the app from half its intended users' devices is not the freest choice available; it is the most restrictive one, measured by who can actually run the software.**
2. **The patent grant is the reason to prefer Apache-2.0 over MIT or BSD.** Section 3 of Apache-2.0 grants contributors' patent rights to users and terminates that grant for anyone who initiates patent litigation over the work. For a cryptographic protocol that other people are being invited to implement, that clause is worth more than the brevity of MIT.
3. **The goal is adoption of the protocol, not control of the implementation.** A copyleft licence protects users of *this* codebase. A permissive one maximises the number of independent, interoperable implementations, and in a mesh network the value to every user rises with the number of devices that speak the protocol. A network effect is the security property here: a mesh with three implementations and many nodes protects people better than a mesh with one pure implementation and few.
4. **`libsignal` is AGPL**, and taking it as a dependency would force the whole project copyleft. The plan already rejects it for technical reasons (§3); the licence makes that rejection convenient rather than costly.
5. **Public source is a legal requirement, not only a value.** The export exemptions in §20 — EU dual-use Note 3 to Category 5 Part 2, and the US EAR TSU exception under 15 CFR 740.13(e) — both depend on the software being publicly available. A proprietary QUIETWIRE would be export-controlled cryptography requiring licences in every jurisdiction it touched.

**Considered and rejected:** MPL-2.0 (file-level copyleft solves a problem this project does not have, and still creates App Store friction on the combined-work question); MIT or BSD-3 (no patent grant); dual `MIT OR Apache-2.0`, the Rust ecosystem default (the MIT arm lets a downstream strip the patent grant, which defeats the point of including it); GPLv2 (same store problem, no patent grant); "Apache-2.0 with Commons Clause" and similar (not free software, and would void the export exemptions).

**Trademark is separate from copyright.** The name QUIETWIRE and the logo are reserved. Anyone may fork the code and the protocol; a fork ships under its own name. This is how a permissive licence stays compatible with users being able to trust what "QUIETWIRE" means — and it is stated in `TRADEMARK.md`, not left implicit.

**REUSE compliance.** The repository follows the [REUSE 3.2 specification](https://reuse.software): every file carries an `SPDX-FileCopyrightText` and `SPDX-License-Identifier` header, or has one in a matching `.license` file; full licence texts live in `LICENSES/`; and `reuse lint` runs in CI as a blocking check (`QW-C-SYS-349`). A project that ships four licences without per-file marking is one that will be unable to answer a straightforward legal question in two years.

**Contributions** are accepted under the **Developer Certificate of Origin 1.1**, signed off per commit (`git commit -s`), not a copyright-assignment CLA. Nobody signs away rights to contribute a bug fix, and the project never acquires the ability to relicense other people's work — which is, in practice, the main thing a CLA is for.

### 19.2 Protocol versioning and evolution

This is harder than it looks, because there is no server to coordinate an upgrade, no way to force a client to update, and relays must keep carrying traffic for versions they do not understand.

**Three rules make it tractable:**

1. **Relays are version-agnostic.** A cell's header (§6.1) is fixed forever at 512 bytes with `version` in byte 0. A relay forwards any cell whose version it recognises as a QUIETWIRE cell, without parsing further. A node running v1 relays v2 traffic correctly because relaying requires nothing beyond the header. **Any future change that would break this property is rejected**, however desirable it seems.
2. **Endpoints negotiate nothing.** There is no cipher suite negotiation, no downgrade path, no "highest common version" handshake — those are the mechanism behind a long history of protocol attacks. Instead, a contact bundle (§5.2) states the versions that device supports, and the sender picks the highest the *recipient* advertised. If the recipient advertises only v1, the sender speaks v1 or declines with a visible message. It never silently weakens.
3. **Version lifetimes are announced, not sprung.** A protocol version is supported for a minimum of **three years** after its successor ships. Deprecation appears in-app twelve months ahead, then monthly, then weekly. A user who never updates loses the ability to reach updated contacts only after three years of warnings.

**Wire-format changes** increment `version` and require a new `PROTOCOL.md` section, AUD-1 re-review, and a full re-run of §17. **Payload-level additions** — a new `content_type` — need none of that: an unknown content type is discarded silently by an old client, which is why the type byte has room for 247 unused values.

### 19.3 Lifecycle events the product must handle

Each of these was absent from the earlier draft and each would have surfaced as a support crisis rather than a design decision.

| Event | Behaviour |
|---|---|
| **New device, backup available** | Import the `*.qwb` archive (§11.6). Identity, contacts and history are restored. Contacts see no change |
| **New device, no backup** | New identity. Every contact must be re-scanned in person. Existing contacts see an unverified new identity with an explicit warning (§11.6). **This is the expected path**, and onboarding says so |
| **Lost or stolen device** | Nothing can be done remotely — there is no server to revoke anything. The user tells contacts out of band. Contacts use **Block** on the old identity. Forward secrecy means past messages are safe if the device was locked; a device seized unlocked is a full compromise and the app says so |
| **Contact changes device** | Their new identity arrives as a new, unverified contact. The app offers to merge the conversation history only *after* safety-number verification, never before |
| **Storage full** | The relay cache is evicted first, oldest and highest-copy-count first, down to zero if necessary. The user's own messages are never evicted to make room for other people's traffic. Below 50 MB free, relaying is suspended and a single unobtrusive line appears in Advanced |
| **Contact deleted** | Session, ratchet state, tag windows and history destroyed. Cells already in flight for that contact are dropped from the outbox but cannot be recalled from the mesh — nothing can |
| **Clock badly wrong** | Tag matching tolerates ±2 h (§5.5). Beyond that, the app detects repeated match failure against a contact whose cells are arriving and prompts the user to check the device clock. It never adjusts the clock itself |
| **Password change** | Re-wraps the DEK under a new KEK. The store is not re-encrypted, since only the wrapping changes. Takes one Argon2id derivation |

### 19.4 Abuse and safety

A messaging system with no directory, no accounts and no operator cannot moderate anything. Pretending otherwise would be dishonest; ignoring the question would be worse.

- **The only moderation surface is the recipient's device**, which is why Block and Delete (§12) are core features rather than settings.
- **Contact requires physical proximity or an out-of-band channel.** There is no way to message a stranger, no discovery, no user search. This eliminates the largest category of messaging abuse by construction — the cost is that the app is useless for meeting new people, which is not what it is for.
- **No group messaging in v1.** Groups are where harassment scales, where key management gets hard, and where metadata leaks multiply. They are deferred until the one-to-one system is audited and stable, not because they are unimportant but because doing them badly is worse than not doing them.
- **The project does not claim the system cannot be misused.** It can. So can a paper envelope. The design question is whether the protections for ordinary users justify that, and the answer this project gives is yes — the same answer every encrypted messenger gives, stated openly rather than avoided.

### 19.5 Sustainability

There are no servers, so there are no running costs beyond the audit programme, the developer accounts and the signing infrastructure. There is also no revenue: no subscriptions, no ads, no telemetry, no premium tier, and nothing that could become one without breaking the architecture.

**Funding model, in order of preference:** public-interest technology grants (NLnet NGI Zero, Open Technology Fund, Sovereign Tech Fund all fund exactly this kind of work); individual donations; institutional sponsorship from organisations whose staff need the tool. **Explicitly excluded:** venture capital, because it requires a growth path that this architecture cannot provide and would create pressure toward the metadata collection the design exists to prevent.

**If funding fails**, the honest outcome is stated in advance: the code remains public and buildable under Apache-2.0, the protocol specification remains implementable under CC-BY-4.0, and the project announces that it is unmaintained rather than quietly rotting while the store listings still promise audits. **An unmaintained security product that still advertises itself as audited is worse than no product**, so the shutdown procedure is written now, while nobody is under pressure: remove the apps from stores, publish a final notice in-app, keep the repository and audit reports online.

### 19.6 Vulnerability disclosure

- A published security contact with a PGP key, monitored by at least two people.
- 90-day coordinated disclosure, with a safe-harbour clause promising no legal action against good-faith research.
- Acknowledgement within 72 hours, triage within 7 days.
- Advisories published for every fixed vulnerability, including ones found internally, with CVE identifiers requested where applicable.
- **Users are notified in-app** of any Critical or High vulnerability affecting a version they are running. Since there is no server, the notice ships with the update and appears on first launch; users who do not update are also warned by the deprecation mechanism in §19.2.

### 19.7 Governance

Small project, small structure, written down anyway so it is not improvised during a disagreement:

- A **maintainer** holds release authority and the signing keys, which live in hardware tokens.
- A **second maintainer** holds a backup signing key in separate custody. Two people, because one is a single point of failure and three is theatre at this scale.
- **Security-relevant decisions require both.** The four-eyes rule in §18.12 `INT-01` has no exception for the maintainer.
- **Architecture Decision Records** in `docs/adr/` are the memory of the project. Every decision in §3 and every correction in Appendix A has one.
- **A decision to weaken a security property requires a published ADR and a 30-day comment period** before it can merge. This is the clause that exists specifically to make a future compromise slow and visible.

---

### 19.8 Repository and GitHub configuration

The project lives at **`github.com/janpenitent/quietwire`**. That string appears in `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, the Cargo manifests' `repository` field, the Nix flake and the CI workflow permissions; a CI check fails the build if any of them disagree.

**One decision to make before the first commit: which email address signs the work.**

The commit identity is `jrodriguez@virtualcable.es`. Two consequences follow from that, neither of them obvious until later:

1. **Every commit email is public and permanent.** Git stores it in the object, GitHub renders it, and every clone and mirror carries it. It cannot be retracted from a distributed history, and it will be scraped. GitHub offers a `users.noreply.github.com` address for exactly this, and it works with signing — the signing key's identity is what GitHub verifies, and a noreply address can be the verified one.
2. **A corporate address implies the corporation.** The Developer Certificate of Origin (§19.1) is an assertion about the right to contribute. Signing off as `@virtualcable.es` reads as contributing in a work capacity, and in most jurisdictions and most employment contracts an employer has a claim on work that is company-connected. For an Apache-2.0 project with an explicit patent grant, that ambiguity is worth removing now rather than discovering during a licence question in three years.

**Recommended:** use a personal address, or `janpenitent@users.noreply.github.com`, for commits and DCO sign-off, and keep `jrodriguez@virtualcable.es` for nothing at all in this repository. If VirtualCable is in fact backing the project, the cleaner arrangement is the opposite and equally explicit: the corporate address, plus a written statement from the employer in `MAINTAINERS.md` confirming the contribution is authorised under Apache-2.0. Either is fine. The one to avoid is the middle, where nobody wrote down which it was.

For the **security contact** in `SECURITY.md`, a role address that outlives any one person is better than an individual's: `security@` on a domain the project controls, with the PGP key published in three places (§19.6). A personal mailbox becomes a single point of failure the first time someone is on holiday during a disclosure.

**Repository settings, all of which are release-blocking (`QW-C-SYS-350`):**

| Setting | Value | Why |
|---|---|---|
| Visibility | Public from the first commit | Export exemptions (§19.1) require public availability, and a repository that goes public later carries its private history with it |
| Default branch | `main`, protected | |
| Merge strategies | **Squash merge and merge commit only. Rebase merge disabled.** | See §19.9 — GitHub does not sign rebased commits, so they land unverified |
| Auto-delete head branches | On | |
| Merge queue | On, required | Keeps the reproducible-build check (§17.11 stage 8) off every push while still gating every merge |
| Force pushes to `main` | Blocked for everyone, administrators included | |
| Branch deletion of `main` | Blocked | |
| Secret scanning + push protection | On | |
| Dependabot alerts and security updates | On | Triaged per `INT-10` |
| Private vulnerability reporting | On | The intake channel for §19.6 |
| Actions permissions | `GITHUB_TOKEN` read-only by default; write granted per job | |
| Fork pull requests | Cannot access secrets, cannot run release workflows | |
| Discussions | On | Keeps design debate out of the issue tracker |
| Wiki | Off | Documentation is versioned in `docs/`, reviewed like code |

**Rulesets on `main` and on `release/*`:**

- Require a pull request, **2 approving reviews**, with `INT-02`'s cryptography reviewer enforced through `CODEOWNERS` for `crates/quietwire-crypto/**` and `crates/quietwire-e2e/**`.
- Dismiss stale approvals on new commits.
- **Require signed commits.**
- Require linear history.
- Require all §17 status checks to pass, including `reuse-lint` and `dco-check`.
- Require conversation resolution.
- **Include administrators.** A protection a maintainer can step around protects nothing, and the whole point of §19.7 is that the maintainer is not an exception.
- Require a deployment to the `release` environment, which has a manual reviewer gate, for any tag push.

**Repository files** (these belong in the tree from commit one, and §13's layout is extended accordingly):

```
LICENSES/Apache-2.0.txt
LICENSES/CC-BY-4.0.txt
LICENSES/CC0-1.0.txt
LICENSE                          -> symlink to LICENSES/Apache-2.0.txt
NOTICE                           Apache-2.0 §4(d) attribution notices
TRADEMARK.md
SECURITY.md                      disclosure policy, PGP key, 90-day terms
CONTRIBUTING.md                  DCO, signing setup, review expectations
CODE_OF_CONDUCT.md
CODEOWNERS                       @janpenitent on everything; crypto paths
                                   additionally require the crypto reviewer
MAINTAINERS.md                   who holds which key, in which custody
.reuse/dep5                      licence metadata for unmarkable files
.github/
├── workflows/                   ci.yml, nightly.yml, release.yml, reuse.yml
├── ISSUE_TEMPLATE/              bug, design, and an explicit "not for
│                                  vulnerabilities — see SECURITY.md" notice
├── PULL_REQUEST_TEMPLATE.md     which §17 tests cover this, which §18.6
│                                  checklist items it touches (INT-08)
└── dependabot.yml
.allowed_signers                 SSH signing keys, for `git log --show-signature`
rust-toolchain.toml              the exact pin (§3)
deny.toml  vet/  clippy.toml  rustfmt.toml
```

### 19.9 Commit, branch and tag signing — everything Verified

**The requirement: every commit, every merge, every tag, on every branch, shows Verified on GitHub.** No exceptions, no unsigned automation commits, no "Unverified" badge anywhere in the history. That is achievable, but only if four specific traps are avoided, and three of them are not obvious.

**Key material.** Signing keys are **hardware-backed**, because a signing key on a laptop disk is a key an attacker gets with the laptop:

- Preferred: a **YubiKey 5** (or equivalent) holding an Ed25519 OpenPGP signing subkey, touch-to-sign required.
- Acceptable alternative: **SSH signing with a FIDO2 resident key** (`sk-ssh-ed25519@openssh.com`), which is simpler to set up and equally hardware-bound.
- Each maintainer holds their own key. The backup maintainer's key is in separate physical custody (§19.7).

**Local configuration** — put this in `CONTRIBUTING.md` verbatim, because "sign your commits" without the commands produces unsigned commits:

```bash
# --- Identity: set it per-repository, not globally ---
git config user.name  "janpenitent"
git config user.email "janpenitent@users.noreply.github.com"   # see §19.8

# --- Option A: SSH signing (simplest, hardware-backed with a FIDO2 key) ---
ssh-keygen -t ed25519-sk -O resident -O verify-required -C "quietwire signing"
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519_sk.pub
git config --global commit.gpgsign true
git config --global tag.gpgsign true
git config --global push.gpgSign if-asked
git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
# then add the SAME key to GitHub twice: once as an Authentication key,
# once as a SIGNING key. Adding it only as an authentication key is the
# single most common reason commits still show Unverified.

# --- Option B: OpenPGP on a YubiKey ---
git config --global user.signingkey <KEYID>
git config --global commit.gpgsign true
git config --global tag.gpgsign true
# Upload the PUBLIC key to GitHub, and make sure the UID email matches
# the commit author email exactly, verified on the account.
```

**The four traps:**

1. **Rebase merge is never signed.** GitHub signs the squash and merge commits it creates in the web UI with its own key, and they show Verified. **Rebase-and-merge rewrites your commits on the server and GitHub does not re-sign them** — every one lands Unverified, permanently, and the only fix is rewriting history. This is why §19.8 disables rebase merge at the repository level rather than trusting people to remember.
2. **The signing email must match the commit author email**, and both must be verified on the GitHub account. A commit authored as `me@laptop.local` will not verify against a key bound to `me@example.org`. Set `user.email` per-repository and check it in CI (`dco-check` also validates this).
3. **Vigilant mode must be on.** In GitHub account settings, "Flag unsigned commits as unverified" makes every unsigned commit display an explicit **Unverified** badge instead of no badge at all. Without it, an attacker who forges an author line on an unsigned commit produces something that looks ordinary. With it, the forgery is visible. **This is the setting that makes the whole policy meaningful**, and it is off by default.
4. **Automation commits.** Anything a workflow commits must also be signed, or the history develops unsigned gaps that everyone learns to ignore:
   - Commits made through the **GitHub API** (including `peter-evans/create-pull-request` with `GITHUB_TOKEN`, and everything Dependabot does) are signed by GitHub and show Verified automatically.
   - Commits made by `git push` **from a runner are not signed**. If a workflow must push directly, it signs with a dedicated bot key stored in an environment secret and registered to a bot account — or, better, it does not push at all and uses the API instead.
   - `release.yml` never commits. It only reads a signed tag and produces artefacts.

**Tags and releases.** Every release tag is annotated and signed (`git tag -s v1.0.0 -m "…"`), pushed by a human from a hardware key, and the release workflow refuses to run on an unsigned tag:

```yaml
- name: Refuse unsigned tags
  run: |
    git verify-tag "${GITHUB_REF_NAME}" \
      || { echo "::error::Tag ${GITHUB_REF_NAME} is not signed. Refusing."; exit 1; }
```

**Branches.** A branch is not itself signed — only commits and tags are — so "verified branches" means, precisely, that every commit reachable on that branch is verified. The `main` ruleset enforces it going forward; a CI job (`QW-C-SYS-351`) walks the full history on every push and fails if any commit anywhere is unsigned:

```bash
git log --pretty='%H %G?' | awk '$2 !~ /^[GU]$/ { print; bad=1 } END { exit bad }'
```

`%G?` returns `G` for a good signature and `U` for good-but-untrusted; anything else — `N` for none, `B` for bad, `X`, `Y`, `R`, `E` — fails the build.

**The first commit sets the standard.** An unsigned initial commit can only be fixed by rewriting history, which is painful once anyone has cloned. Configure signing *before* `git init`, and verify with `git log --show-signature` before the first push.

### 19.10 Release integrity

Signed commits prove who wrote the source. They say nothing about whether the binary in the user's hand came from that source. Three further mechanisms close that gap, and all three are already required by §17.10 and §18.6 I:

- **Reproducible builds** (`flake.nix`): two independent machines produce bit-identical artefacts, and an external party reproduces every release before it is announced (`QW-C-SYS-341`).
- **SLSA Build Level 3 provenance**, generated by the GitHub-hosted reusable generator, attesting which workflow built which artefact from which commit — and published with the release.
- **A signed CycloneDX SBOM** per artefact, plus `cargo-auditable` metadata embedded in every binary so the dependency set can be recovered from the binary alone, without trusting the accompanying files.

Platform signing sits on top: Play Integrity and Play App Signing, Apple notarisation, and the Windows hardware-token code-signing certificate from §16. **Each store's signature proves the store accepted it; only the reproducible build proves it matches the source.** Users who care are told, in `SECURITY.md`, exactly how to verify the second thing themselves — with the commands, not a gesture at the concept.

---

## 20. Legal and regulatory

**This section is not optional and must be reviewed by a qualified lawyer before deployment.**

| Area | Position |
|---|---|
| EU dual-use export (Reg. 2021/821) | Strong cryptography can be export-controlled. Publicly available open-source software generally qualifies for an exemption (Note 3 to Category 5 Part 2), but this must be confirmed in writing |
| US EAR | If any distribution touches the US, file the TSU 740.13(e) notification to BIS and NSA before public release |
| ISM band 868 MHz (EU) | Licence-free; the 1 % duty cycle and +14 dBm ERP limits are enforced in software and are non-configurable |
| ISM band 915 MHz | Region-gated in software; the app refuses to transmit on a band not permitted for the selected region |
| **Amateur radio HF** | **Explicitly excluded.** Encryption to obscure meaning is prohibited on amateur bands in virtually every jurisdiction. QUIETWIRE will not operate on amateur allocations |
| Countries restricting encryption | The app ships a clear in-app warning listing jurisdictions with known restrictions. Users are responsible for their own legal position |
| GDPR | No personal data is ever processed by any operator, because there is no operator. Document this in a one-page privacy statement |
| Public availability | The export exemptions above **depend on the source being publicly available**. The Apache-2.0 / CC-BY-4.0 licensing in §19.1 is therefore a regulatory requirement, not only a preference |
| Liability and entity | The project needs a legal entity (a foundation or non-profit association) before release, to hold the signing keys, sign audit contracts and receive grant funding. A personal project holding release authority over security software is a risk to the individual and to users |
| App-store policy | Both Apple and Google permit encrypted messengers, but review is slower. Prepare export-compliance documentation in advance |

---

## 21. Decisions deliberately rejected

Recording what was *not* chosen, and why, matters as much as what was.

| Rejected | Reason |
|---|---|
| **A public web application** | A browser cannot securely hold long-term keys (XSS, extensions, no memory control), cannot run BLE reliably (Web Bluetooth is Chromium-only and requires a user gesture per connection), cannot access LoRa serial portably, and cannot relay in the background. Shipping one would be a security theatre. **Replacement: the desktop app serves an identical web UI on `127.0.0.1`, with the keys held in the native Rust process.** The user gets a browser interface; the browser never gets the keys |
| **Onion routing (Tor-style circuits)** | Requires knowing a full path in advance. In an intermittently connected DTN, circuits break constantly and relays go offline mid-route. Sealed sender with epoch tags achieves the same relay-blindness without needing routes to exist |
| **Any blockchain** | Adds a global consensus requirement to a system whose entire premise is that no global connectivity exists. Solves nothing here |
| **A discovery server or key directory** | Any central point is a censorship target, a metadata source and a single point of failure. In-person QR exchange is more secure and simpler to explain |
| **Account recovery / recovery phrases** | Every recovery mechanism is a second key, and therefore a backdoor. Explicitly rejected |
| **Python or Go for the core** | Python is unsuitable for a security core (no memory control, no constant-time guarantees, no viable mobile story). Go's GC introduces timing variability and its mobile binding story is worse than UniFFI's. Python remains, correctly, in `tools/` |
| **Writing our own crypto primitives** | Never. Only audited, widely deployed implementations |
| **Flutter or React Native** | Both abstract away exactly the low-level BLE, background-execution and secure-storage APIs that this system depends on |
| **AES-GCM** | Catastrophic on nonce reuse, and slow without AES-NI on the cheap ARM devices that will make up most of the mesh |
| **Amateur HF radio for intercontinental reach** | Technically capable, legally prohibited for encrypted traffic almost everywhere. Sneakernet and Reticulum bridges achieve the same reach lawfully |
| **GPLv3 / AGPLv3** | Cannot be distributed on Apple's App Store — settled practice since VLC's removal in 2011. A licence that cuts off iOS users is, measured by who can run the software, the least free option available here (§19.1) |
| **Dual `MIT OR Apache-2.0`** (the Rust default) | The MIT arm lets a downstream strip the patent grant, which defeats the reason Apache-2.0 was chosen |
| **A copyright-assignment CLA** | Its practical function is the ability to relicense other people's work later. DCO gives provenance without that power (§19.1) |
| **Rebase-and-merge on GitHub** | GitHub does not sign rebased commits, so every merge would land permanently Unverified. Disabled at repository level rather than left to discipline (§19.9) |
| **Sigstore / `gitsign` keyless signing** | Elegant, and GitHub does not render it as Verified. The requirement is a green badge on every commit, so OpenPGP or SSH signing it is |
| **Telemetry, crash reporting, analytics — in any form** | There is no server to send them to, and building one would create the metadata pipeline the entire design exists to avoid. Bugs are found by tests, fuzzing and audits, not by watching users |

---

## Closing note

Every requirement in the original brief is met, with two substitutions stated openly: the public web application is replaced by a local-only web interface served by the desktop node, because a browser cannot hold the keys safely; and amateur HF radio is excluded, because encrypting on those bands is illegal almost everywhere. Everything else — universal OS support, arbitrary relay devices, unlimited distance, relay blindness, maximum-grade encryption, encrypted local storage, password-gated reading and sending, and a three-screen interface — is specified above and achievable with the technologies chosen.

The system's hardest constraint is not cryptographic. It is physical: without infrastructure, distance costs time. QUIETWIRE is built to make that time acceptable rather than to pretend it does not exist.

---

## Appendix A — First design review log

This document has been reviewed line by line against itself. The corrections below are recorded rather than silently absorbed, because a plan that hides its own revision history teaches the next reader to trust it more than they should. Each entry has an ADR in `docs/adr/`.

### Design flaws — would have shipped a real weakness

| # | Section | Flaw | Correction |
|---|---|---|---|
| R-01 | §5.5 | One tag per session per hour, derived identically by both parties. Two devices emitting the same 16 bytes in the same hour would have been **visibly talking to each other**, and every cell of a conversation would have carried an identical marker letting an observer count the messages | Tags are now **directional and per-message**: a fresh value for every cell, with a 256-entry sliding window and a bounded resynchronisation path |
| R-02 | §5.6 | The Noise static key was unspecified and would naturally have been the identity key, handing every relay a permanent unique identifier and making the rotating BLE advertisement pointless | A **24-hour link pseudonym**, unrelated to identity keys. The cost to reputation and routing is stated rather than hidden |
| R-03 | §5.3 | The X3DH output bound neither the identities nor `CT_pq`. Without transcript binding the hybrid is not a sound KEM combiner and the handshake is open to unknown-key-share and key-substitution | A **transcript hash is now the HKDF salt**, binding both identities, the ephemeral, the prekeys actually used and the KEM ciphertext |
| R-04 | §6.1 | A `real/decoy` flag bit sat in the **cleartext** header, described as "local only" — it would have been visible to every relay, destroying the property cover traffic exists to create | **Bit removed.** A decoy is a self-addressed cell whose type byte is inside the encrypted payload |
| R-05 | §6.1 | The MAC was specified over bytes 0..496, which includes the mutable `ttl` and `copies` — it would have failed on the first hop. The same paragraph also claimed those fields were outside the MAC | AAD explicitly defined as `bytes[0..2] ‖ bytes[4..44]`; the mutable pair is protected hop-by-hop instead |
| R-06 | §8.2 | **Destination-keyed PRoPHET specified alongside per-message unlinkable tags.** The two are mutually exclusive: routing on a destination requires a stable destination identifier, which is exactly what the tag design destroys | Replaced with **encounter-utility routing**, which routes on properties of the carrier. Delivery gates re-baselined from 92 % to 88 % |
| R-07 | §8.5 | Replay protection was a 24-hour cache while cells may legitimately live 30 days. An attacker replaying on day two would have passed | Two mechanisms separated: **ratchet message numbers** are the replay defence; the 24-hour cache is a relay-level optimisation |
| R-08 | §11.4 | The wipe destroyed only the real slot, leaving the decoy openable — which **proves** a second store existed. Worse than not wiping | The wipe destroys **both** slots and both store files and regenerates decoy content |
| R-09 | §10.2 | `store_id` column in a shared database. Row and page counts leak the second store's existence, and one wrong `WHERE` clause leaks real data into the decoy view | **Two separate store files**, both always present, isolation enforced by the type system |
| R-10 | §10.2 | `direction`, `state`, `verified` as plaintext enums and millisecond timestamps, contradicting the claim that the schema leaks nothing | Moved inside encrypted envelopes; all timestamps bucketed to the hour |
| R-11 | §9 / §7.3 | Cover traffic at 40 cells/hour on LoRa would have needed 112 s of airtime against a 36 s legal budget — illegal **and** conspicuous | Cover traffic is now per-transport and **disabled on LoRa**, with the reduction in protection disclosed to users |
| R-12 | §12 | The UI promised *"3 hops away, carried by 4 devices"* — information the sender cannot possibly have without abandoning the privacy model | Replaced with what the device actually observes |
| R-13 | §12 | **No block or delete.** A system with no directory and no operator, and no way for a recipient to stop someone | Block, Delete and Mute are now core features, not settings |

### Factual errors

| # | Section | Error | Correction |
|---|---|---|---|
| R-14 | §5.1 | Keys "generated inside the secure element". Secure Enclave supports only P-256; StrongBox cannot hold X25519, Ed25519 or ML-KEM | Keys are generated in software; hardware **wraps** the encrypted blob |
| R-15 | §5.2 | Safety number `BLAKE3(IK_A ‖ IK_B)` is order-dependent — the two devices would compute different numbers | Canonical lexicographic ordering; commits to all three identity keys |
| R-16 | §6.2 | The inner Poly1305 tag was counted twice (396 "including tag" plus a separate 16-byte MAC) | Counted once: 40 + 396 + 16 = 452 |
| R-17 | §6.3 | Titled "380 bytes usable" with a phantom padding row; the real figure quoted elsewhere is 365 | 31 + 365 = 396 exactly |
| R-18 | §7.1 | A "rotating **16-bit** service UUID" — that range is SIG-allocated and cannot be used | 128-bit custom UUID with a stated derivation and ±1 day tolerance |
| R-19 | §7.3 | "US/ES-overseas 915 MHz" is meaningless; Spain is EU 868 | Correct regional bands with their governing standards |
| R-20 | §7.3 | LoRa airtime given as 2.1 s per cell | Recomputed: **≈ 2.8 s** at SF9/BW125/CR4:5, and the 13-cells-per-hour consequence spelled out |
| R-21 | §10.1 | "Even the SQLite file header is encrypted" — SQLCipher writes a plaintext random salt, and a passphrase key would stack PBKDF2 on Argon2 | Raw keying plus `cipher_plaintext_header_size = 0` with an external salt |
| R-22 | §11.5 | Panic trigger "a duress PIN on the lock screen" — no third-party app can observe the OS lock screen | Triggers replaced with ones an app can actually implement |
| R-23 | §16 | Budget did not sum: low column ≈ €49 000 against a stated €54 000; flat €9 000 contingency wrong at both ends | Sums corrected; contingency expressed as a percentage |
| R-24 | §18.14 | Minimum subset arithmetic wrong (€36 000–62 500, not €38 000–67 500) **and** it dropped AUD-1, the one audit whose findings cannot be patched later | Both fixed; AUD-1 is now in the non-negotiable subset |
| R-25 | §14 | `rustup target add` before setting the default toolchain; a global `uniffi-bindgen` that does not exist; no NDK | Corrected, with the reasons |
| R-26 | §15 | Attenuators required by `QW-E-TRN-220` and a power analyser required by the §17.9 battery gates were absent from the BOM; the HackRF was implied to satisfy a compliance test it cannot | Added; compliance measurement assigned to AUD-8 |
| R-27 | §14 / §18.14 | AUD-1, the design review, scheduled at T-12 — around week 40, long after everything was built on the design | Moved to the end of Phase 1, week 9. The T-12 slot becomes re-review |

### Omissions

| # | Gap | Resolution |
|---|---|---|
| R-28 | No licence stated anywhere, despite the export exemptions in §20 requiring public availability | §19.1: Apache-2.0 and CC-BY-4.0, with reasoning |
| R-29 | No protocol versioning or upgrade path for a network with no servers and no forced updates | §19.2 |
| R-30 | No answer to device loss, device replacement, storage exhaustion, clock drift or password change | §19.3 |
| R-31 | No position on abuse in a system that cannot be moderated | §19.4 |
| R-32 | No funding model, and no shutdown procedure for an unmaintained security product still advertising audits | §19.5 |
| R-33 | No vulnerability disclosure process or governance structure | §19.6, §19.7 |
| R-34 | OPK exhaustion undefined with no server to hold a prekey pool | §5.1: an OPK is burned per QR display, with a refill threshold and a visible notice on exhaustion |
| R-35 | The first message does not fit in one cell (ML-KEM ciphertext is 1 088 bytes) and no session-establishment framing existed | §6.2: a mandatory three-cell `session_init` fragment set |
| R-36 | No first-run onboarding flow, though `QW-E-APP-271` tests one | §12: a four-step setup flow |
| R-37 | Read receipts existed in the wire format with no privacy position | §12: off by default, per-contact |
| R-38 | §17 and §18 still referenced PRoPHET, epoch tags and `store_id` after those designs changed | Tests and checklists realigned; `QW-U-RTE-134b` and `AUD-RTE-F011` added specifically to stop §8.2's guarantee regressing silently |

### Known tensions, accepted rather than resolved

| # | Tension | Position |
|---|---|---|
| R-39 | Unlinkability versus routing efficiency | Unlinkability wins; ~10–20 % delivery cost accepted and reflected in the gates |
| R-40 | Unlinkability versus anti-Sybil | 24-hour pseudonyms make reputation weak. The copy bound, not reputation, is what makes Sybil attacks survivable. Stated plainly in §8.6 |
| R-41 | Deniability versus continuity | A backup archive undermines the duress store and is out of reach of the wipe. Off by default, warned every time, user decides (§11.6) |
| R-42 | LoRa reach versus traffic-analysis resistance | Cover traffic is impossible within the legal duty cycle. Protection is weaker on LoRa and users are told so (§9) |

---

## Appendix B — Second design review log

A second full pass over the corrected document. The first review found flaws in the design; this one found mostly errors of internal consistency, unstated scaling limits, and four places where a gate would have been impossible to satisfy honestly. Fewer serious findings than the first pass, which is the expected shape — but not zero, which is why the pass was worth making.

### Contradictions between sections

| # | Sections | Problem | Correction |
|---|---|---|---|
| R-43 | §17.2 / §17.5 | The Argon2id timing gate bound `≥ 400 ms` to the **slowest** device and `≤ 3 s` to the **fastest** — exactly backwards. As written, a build whose KDF parameters had been quietly reduced would pass. Compounding it, `QW-N-STO-184` demanded an unlock in under 2 s while the KDF alone was allowed 3 | Bounds attached to the correct devices; unlock gate raised to < 4 s, so nobody is ever pressured to weaken the KDF to pass a performance test |
| R-44 | §1 / §7.4 / §8.3 / §18.6 G006 | §1 promised "no internet", §8.3 priced a Reticulum-over-TCP/I2P transport, and the platform checklist asked for an app with no `INTERNET` permission "if achievable". Three positions, never reconciled | **Two build flavours.** `airgap` ships with no `INTERNET` permission in the manifest at all — verifiable by anyone with `aapt` — and `bridged` adds the internet-capable Reticulum interfaces. The guarantee becomes structural instead of a setting |
| R-45 | §6.3 | Content type `0x06 telemetry/position` appeared in the wire format and nowhere else: no UI, no consent model, no threat analysis, no test. An unreviewed location-sharing surface inside a tool built to not reveal where people are | Withdrawn from v1; the code point stays reserved for a future version that specifies it properly and passes its own AUD-1 |

### Unstated limits that would have surfaced as bugs

| # | Section | Problem | Correction |
|---|---|---|---|
| R-46 | §8.5 | A flat 500 MB relay cache on a 32 GB phone is a support ticket | `min(500 MB, 5 % of free space)` |
| R-47 | §5.5 | The tag-window memory cost was quoted for 50 contacts with no scaling rule. It is linear, so at 500 contacts the figure silently breaches the RAM gate | Dormant contacts get a 32-entry window instead of 256, widening on first contact; hard warning above 1 000 contacts. 500 contacts now costs 8.6 MB against a 90 MB budget |
| R-53 | §7.1 | Android permissions listed `ACCESS_FINE_LOCATION` **and** `neverForLocation` together, which is self-contradictory: `neverForLocation` is the declaration that removes the need for location permission on API 31+ | Split by API level, with the app requesting location only on API 26–30 where the platform forces it, and saying so |

### Factual and unit errors

| # | Section | Error | Correction |
|---|---|---|---|
| R-48 | §12 / §17.7 | "48 dp touch targets" quoted as a universal minimum. iOS uses points, with a 44 pt minimum in Apple's guidelines | Both stated; the accessibility test asserts both |
| R-49 | §12 | Launch language list said "Mandarin", which names a spoken variety and specifies no script | "Chinese (Simplified)", with the Simplified/Traditional decision made explicitly |
| R-50 | §3 / §14 | "MSRV 1.79" pinned in prose and hardcoded in a shell snippet. An MSRV is a compatibility promise to downstream consumers, which this project does not have; what it actually needs is an exact reproducibility pin | `rust-toolchain.toml` is the single source of truth, read by the snippet rather than duplicated, and advancing it is an ADR because it moves the reproducible-build baseline |
| R-55 | §15 | One iPhone cannot test both the current OS and the iOS 16 support floor | Two devices; subtotal and budget re-summed to €4 764 and €50 642 – €98 642 |

### Gates that were unrealistic as written

| # | Section | Problem | Correction |
|---|---|---|---|
| R-51 | §17.1 | "200 consecutive runs of the whole suite, zero failures" as a release gate. At roughly 9 minutes per run that is 30 hours of compute for every release, and it would have been quietly skipped within a month | 200 runs of **new and changed** tests per PR; 20 runs of the whole suite nightly |
| R-52 | §17.11 | An 18-minute reproducible-build check on every push, on top of 59 minutes of other stages. A CI pipeline people route around is worse than a shorter one they respect | Moved to the merge queue |
| R-56 | §18.14 | A €30 000 bounty reserve against a €25 000 Critical payout: one finding empties it | Replenishment policy added — top up within 30 days or publicly pause the programme rather than advertise rewards it cannot pay |

### Omissions

| # | Gap | Resolution |
|---|---|---|
| R-54 | Minimum supported OS versions appeared as scattered numbers across four sections and were never assembled | §7.1b: an explicit support matrix with the reason for each floor |
| R-57 | The licence decision was asserted in three bullet points with no analysis of the strongest counter-argument — that a copyleft licence would protect users better | §19.1 rewritten: the App Store incompatibility of GPLv3/AGPLv3 is the decisive practical fact, and MPL-2.0, MIT/BSD, the Rust dual-licence default and GPLv2 are each considered and rejected with reasons. Four-artefact licence table, SPDX identifiers, REUSE 3.2 compliance as a blocking CI check, trademark handled separately from copyright |
| R-58 | No repository configuration, no branch protection, no CODEOWNERS, no SECURITY.md, no PR template — the project had a test suite and an audit programme but no place to put them | §19.8, with settings committed as `.github/settings.yml` and drift-checked by `QW-C-SYS-350` |
| R-59 | No commit-signing policy at all, despite the whole supply-chain argument in §18.6 I depending on knowing who wrote what | §19.9, including the four traps: **rebase merge is never signed by GitHub**, the signing email must match the author email, **Vigilant Mode is off by default and is what makes the policy meaningful**, and workflow commits are signed only when made through the API. Plus `QW-C-SYS-351`, a whole-history signature walk that fails the release on a single unsigned commit anywhere |
| R-60 | Nothing distinguished "the store signed this binary" from "this binary matches the source" | §19.10: reproducible builds, SLSA L3 provenance and a signed SBOM, with the distinction stated and the verification commands given to users in `SECURITY.md` |

### Still open, deliberately

| # | Item | Position |
|---|---|---|
| R-61 | ~~The GitHub owner is a placeholder~~ **Closed.** | Resolved: `github.com/janpenitent/quietwire`. The open question that replaced it is narrower and is in §19.8 — whether commits are signed with a personal address or a corporate one, which decides whether the work is personal or employer-connected under the DCO |
| R-62 | No group messaging in v1 | Deferred deliberately (§19.4). Groups multiply key-management and metadata problems, and doing them badly is worse than not doing them |
| R-63 | iOS is a structurally weaker relay | A platform constraint, not a bug. Disclosed in-app rather than hidden (§7.1) |

### Third pass — mechanical verification

The third pass was run as checks rather than as reading, because after two careful readings the remaining errors are the kind a reader's eye slides over and a script does not.

| Check | Method | Result |
|---|---|---|
| Section cross-references | Every `§n` and `§n.m` resolved against the actual headings | 4 findings, all fixed |
| Test identifiers | Every `QW-*` reference resolved against its definition; every definition checked for duplicates | 1 undefined, 1 wildcard, fixed |
| Audit checklist identifiers | 192 IDs across A–K checked for collisions | clean |
| Review-log numbering | R-01 to R-63 checked for gaps | contiguous |
| Arithmetic | Every sum in §15, §16, §18.3 and §18.14 recomputed | all correct |
| Architecture ↔ repository | Crates named in §4 compared against §13 | 2 missing, fixed |

| # | Section | Finding | Correction |
|---|---|---|---|
| R-64 | §4 | The layer diagram omitted `quietwire-crypto` and `quietwire-ffi`, both of which §13 defines. The FFI omission mattered most: it is the **trust boundary**, and a diagram that does not draw it invites someone to put a secret above the line | Both added, with L4a labelled explicitly as the boundary above which nothing holds a secret |
| R-65 | §17.3 | `QW-U-PKT-111b` was referenced inside the `111` row as the LoRa carve-out but never given a definition. A test that exists only as a cross-reference is a test nobody runs | Defined as its own row, asserting zero decoy cells generated on a LoRa transport |
| R-66 | §15 | The power analyser cited "`QW-N-SYS-32x`" — a wildcard, not an identifier | Replaced with `QW-N-SYS-320`–`322` |
| R-67 | §19.1 | "the US EAR TSU exception under §740.13(e)" used `§` for a US regulation, colliding with this document's own convention where `§` means an internal section | Cited as `15 CFR 740.13(e)` |

Verified as correct and needing no change: the audit effort allocation in §18.3 sums to exactly 100 %; the audit costs in §18.14 sum to €142 500 – €216 500 as stated, and the minimum subset to €48 000 – €81 000 as stated; the hardware BOM sums to €4 764 and carries through §16 correctly to €50 642 – €98 642; the CI stages sum to the 59 minutes claimed; the cell arithmetic holds at every layer (512 = 60 header + 452 frame; 452 = 40 + 396 + 16; 396 = 31 + 365); and the re-baselined delivery figure of 88 % is consistent across §8, §14 and §17.4.

### Review status

Three passes have now been made. The first found 42 items, thirteen of which were design flaws that would have shipped a real weakness. The second found 21, of which three were cross-section contradictions and none broke a cryptographic guarantee. The third found 4, all of them bookkeeping.

**The curve is the point.** 42, then 21, then 4 — and the third pass needed a script to find anything at all. That is what a document converging looks like, and it is also the clearest possible signal that further self-review has stopped paying. A fourth pass by the same author would find typography.

**This document is not declared finished, and no document of this kind should ever be.** What can be said is narrower and more useful: every correction is recorded rather than absorbed, each has an ADR, the tests and audit checklists were realigned to the corrected design in the same pass rather than left to drift, and the three mechanisms most likely to let a guarantee regress silently — `QW-U-RTE-134b` (no destination-keyed routing state), `AUD-RTE-F011` (an auditor reads for it) and `QW-C-SYS-351` (whole-history signature walk) — now exist as blocking checks.

**The next review could not be done by whoever wrote this — but one more mechanical pass was still owed.** See Appendix C.

**Independent review remains the only thing that can settle this.** Self-review finds inconsistency; it does not find the assumption the author never questioned, because that assumption is invisible from the inside. That is what AUD-1 is for (§18.1), why it moved to week 9 (§14, Phase 1), and why it is in the non-negotiable funding subset (§18.14). Everything above is a plan that is internally coherent and honest about its limits. Whether it is *correct* is a question only someone else can answer.

---

## Appendix C — Full linear read

The first three passes were targeted: pass one hunted design flaws, pass two hunted contradictions, pass three ran scripts. None of them had read the document straight through, front to back, since the corrections began. This pass did exactly that, and the result is the honest argument against declaring any document of this size finished: **a full linear read found two more design flaws that three earlier passes had walked past.**

### Design flaws

| # | Section | Flaw | Correction |
|---|---|---|---|
| R-68 | §6.1 | The `flags` byte assigned bit0 to "fragment follows" and bit1 to "ack requested" — **in the cleartext header**. Every relay and every observer could read, per cell, whether it belonged to a multi-cell message and whether a reply was expected: enough to group a message's fragments together and to tell a conversation from a one-way notification, entirely from outside the encryption. This is the same mistake as the decoy bit caught in R-04, in the same byte, two bits over — and it survived three reviews because the decoy-bit correction drew the eye to what had been *removed* rather than to what was still there | All 8 bits reserved and random. Both facts already live encrypted in the payload. `QW-U-PKT-102b` asserts structurally that nothing ever reads meaning from that byte again |
| R-69 | §5.5 | `tag_secret` was derived from `SK_session` and then never changed. Anyone who compromised a device could recompute **every tag it had ever emitted**, retroactively linking months of captured traffic to one contact — unlinkability broken backwards, which is precisely what forward secrecy prevents for content and what the tag scheme silently failed to prevent for metadata | The secret ratchets once per epoch with the old value zeroized; a seized device can derive tags for a five-hour window and nothing before it. `QW-P-E2E-068b` tests it by attempting the derivation from seized state |

### Arithmetic and logic

| # | Section | Error | Correction |
|---|---|---|---|
| R-70 | §6.2 | `session_init` specified as a **three-cell** set. `CT_pq` (1 088 B) + `EK_A_pub` (32 B) is 1 120 bytes; three cells hold 1 095. Twenty-five bytes short — the handshake would have failed on every new contact | Four cells, with the fourth's remaining 335 bytes carrying the start of the first real message |
| R-71 | §5.1 | The Address was "128 bits, displayed as 8 groups of 4 base32 characters". Eight groups of four base32 characters is 160 bits. The two never matched — and the Address was a **second identity derivation that nothing in the protocol consumed** | Folded into `fp()` from §5.2: one derivation, truncated to 160 bits for display, with its purpose stated as display-only |
| R-72 | §5.5 | Window resynchronisation triggered "after eight consecutive unmatched send attempts". **A sender cannot observe a tag mismatch** — nothing comes back from a tag that did not match | Triggered by eight consecutive cells with no delivery receipt, which is observable |
| R-80 | §6.3 | `fragment_total` is a `u16`, implying a hard 23.9 MB ceiling on any message or file, stated nowhere | Stated, and enforced at send time rather than discovered at fragment 65 536 |

### Contradictions with requirements

| # | Section | Problem | Correction |
|---|---|---|---|
| R-73 | §5.7 | Hardware sealing offered "biometric or PIN release, enabling fast unlock". The brief this system exists to satisfy requires a password **to read and to send**. A fingerprint is not a password, and the clause quietly weakened the one guarantee the user asked for by name | Off by default; when enabled, the password is still required after every boot, after any fail-counter increment, and after 24 h without one. `QW-U-STO-179b` tests it against the real keystore |
| R-74 | §10.2 | `inbox_fragments` and `seen_cells` had no eviction index and no caps. A hostile peer sending fragment 40 000 of a message that never completes, from endless message ids, would have grown both tables without bound — and the periodic sweep would have full-scanned the largest tables in the database | Eviction indices added, plus three caps: 64 incomplete sets per contact, 8 MB total, 6-hour expiry. `QW-U-PKT-115b` tests it under exactly that attack |

### Stale after earlier corrections

| # | Section | Problem | Correction |
|---|---|---|---|
| R-75 | §2 | The threat table was never revisited after passes one and two. A2 still credited the 24-hour relay cache as the replay defence (R-07 moved it to ratchet message numbers); A4 still led with proof-of-relay reputation (R-40 concluded the copy bound is what actually works); A5 covered only powered-off devices though §18.7 tests a locked-but-powered-on image | All three rewritten to match what the system now does |
| R-76 | §5.4 | The root chain was rewritten with explicit argument names because `HKDF(a, b)` is ambiguous about which is the salt. **The symmetric chain three lines below it was left as `HMAC-SHA512(CK, 0x01)`** — the identical ambiguity, the identical bug class, half-fixed | Argument names written out in both |
| R-77 | §5.1 | The key table still said OPKs are "consumed on use" directly above a paragraph explaining that they are burned on *publication* | Table corrected |
| R-78 | §4, §7.1b | "No security logic exists above L4" after the layer was split into L4a and L4b; "(see below)" pointing at text that is above | Both fixed |
| R-79 | §1 | The guarantees table still promised "three screens" after §12 added a first-run flow, and "works with no internet" without the `airgap` flavour that makes it structural | Both updated |
| R-82 | §3 | Swift pinned as "5.10" in prose — the exact mistake R-50 corrected for Rust, left uncorrected one row above it in the same table | Version lives in `.swift-version` and the Xcode project, not in prose |
| R-81 | throughout | Six US spellings in a document that is otherwise consistently British English across 52 instances: *analyzed, traveling, leveling, minimizes, Defense* | Normalised. `relicense` and `Apache License 2.0` are correct as they stand — the verb and a proper noun |

### What this pass actually demonstrates

Four passes: **42, 21, 4, 15.** The count went back up, and that is the finding worth keeping.

The third pass was mechanical — scripts checking cross-references, identifiers and arithmetic — and it found four bookkeeping errors, which made the document look convergent. It was not. A machine cannot see that a bit in a cleartext header leaks fragment structure, or that a tag secret which never ratchets defeats its own purpose, or that "eight consecutive unmatched send attempts" describes something the sender has no way to observe. Those needed a human reading sentences in order, holding the whole design in mind at once.

Two of the fifteen findings were in text that three previous passes had *edited*. R-68 sits two bits away from a flaw corrected in pass one; the correction drew attention to what had been removed and away from what remained. R-76 is half of a fix applied in the same paragraph as its other half. **Corrected text is where the next bug hides**, because everyone has already looked there and remembers looking.

So: no, further self-review has not stopped paying, and the claim in Appendix B that it had was wrong. What can be said instead is narrower. This pass read every line in order and found what it found. The findings are recorded, tested and cross-checked. The next pass should be someone else's — not because this document has been exhausted, but because the specific thing a fifth pass by the same author cannot do is question an assumption they still hold. That is AUD-1, and it is the reason it sits in the non-negotiable funding subset.
