<!--
SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>

SPDX-License-Identifier: CC-BY-4.0
-->

# QUIETWIRE threat model

Extracted from sections 1–2 of the project plan (`README.md`).

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
