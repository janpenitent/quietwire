<!--
SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>

SPDX-License-Identifier: CC-BY-4.0
-->

# QUIETWIRE protocol specification

Normative. Extracted from sections 5–9 of the project plan (`README.md`); changes to the wire format follow §19.2.

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

The byte-level construction is fixed by ADR-0014:

- **Subkeys**: `HKDF-SHA512(ikm = DEK, salt = empty, info = "QUIETWIRE-DEK-v1" ‖ label, L = 32)`, with the labels shown in the diagram.
- **Wrapped DEK**: XChaCha20-Poly1305 under the KEK, AAD `"QUIETWIRE-DEK-WRAP-v1"`, stored as 72 bytes: `nonce (24) ‖ ciphertext (32) ‖ tag (16)`. Changing the password rewraps the DEK; the data is not re-encrypted.
- **KEK**: Argon2id v1.3 with no secret and no associated data; only the two profiles above can be constructed.

Every long-lived symmetric key sits alone at the start of its own 16 KiB-aligned allocation, wiped on drop. That allocation is `mlock`ed when the OS page size divides 16 KiB and the lock limit allows it; on larger pages it stays unlocked rather than lock unrelated heap data, and the implementation reports which case applies.

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
