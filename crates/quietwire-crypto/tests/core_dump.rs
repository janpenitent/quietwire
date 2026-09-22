// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! QW-U-CRY-052: the whole memory image of an unlocked process holds its key
//! material only in `mlock`ed pages, and once locked holds none of it.
//!
//! The test runs itself again as a child that unlocks a vault from material
//! piped in on stdin. The parent then reads every mapping of the child
//! through `/proc/<pid>/mem`, which is what a full core dump would contain.

#![cfg(all(target_os = "linux", not(miri)))]
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    env,
    fs::{self, File},
    hint::black_box,
    io::{self, BufRead, BufReader, Read, Write},
    os::{fd::AsFd, unix::fs::FileExt},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

use argon2::{Algorithm, Argon2, Params, Version};
use quietwire_crypto::{
    ed25519::SigningKey,
    hierarchy::{Dek, Kek, Purpose, WrappedDek, WRAPPED_DEK_LEN},
    mlkem::{self, DecapsulationKey, CIPHERTEXT_LEN},
    password::{derive_kek, KdfParams, Salt},
    x25519, SecretKey,
};
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

const TEST_NAME: &str = "keys_live_only_in_locked_pages_and_vanish_on_lock";
const CHILD_ENV: &str = "QW_CORE_DUMP_CHILD";
const UNLOCKED: &str = "qw-core-dump: unlocked";
const LOCKED: &str = "qw-core-dump: locked";
const KEY_LEN: usize = 32;
const PASSWORD_LEN: usize = 32;
const PARAMS: KdfParams = KdfParams::MOBILE;
const PURPOSES: [Purpose; 5] = [
    Purpose::Db,
    Purpose::Field,
    Purpose::Identity,
    Purpose::Sessions,
    Purpose::Meta,
];
const MATERIAL_LEN: usize = PASSWORD_LEN + KEY_LEN + WRAPPED_DEK_LEN + 5 * KEY_LEN + CIPHERTEXT_LEN;
const EIO: i32 = 5;
/// `VmFlags` the kernel leaves out of a core dump: `VM_DONTDUMP`, `VM_IO` and
/// `VM_PFNMAP`, the last two being device memory rather than process memory.
const NOT_DUMPED_FLAGS: [&str; 3] = ["dd", "io", "pf"];

#[test]
fn keys_live_only_in_locked_pages_and_vanish_on_lock() {
    if env::var_os(CHILD_ENV).is_some() {
        run_vault();
        return;
    }
    let (material, needles) = vault_material();
    let mut vault = VaultProcess::spawn(&material);

    let unlocked_hits = vault.scan(&needles);
    vault.lock();
    let locked_hits = vault.scan(&needles);
    vault.exit();

    assert_every_resident_key_found(&needles, &unlocked_hits);
    let outside_locked: Vec<_> = unlocked_hits.iter().filter(|hit| !hit.locked).collect();
    assert!(outside_locked.is_empty(), "{outside_locked:#?}");
    assert!(locked_hits.is_empty(), "{locked_hits:#?}");
}

fn assert_every_resident_key_found(needles: &[Needle], hits: &[Hit]) {
    for needle in needles.iter().filter(|needle| needle.resident) {
        assert!(
            hits.iter().any(|hit| hit.needle == needle.name),
            "{} is not in the image of the unlocked process",
            needle.name
        );
    }
}

struct Needle {
    name: &'static str,
    bytes: [u8; KEY_LEN],
    resident: bool,
}

impl Needle {
    const fn resident(name: &'static str, bytes: [u8; KEY_LEN]) -> Self {
        Self {
            name,
            bytes,
            resident: true,
        }
    }

    const fn transient(name: &'static str, bytes: [u8; KEY_LEN]) -> Self {
        Self {
            name,
            bytes,
            resident: false,
        }
    }
}

#[derive(Debug)]
struct Hit {
    needle: &'static str,
    #[expect(dead_code, reason = "shown by the failure report")]
    address: u64,
    #[expect(dead_code, reason = "shown by the failure report")]
    mapping: String,
    locked: bool,
}

fn random_bytes() -> [u8; KEY_LEN] {
    *SecretKey::random().unwrap().expose_secret()
}

fn key(bytes: &[u8]) -> SecretKey {
    SecretKey::from_slice(bytes).unwrap()
}

fn vault_material() -> (Vec<u8>, Vec<Needle>) {
    let password = random_bytes();
    let salt = random_bytes();
    let kek = argon2id(&password, &salt);
    let dek = random_bytes();
    let wrapped = Dek::from(key(&dek))
        .wrap_with(&Kek::from(key(&kek)))
        .unwrap();
    let x25519_private = random_bytes();
    let x25519_peer = x25519::PrivateKey::from(key(&random_bytes())).public_key();
    let ed25519_seed = random_bytes();
    let (mlkem_d, mlkem_z) = (random_bytes(), random_bytes());
    let (ciphertext, mlkem_shared) = DecapsulationKey::from_seed(key(&mlkem_d), key(&mlkem_z))
        .encapsulation_key()
        .encapsulate()
        .unwrap();

    let material = [
        &password[..],
        &salt,
        &wrapped.to_bytes(),
        &x25519_private,
        x25519_peer.as_bytes(),
        &ed25519_seed,
        &mlkem_d,
        &mlkem_z,
        ciphertext.as_bytes(),
    ]
    .concat();
    let x25519_shared = x25519::PrivateKey::from(key(&x25519_private))
        .diffie_hellman(&x25519_peer)
        .unwrap();
    let ed25519_hash = Sha512::digest(ed25519_seed);
    let (ed25519_scalar, ed25519_prefix) = ed25519_hash.split_at(KEY_LEN);

    let mut needles = vec![
        Needle::transient("password", password),
        Needle::transient("kek", kek),
        Needle::resident("dek", dek),
        Needle::resident("x25519 private key", x25519_private),
        Needle::transient("x25519 clamped scalar", clamped(x25519_private)),
        Needle::resident("x25519 shared secret", *x25519_shared.expose_secret()),
        Needle::resident("ed25519 seed", ed25519_seed),
        Needle::transient("ed25519 scalar", ed25519_scalar.try_into().unwrap()),
        Needle::transient("ed25519 prefix", ed25519_prefix.try_into().unwrap()),
        Needle::resident("ml-kem d", mlkem_d),
        Needle::resident("ml-kem z", mlkem_z),
        Needle::resident("ml-kem shared key", *mlkem_shared.expose_secret()),
    ];
    let dek = Dek::from(key(&dek));
    needles.extend(PURPOSES.map(|purpose| {
        Needle::resident("dek subkey", *dek.subkey(purpose).unwrap().expose_secret())
    }));
    (material, needles)
}

fn argon2id(password: &[u8], salt: &[u8]) -> [u8; KEY_LEN] {
    let params = Params::new(
        PARAMS.memory_kib(),
        PARAMS.iterations(),
        PARAMS.parallelism(),
        Some(KEY_LEN),
    )
    .unwrap();
    let mut kek = [0; KEY_LEN];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, &mut kek)
        .unwrap();
    kek
}

fn clamped(mut scalar: [u8; KEY_LEN]) -> [u8; KEY_LEN] {
    scalar[0] &= 0b1111_1000;
    scalar[KEY_LEN - 1] &= 0b0111_1111;
    scalar[KEY_LEN - 1] |= 0b0100_0000;
    scalar
}

struct VaultProcess {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl VaultProcess {
    fn spawn(material: &[u8]) -> Self {
        let mut child = Command::new(env::current_exe().unwrap())
            .args([TEST_NAME, "--exact", "--nocapture"])
            .env(CHILD_ENV, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(material).unwrap();
        let mut vault = Self {
            stdout: BufReader::new(child.stdout.take().unwrap()),
            child,
            stdin,
        };
        vault.wait_for(UNLOCKED);
        vault
    }

    fn lock(&mut self) {
        self.stdin.write_all(b"l").unwrap();
        self.wait_for(LOCKED);
    }

    fn exit(mut self) {
        self.stdin.write_all(b"q").unwrap();
        assert!(self.child.wait().unwrap().success());
    }

    fn wait_for(&mut self, marker: &str) {
        let mut line = String::new();
        while !line.contains(marker) {
            line.clear();
            let read = self.stdout.read_line(&mut line).unwrap();
            assert_ne!(
                read, 0,
                "the vault process ended before printing {marker:?}"
            );
        }
    }

    fn scan(&self, needles: &[Needle]) -> Vec<Hit> {
        let pid = self.child.id();
        let memory = File::open(format!("/proc/{pid}/mem")).unwrap();
        mappings(pid)
            .iter()
            .filter(|mapping| mapping.is_dumped())
            .flat_map(|mapping| mapping.hits(&memory, needles))
            .collect()
    }
}

struct Mapping {
    start: u64,
    end: u64,
    readable: bool,
    name: String,
    flags: Vec<String>,
}

impl Mapping {
    fn parse(header: &str) -> Option<Self> {
        let mut fields = header.split_whitespace();
        let (start, end) = fields.next()?.split_once('-')?;
        Some(Self {
            start: u64::from_str_radix(start, 16).ok()?,
            end: u64::from_str_radix(end, 16).ok()?,
            readable: fields.next()?.starts_with('r'),
            name: fields.nth(3).unwrap_or_default().to_owned(),
            flags: Vec::new(),
        })
    }

    fn is_dumped(&self) -> bool {
        self.readable && !NOT_DUMPED_FLAGS.iter().any(|flag| self.has_flag(flag))
    }

    /// `lo` is `VM_LOCKED`; `mlock` splits a mapping so that the locked range
    /// gets a line of its own.
    fn is_locked(&self) -> bool {
        self.has_flag("lo")
    }

    fn has_flag(&self, flag: &str) -> bool {
        self.flags.iter().any(|f| f == flag)
    }

    fn hits(&self, memory: &File, needles: &[Needle]) -> Vec<Hit> {
        let contents = self.read(memory);
        needles
            .iter()
            .flat_map(|needle| {
                contents
                    .windows(KEY_LEN)
                    .enumerate()
                    .filter(|(_, window)| *window == needle.bytes)
                    .map(|(offset, _)| self.hit(needle, offset))
            })
            .collect()
    }

    /// Guard regions (`gu`) fault on every access, so their pages are left
    /// zeroed, as a core dump leaves them.
    fn read(&self, memory: &File) -> Vec<u8> {
        let mut contents = vec![0; usize::try_from(self.end - self.start).unwrap()];
        let page_size = region::page::size();
        let addresses = (self.start..).step_by(page_size);
        for (page, address) in contents.chunks_mut(page_size).zip(addresses) {
            match memory.read_exact_at(page, address) {
                Err(error) if error.raw_os_error() == Some(EIO) && self.has_flag("gu") => {}
                result => result.unwrap_or_else(|error| panic!("reading {address:x}: {error}")),
            }
        }
        contents
    }

    fn hit(&self, needle: &Needle, offset: usize) -> Hit {
        Hit {
            needle: needle.name,
            address: self.start + u64::try_from(offset).unwrap(),
            mapping: self.name.clone(),
            locked: self.is_locked(),
        }
    }
}

fn mappings(pid: u32) -> Vec<Mapping> {
    let smaps = fs::read_to_string(format!("/proc/{pid}/smaps")).unwrap();
    let mut mappings: Vec<Mapping> = Vec::new();
    for line in smaps.lines() {
        if let Some(flags) = line.strip_prefix("VmFlags:") {
            mappings.last_mut().unwrap().flags =
                flags.split_whitespace().map(str::to_owned).collect();
        } else if let Some(mapping) = Mapping::parse(line) {
            mappings.push(mapping);
        }
    }
    mappings
}

struct UnlockedVault {
    _dek_subkeys: Vec<SecretKey>,
    _x25519_shared: SecretKey,
    _mlkem_shared: SecretKey,
    _x25519: x25519::PrivateKey,
    _ed25519: SigningKey,
    _mlkem: DecapsulationKey,
    _dek: Dek,
}

fn run_vault() {
    let mut stdin = File::from(io::stdin().as_fd().try_clone_to_owned().unwrap());
    let vault = unlock(&mut stdin);
    println!("{UNLOCKED}");
    wait_for_command(&mut stdin);
    drop(vault);
    println!("{LOCKED}");
    wait_for_command(&mut stdin);
}

fn wait_for_command(stdin: &mut File) {
    stdin.read_exact(&mut [0]).unwrap();
}

fn unlock(stdin: &mut File) -> UnlockedVault {
    let mut material = Zeroizing::new([0; MATERIAL_LEN]);
    stdin.read_exact(material.as_mut_slice()).unwrap();
    let mut fields = Fields(material.as_slice());

    let kek = derive_kek(
        fields.take(PASSWORD_LEN),
        &salt(fields.take(KEY_LEN)),
        &PARAMS,
    )
    .unwrap();
    let dek = WrappedDek::from_bytes(fields.take(WRAPPED_DEK_LEN).try_into().unwrap())
        .unwrap_with(&kek)
        .unwrap();
    drop(kek);
    let x25519 = x25519::PrivateKey::from(key(fields.take(KEY_LEN)));
    let x25519_peer = x25519::PublicKey::from_bytes(fields.take(KEY_LEN).try_into().unwrap());
    let ed25519 = SigningKey::from(key(fields.take(KEY_LEN)));
    let mlkem = DecapsulationKey::from_seed(key(fields.take(KEY_LEN)), key(fields.take(KEY_LEN)));
    let ciphertext = mlkem::Ciphertext::from_bytes(fields.take(CIPHERTEXT_LEN).try_into().unwrap());

    black_box(ed25519.sign(b"unlocked"));
    UnlockedVault {
        _dek_subkeys: PURPOSES.map(|purpose| dek.subkey(purpose).unwrap()).into(),
        _x25519_shared: x25519.diffie_hellman(&x25519_peer).unwrap(),
        _mlkem_shared: mlkem.decapsulate(&ciphertext),
        _x25519: x25519,
        _ed25519: ed25519,
        _mlkem: mlkem,
        _dek: dek,
    }
}

fn salt(bytes: &[u8]) -> Salt {
    Salt::from_bytes(bytes.try_into().unwrap())
}

struct Fields<'a>(&'a [u8]);

impl<'a> Fields<'a> {
    fn take(&mut self, len: usize) -> &'a [u8] {
        let (field, rest) = self.0.split_at(len);
        self.0 = rest;
        field
    }
}
