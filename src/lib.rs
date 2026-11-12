//! **virga**: the Operator's wand for Annulus.
//!
//! The wand is the only key. It is a folder `VIRGA` on a USB stick holding two secrets,
//! each locked by the Operator's words:
//!
//! - the **master secret** (`magister`), which proves the Operator himself, and is the
//!   wand's identity: its public key *is* the wand's fingerprint;
//! - the **rite secret** (`ritus`), which proves only that the wand is present, bound to
//!   the master by the master's own signature.
//!
//! A wand is made once, at one stroke, together with its spare ([`fac`]): a virgin wand,
//! cut new, never re-cut. The spare can revoke a lost wand, and a remaining wand can make
//! a new spare; both acts are written in the wands' **lineage** ([`Stirps`]), a signed,
//! hash-chained log that an installation follows.
//!
//! Everything here is written from the standards (FIPS 180-4, RFC 8032, RFC 7914,
//! RFC 8439) with no outside crates, and checked against their published vectors.

#![deny(unsafe_code)]

#[doc(hidden)]
pub mod aead;
mod ed25519;
pub mod os;
pub mod scrypt;
pub mod sha2;
mod stirps;
pub mod verba;
mod virga;

pub use scrypt::Labor;
pub use stirps::{Actus, Stirps, MAX_ACTA};
pub use virga::{
    adde, fac, quaere, vinculum_valet, Ordo, Secretum, Status, Virga, ANCORAE, DIR, FILE,
    MIN_VERBA, STIRPS,
};

/// Overwrites a secret before its memory is released.
pub fn wipe(b: &mut [u8]) {
    for x in b.iter_mut() {
        *x = 0;
    }
    std::hint::black_box(b);
}

pub fn hex(b: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(D[(x >> 4) as usize] as char);
        s.push(D[(x & 15) as usize] as char);
    }
    s
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let v = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    s.as_bytes()
        .chunks(2)
        .map(|p| Some(v(p[0])? << 4 | v(p[1])?))
        .collect()
}

fn unhex_n<const N: usize>(s: &str) -> Option<[u8; N]> {
    unhex(s)?.try_into().ok()
}

/// The bond a master key gives a rite key (what [`vinculum_valet`] checks).
pub fn vincula(master: &Clavis, ritus: &str) -> String {
    master.signa(format!("virga-vinculum|1|{}|{ritus}", master.publica()).as_bytes())
}

/// A signing key. Its seed is wiped when it is dropped, so a key lives only as long as
/// the act that needs it.
pub struct Clavis {
    seed: [u8; 32],
    expanded: ed25519::Expanded,
}

impl Clavis {
    /// The key grown from a 32-byte seed (RFC 8032's "private key").
    pub fn ex_semine(seed: [u8; 32]) -> Clavis {
        let expanded = ed25519::expand(&seed);
        Clavis { seed, expanded }
    }

    /// A key from fresh randomness.
    pub fn nova() -> Result<Clavis, String> {
        let mut seed = [0u8; 32];
        os::random(&mut seed)?;
        Ok(Clavis::ex_semine(seed))
    }

    /// The public key, 64 hex digits.
    pub fn publica(&self) -> String {
        hex(&self.expanded.public)
    }

    /// Signs `msg`; the signature is 128 hex digits.
    pub fn signa(&self, msg: &[u8]) -> String {
        hex(&ed25519::sign(&self.expanded, msg))
    }

    pub(crate) fn seed(&self) -> &[u8; 32] {
        &self.seed
    }
}

impl Drop for Clavis {
    fn drop(&mut self) {
        wipe(&mut self.seed);
    }
}

/// Whether `signature` is `public`'s signature on `msg`. Anything malformed is `false`.
pub fn verifica(public: &str, msg: &[u8], signature: &str) -> bool {
    let (Some(pk), Some(sig)) = (unhex_n::<32>(public), unhex_n::<64>(signature)) else {
        return false;
    };
    ed25519::verify(&pk, msg, &sig)
}

/// Whether `s` is a well-formed public key (64 lowercase hex digits naming a curve point).
pub fn publica_valida(s: &str) -> bool {
    unhex_n::<32>(s).is_some_and(|pk| ed25519::decodes(&pk))
}

/// A fingerprint as a person reads it aloud: the first 16 digits in fours.
pub fn breviter(fingerprint: &str) -> String {
    let head: String = fingerprint
        .chars()
        .take(16)
        .collect::<String>()
        .to_uppercase();
    head.as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}
