//! The lineage (`stirps`): the signed, hash-chained log of which wands are the Operator's.
//!
//! It begins with the making (`ORTUS`), signed by both wands made at that stroke. After
//! that only two acts exist: a living wand revokes another (`REVOCAT`), or a living wand
//! makes a new spare (`ADDIT`, signed by both). Each act's signature covers the hash of
//! everything before it, so acts cannot be reordered, dropped from the middle or moved to
//! another lineage. A revoked wand never lives again, and the last living wand cannot be
//! revoked.

use crate::sha2::sha256;
use crate::{hex, verifica, Clavis};
use std::collections::BTreeSet;

pub const MAX_ACTA: usize = 4096;
const GENESIS: &str = "virga-stirps";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Actus {
    Ortus {
        prima: String,
        secunda: String,
        sig_prima: String,
        sig_secunda: String,
    },
    Revocat {
        amissa: String,
        per: String,
        sig: String,
    },
    Addit {
        nova: String,
        per: String,
        sig_per: String,
        sig_nova: String,
    },
}

impl Actus {
    fn body(&self) -> String {
        match self {
            Actus::Ortus { prima, secunda, .. } => format!("ORTUS|{prima}|{secunda}"),
            Actus::Revocat { amissa, per, .. } => format!("REVOCAT|{amissa}|{per}"),
            Actus::Addit { nova, per, .. } => format!("ADDIT|{nova}|{per}"),
        }
    }

    fn fields(&self) -> Vec<&str> {
        match self {
            Actus::Ortus {
                prima,
                secunda,
                sig_prima,
                sig_secunda,
            } => vec!["ORTUS", prima, secunda, sig_prima, sig_secunda],
            Actus::Revocat { amissa, per, sig } => vec!["REVOCAT", amissa, per, sig],
            Actus::Addit {
                nova,
                per,
                sig_per,
                sig_nova,
            } => vec!["ADDIT", nova, per, sig_per, sig_nova],
        }
    }

    fn parse(f: &[&str]) -> Result<Actus, String> {
        let s = |x: &str| x.to_string();
        match f {
            ["ORTUS", a, b, sa, sb] => Ok(Actus::Ortus {
                prima: s(a),
                secunda: s(b),
                sig_prima: s(sa),
                sig_secunda: s(sb),
            }),
            ["REVOCAT", a, p, sg] => Ok(Actus::Revocat {
                amissa: s(a),
                per: s(p),
                sig: s(sg),
            }),
            ["ADDIT", n, p, sp, sn] => Ok(Actus::Addit {
                nova: s(n),
                per: s(p),
                sig_per: s(sp),
                sig_nova: s(sn),
            }),
            _ => Err("an act of the lineage is malformed".into()),
        }
    }
}

fn message(prev: &str, body: &str) -> Vec<u8> {
    format!("virga-stirps|1|{prev}|{body}").into_bytes()
}

fn link(prev: &str, line: &str) -> String {
    hex(&sha256(format!("{prev}|{line}").as_bytes()))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stirps {
    acta: Vec<Actus>,
    hashes: Vec<String>,
    live: BTreeSet<String>,
    ever: BTreeSet<String>,
    revoked: Vec<String>,
}

impl Stirps {
    fn empty() -> Stirps {
        Stirps {
            acta: Vec::new(),
            hashes: Vec::new(),
            live: BTreeSet::new(),
            ever: BTreeSet::new(),
            revoked: Vec::new(),
        }
    }

    fn head(&self) -> String {
        self.hashes
            .last()
            .cloned()
            .unwrap_or_else(|| hex(&sha256(GENESIS.as_bytes())))
    }

    /// Checks one act against the lineage so far and appends it.
    fn push(&mut self, act: Actus) -> Result<(), String> {
        if self.acta.len() >= MAX_ACTA {
            return Err("the lineage is too long".into());
        }
        let prev = self.head();
        let msg = message(&prev, &act.body());
        match &act {
            Actus::Ortus {
                prima,
                secunda,
                sig_prima,
                sig_secunda,
            } => {
                if !self.acta.is_empty() {
                    return Err("a lineage is begun only once".into());
                }
                if prima == secunda {
                    return Err("a wand and its spare must be two wands".into());
                }
                if !verifica(prima, &msg, sig_prima) || !verifica(secunda, &msg, sig_secunda) {
                    return Err("the making of the wands is not signed by both".into());
                }
                self.live.insert(prima.clone());
                self.live.insert(secunda.clone());
                self.ever.insert(prima.clone());
                self.ever.insert(secunda.clone());
            }
            Actus::Revocat { amissa, per, sig } => {
                if self.acta.is_empty() {
                    return Err("the lineage does not begin with the making".into());
                }
                if amissa == per {
                    return Err("a wand does not revoke itself".into());
                }
                if !self.live.contains(amissa) {
                    return Err("only a living wand can be revoked".into());
                }
                if !self.live.contains(per) {
                    return Err("a revocation must be made by a living wand".into());
                }
                if !verifica(per, &msg, sig) {
                    return Err("a revocation is not signed by the wand that made it".into());
                }
                self.live.remove(amissa);
                self.revoked.push(amissa.clone());
            }
            Actus::Addit {
                nova,
                per,
                sig_per,
                sig_nova,
            } => {
                if self.acta.is_empty() {
                    return Err("the lineage does not begin with the making".into());
                }
                if self.ever.contains(nova) {
                    return Err("a wand enters the lineage only once".into());
                }
                if !self.live.contains(per) {
                    return Err("a new spare must be made by a living wand".into());
                }
                if !verifica(per, &msg, sig_per) || !verifica(nova, &msg, sig_nova) {
                    return Err("a new spare is not signed by both wands".into());
                }
                self.live.insert(nova.clone());
                self.ever.insert(nova.clone());
            }
        }
        let line = act.fields().join("\t");
        self.hashes.push(link(&prev, &line));
        self.acta.push(act);
        Ok(())
    }

    /// Begins a lineage with the making of `prima` and `secunda`.
    pub fn ortus(prima: &Clavis, secunda: &Clavis) -> Result<Stirps, String> {
        let mut s = Stirps::empty();
        let (a, b) = (prima.publica(), secunda.publica());
        let msg = message(&s.head(), &format!("ORTUS|{a}|{b}"));
        s.push(Actus::Ortus {
            sig_prima: prima.signa(&msg),
            sig_secunda: secunda.signa(&msg),
            prima: a,
            secunda: b,
        })?;
        Ok(s)
    }

    /// `per` revokes the wand whose fingerprint is `amissa`.
    pub fn revoca(&mut self, amissa: &str, per: &Clavis) -> Result<(), String> {
        let p = per.publica();
        let msg = message(&self.head(), &format!("REVOCAT|{amissa}|{p}"));
        self.push(Actus::Revocat {
            amissa: amissa.to_string(),
            sig: per.signa(&msg),
            per: p,
        })
    }

    /// `per` brings the new wand `nova` into the lineage.
    pub fn adde(&mut self, nova: &Clavis, per: &Clavis) -> Result<(), String> {
        let (n, p) = (nova.publica(), per.publica());
        let msg = message(&self.head(), &format!("ADDIT|{n}|{p}"));
        self.push(Actus::Addit {
            sig_per: per.signa(&msg),
            sig_nova: nova.signa(&msg),
            nova: n,
            per: p,
        })
    }

    pub fn encode(&self) -> String {
        let mut out = String::new();
        for (act, hash) in self.acta.iter().zip(&self.hashes) {
            out.push_str(hash);
            out.push('\t');
            out.push_str(&act.fields().join("\t"));
            out.push('\n');
        }
        out
    }

    /// Reads a lineage and checks every act; any fault refuses the whole.
    pub fn decode(text: &str) -> Result<Stirps, String> {
        let mut s = Stirps::empty();
        for (n, line) in text.lines().enumerate() {
            let f: Vec<&str> = line.split('\t').collect();
            let (hash, rest) = f.split_first().ok_or("an empty line in the lineage")?;
            let act = Actus::parse(rest).map_err(|e| format!("lineage, line {}: {e}", n + 1))?;
            s.push(act)
                .map_err(|e| format!("lineage, line {}: {e}", n + 1))?;
            if s.head() != *hash {
                return Err(format!(
                    "lineage, line {}: does not match its chain (tampered with)",
                    n + 1
                ));
            }
        }
        if s.acta.is_empty() {
            return Err("the lineage is empty".into());
        }
        Ok(s)
    }

    /// The hash of the making: the same for every wand of one Operator's lineage.
    pub fn genus(&self) -> &str {
        &self.hashes[0]
    }

    pub fn acta(&self) -> &[Actus] {
        &self.acta
    }

    pub fn vivit(&self, fingerprint: &str) -> bool {
        self.live.contains(fingerprint)
    }

    pub fn revocata(&self, fingerprint: &str) -> bool {
        self.revoked.iter().any(|r| r == fingerprint)
    }

    pub fn vivae(&self) -> Vec<String> {
        self.live.iter().cloned().collect()
    }

    pub fn revocatae(&self) -> &[String] {
        &self.revoked
    }

    /// Whether `self` is `other` with zero or more acts after it.
    pub fn continuat(&self, other: &Stirps) -> bool {
        other.hashes.len() <= self.hashes.len() && self.hashes[..other.hashes.len()] == other.hashes
    }

    /// Of two copies of one lineage, the later one; refused if they have diverged.
    pub fn concilia(a: &Stirps, b: &Stirps) -> Result<Stirps, String> {
        if a.genus() != b.genus() {
            return Err("these wands are not of one lineage".into());
        }
        if a.continuat(b) {
            Ok(a.clone())
        } else if b.continuat(a) {
            Ok(b.clone())
        } else {
            Err(
                "the two copies of the lineage have diverged: settle it with the remaining wand"
                    .into(),
            )
        }
    }
}
