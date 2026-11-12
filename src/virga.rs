//! The wand on its stick: making it, opening it, unlocking its secrets.

use crate::scrypt::{scrypt, Labor};
use crate::stirps::Stirps;
use crate::{aead, hex, os, unhex, unhex_n, verifica, wipe, Clavis};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// The wand's folder on the stick.
pub const DIR: &str = "VIRGA";
/// The wand itself: its public keys and its two locked secrets.
pub const FILE: &str = "virga.txt";
/// The lineage.
pub const STIRPS: &str = "stirps.txt";
/// Where installations keep their anchors on the wand.
pub const ANCORAE: &str = "ancorae";
/// The fewest characters the Operator's words may have.
pub const MIN_VERBA: usize = 12;
const STAGED: &str = "VIRGA.novum";
const MAX_FILE: u64 = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ordo {
    /// The wand made first at the stroke, for daily use.
    Prima,
    /// A spare: made at the stroke, or later by a remaining wand.
    Secunda,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Secretum {
    Magister,
    Ritus,
}

impl Secretum {
    fn name(self) -> &'static str {
        match self {
            Secretum::Magister => "magister",
            Secretum::Ritus => "ritus",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Vivit,
    Revocata,
}

#[derive(Clone, Debug)]
struct Arca {
    labor: Labor,
    salt: [u8; 16],
    nonce: [u8; 12],
    sealed: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Virga {
    radix: PathBuf,
    pub nomen: String,
    pub ordo: Ordo,
    pub facta: u64,
    pub magister: String,
    pub ritus: String,
    pub vinculum: String,
    titulus: String,
    arcae: [Arca; 2],
    pub stirps: Stirps,
}

fn vinculum_msg(magister: &str, ritus: &str) -> Vec<u8> {
    format!("virga-vinculum|1|{magister}|{ritus}").into_bytes()
}

fn titulus_msg(magister: &str, nomen: &str, ordo: Ordo, facta: u64) -> Vec<u8> {
    format!("virga-titulus|1|{magister}|{nomen}|{ordo:?}|{facta}").into_bytes()
}

/// Whether `vinculum` is the master `magister`'s bond on the rite key `ritus`: the proof,
/// checkable by anyone, that a signature by `ritus` speaks for that wand.
pub fn vinculum_valet(magister: &str, ritus: &str, vinculum: &str) -> bool {
    verifica(magister, &vinculum_msg(magister, ritus), vinculum)
}

fn aad(which: Secretum, magister: &str, own: &str) -> Vec<u8> {
    format!("virga-arca|1|{}|{magister}|{own}", which.name()).into_bytes()
}

fn derive(words: &str, salt: &[u8; 16], labor: Labor) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    scrypt(words.as_bytes(), salt, labor, &mut key)?;
    Ok(key)
}

fn lock(
    key: &Clavis,
    words: &str,
    labor: Labor,
    which: Secretum,
    magister: &str,
) -> Result<Arca, String> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    os::random(&mut salt)?;
    os::random(&mut nonce)?;
    let mut k = derive(words, &salt, labor)?;
    let sealed = aead::seal(
        &k,
        &nonce,
        &aad(which, magister, &key.publica()),
        key.seed(),
    );
    wipe(&mut k);
    Ok(Arca {
        labor,
        salt,
        nonce,
        sealed,
    })
}

fn sanus(nomen: &str) -> Result<(), String> {
    if nomen.chars().count() > 64 || nomen.chars().any(|c| c.is_control()) {
        return Err("a wand's name is at most 64 plain characters".into());
    }
    Ok(())
}

fn verba_valida(magistri: &str, ritus: &str) -> Result<(), String> {
    for w in [magistri, ritus] {
        if w.chars().count() < MIN_VERBA {
            return Err(format!(
                "the words must be at least {MIN_VERBA} characters; a short sentence is best"
            ));
        }
    }
    if magistri == ritus {
        return Err(
            "the master's words and the rite's words must differ: words spoken in a rite must never open the master secret"
                .into(),
        );
    }
    Ok(())
}

fn read_bounded(path: &Path) -> Result<String, String> {
    let len = fs::metadata(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?
        .len();
    if len > MAX_FILE {
        return Err(format!(
            "{} is too large to be part of a wand",
            path.display()
        ));
    }
    fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

fn write_synced(path: &Path, text: &str) -> Result<(), String> {
    let mut f =
        fs::File::create(path).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    f.write_all(text.as_bytes())
        .and_then(|_| f.sync_all())
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

fn replace_file(path: &Path, text: &str) -> Result<(), String> {
    let tmp = path.with_extension("novum");
    write_synced(&tmp, text)?;
    fs::rename(&tmp, path).map_err(|e| format!("cannot replace {}: {e}", path.display()))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Virga {
    /// Opens the wand on a stick: `path` is the stick (holding `VIRGA`) or the `VIRGA`
    /// folder itself. Its bond and its lineage are checked; nothing is unlocked.
    pub fn aperi(path: &Path) -> Result<Virga, String> {
        let radix = if path.join(DIR).join(FILE).is_file() {
            path.join(DIR)
        } else if path.join(FILE).is_file() {
            path.to_path_buf()
        } else {
            return Err(format!("there is no wand at {}", path.display()));
        };
        let text = read_bounded(&radix.join(FILE))?;
        let stirps = Stirps::decode(&read_bounded(&radix.join(STIRPS))?)?;
        let mut v = Virga::decode(&text, radix, stirps)?;
        if !v.stirps.vivit(&v.magister) && !v.stirps.revocata(&v.magister) {
            return Err("this wand is not in its own lineage".into());
        }
        v.radix = v.radix.canonicalize().unwrap_or(v.radix.clone());
        Ok(v)
    }

    fn decode(text: &str, radix: PathBuf, stirps: Stirps) -> Result<Virga, String> {
        let bad = |what: &str| format!("the wand file is malformed: {what}");
        let mut lines = text.lines();
        if lines.next() != Some("VIRGA\t1") {
            return Err(bad("not a wand of this kind"));
        }
        let mut field = |name: &str| -> Result<Vec<String>, String> {
            let line = lines.next().ok_or_else(|| bad(name))?;
            let f: Vec<String> = line.split('\t').map(str::to_string).collect();
            if f.first().map(String::as_str) != Some(name) {
                return Err(bad(name));
            }
            Ok(f[1..].to_vec())
        };
        let one = |f: Vec<String>, name: &str| -> Result<String, String> {
            match f.as_slice() {
                [x] => Ok(x.clone()),
                _ => Err(bad(name)),
            }
        };
        let nomen = one(field("nomen")?, "nomen")?;
        let ordo = match one(field("ordo")?, "ordo")?.as_str() {
            "prima" => Ordo::Prima,
            "secunda" => Ordo::Secunda,
            _ => return Err(bad("ordo")),
        };
        let facta: u64 = one(field("facta")?, "facta")?
            .parse()
            .map_err(|_| bad("facta"))?;
        let magister = one(field("magister")?, "magister")?;
        let ritus = one(field("ritus")?, "ritus")?;
        let vinculum = one(field("vinculum")?, "vinculum")?;
        let titulus = one(field("titulus")?, "titulus")?;
        let mut arca = |which: Secretum| -> Result<Arca, String> {
            let f = field("arca")?;
            let [w, log_n, r, p, salt, nonce, sealed] = f.as_slice() else {
                return Err(bad("arca"));
            };
            if w != which.name() {
                return Err(bad("arca"));
            }
            let labor = Labor {
                log_n: log_n.parse().map_err(|_| bad("arca"))?,
                r: r.parse().map_err(|_| bad("arca"))?,
                p: p.parse().map_err(|_| bad("arca"))?,
            };
            if !labor.admissible() {
                return Err(bad("the work it asks for is inadmissible"));
            }
            Ok(Arca {
                labor,
                salt: unhex_n(salt).ok_or_else(|| bad("salt"))?,
                nonce: unhex_n(nonce).ok_or_else(|| bad("nonce"))?,
                sealed: unhex(sealed)
                    .filter(|s| s.len() == 48)
                    .ok_or_else(|| bad("sealed secret"))?,
            })
        };
        let arcae = [arca(Secretum::Magister)?, arca(Secretum::Ritus)?];
        if lines.next().is_some() {
            return Err(bad("trailing lines"));
        }
        sanus(&nomen)?;
        if !crate::publica_valida(&magister) || !crate::publica_valida(&ritus) {
            return Err(bad("a public key"));
        }
        if !vinculum_valet(&magister, &ritus, &vinculum) {
            return Err("the wand's rite secret is not bound to its master: refused".into());
        }
        if !verifica(
            &magister,
            &titulus_msg(&magister, &nomen, ordo, facta),
            &titulus,
        ) {
            return Err("the wand's name or kind has been altered: refused".into());
        }
        Ok(Virga {
            radix,
            nomen,
            ordo,
            facta,
            magister,
            ritus,
            vinculum,
            titulus,
            arcae,
            stirps,
        })
    }

    fn encode(&self) -> String {
        let mut out = format!(
            "VIRGA\t1\nnomen\t{}\nordo\t{}\nfacta\t{}\nmagister\t{}\nritus\t{}\nvinculum\t{}\ntitulus\t{}\n",
            self.nomen,
            match self.ordo {
                Ordo::Prima => "prima",
                Ordo::Secunda => "secunda",
            },
            self.facta,
            self.magister,
            self.ritus,
            self.vinculum,
            self.titulus
        );
        for (which, a) in [Secretum::Magister, Secretum::Ritus]
            .iter()
            .zip(&self.arcae)
        {
            out.push_str(&format!(
                "arca\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                which.name(),
                a.labor.log_n,
                a.labor.r,
                a.labor.p,
                hex(&a.salt),
                hex(&a.nonce),
                hex(&a.sealed)
            ));
        }
        out
    }

    /// The wand's fingerprint: its master public key.
    pub fn signum(&self) -> &str {
        &self.magister
    }

    pub fn radix(&self) -> &Path {
        &self.radix
    }

    /// The folder on the wand where installations keep their anchors.
    pub fn ancorae(&self) -> PathBuf {
        self.radix.join(ANCORAE)
    }

    pub fn status(&self) -> Status {
        if self.stirps.vivit(&self.magister) {
            Status::Vivit
        } else {
            Status::Revocata
        }
    }

    /// Unlocks one secret with the words. The key is returned for one act and wiped when
    /// dropped. Wrong words, or a secret moved from another wand or slot, fail alike.
    pub fn solve(&self, which: Secretum, words: &str) -> Result<Clavis, String> {
        let (a, own) = match which {
            Secretum::Magister => (&self.arcae[0], &self.magister),
            Secretum::Ritus => (&self.arcae[1], &self.ritus),
        };
        let mut k = derive(words, &a.salt, a.labor)?;
        let opened = aead::open(&k, &a.nonce, &aad(which, &self.magister, own), &a.sealed);
        wipe(&mut k);
        let mut seed = opened.ok_or("the words do not open this secret")?;
        let arr: [u8; 32] = seed
            .as_slice()
            .try_into()
            .map_err(|_| "a secret is malformed")?;
        wipe(&mut seed);
        let key = Clavis::ex_semine(arr);
        if key.publica() != *own {
            return Err("the secret does not match its wand".into());
        }
        Ok(key)
    }

    /// Writes a later copy of the lineage onto this wand. Never shortens or rewrites it.
    pub fn scribe_stirpem(&mut self, s: &Stirps) -> Result<(), String> {
        let later = Stirps::concilia(&self.stirps, s)?;
        if later == self.stirps {
            return Ok(());
        }
        replace_file(&self.radix.join(STIRPS), &later.encode())?;
        self.stirps = later;
        Ok(())
    }

    /// This wand revokes the lost wand `amissa`, with this wand's master words.
    pub fn revoca(&mut self, amissa: &str, verba_magistri: &str) -> Result<(), String> {
        if self.status() != Status::Vivit {
            return Err("a revoked wand revokes nothing".into());
        }
        let key = self.solve(Secretum::Magister, verba_magistri)?;
        let mut s = self.stirps.clone();
        s.revoca(amissa, &key)?;
        self.scribe_stirpem(&s)
    }
}

#[allow(clippy::too_many_arguments)]
fn forge(
    master: &Clavis,
    rite: &Clavis,
    verba_magistri: &str,
    verba_ritus: &str,
    nomen: &str,
    ordo: Ordo,
    facta: u64,
    labor: Labor,
    stirps: Stirps,
) -> Result<Virga, String> {
    let magister = master.publica();
    let ritus = rite.publica();
    let vinculum = master.signa(&vinculum_msg(&magister, &ritus));
    let titulus = master.signa(&titulus_msg(&magister, nomen, ordo, facta));
    let arcae = [
        lock(master, verba_magistri, labor, Secretum::Magister, &magister)?,
        lock(rite, verba_ritus, labor, Secretum::Ritus, &magister)?,
    ];
    Ok(Virga {
        radix: PathBuf::new(),
        nomen: nomen.to_string(),
        ordo,
        facta,
        magister,
        ritus,
        vinculum,
        titulus,
        arcae,
        stirps,
    })
}

/// Checks that `stick` can take a new wand: it exists, and holds no wand.
fn virgin(stick: &Path) -> Result<PathBuf, String> {
    let real = stick
        .canonicalize()
        .map_err(|e| format!("cannot find {}: {e}", stick.display()))?;
    if !real.is_dir() {
        return Err(format!("{} is not a folder or a drive", stick.display()));
    }
    if real.join(DIR).exists() {
        return Err(format!(
            "{} already holds a wand: a wand is cut once, and never re-cut",
            stick.display()
        ));
    }
    Ok(real)
}

/// Writes the wand into `<stick>/VIRGA.novum`, ready to be put in place.
fn stage(stick: &Path, v: &Virga) -> Result<PathBuf, String> {
    let staged = stick.join(STAGED);
    if staged.exists() {
        fs::remove_dir_all(&staged).map_err(|e| {
            format!(
                "cannot clear an unfinished wand at {}: {e}",
                staged.display()
            )
        })?;
    }
    fs::create_dir(&staged).map_err(|e| format!("cannot write to {}: {e}", stick.display()))?;
    fs::create_dir(staged.join(ANCORAE))
        .map_err(|e| format!("cannot write to {}: {e}", stick.display()))?;
    write_synced(&staged.join(FILE), &v.encode())?;
    write_synced(&staged.join(STIRPS), &v.stirps.encode())?;
    Ok(staged)
}

/// Makes the wand and its spare at one stroke, on two virgin sticks. Both are written in
/// full, then both are put in place; if a step fails, what was put in place is taken back.
/// Two sticks cannot be changed in one indivisible act: if the power fails between the two
/// last steps, the spare's stick holds a finished but unplaced wand (`VIRGA.novum`), and
/// [`perfice`] puts it in place (audit V05).
pub fn fac(
    prima: &Path,
    secunda: &Path,
    verba_magistri: &str,
    verba_ritus: &str,
    nomen: &str,
    labor: Labor,
) -> Result<(Virga, Virga), String> {
    verba_valida(verba_magistri, verba_ritus)?;
    sanus(nomen)?;
    if !labor.admissible() {
        return Err("a wand is made only with the standard amount of work".into());
    }
    let a = virgin(prima)?;
    let b = virgin(secunda)?;
    if a == b || a.starts_with(&b) || b.starts_with(&a) {
        return Err("the wand and its spare must be made on two different sticks".into());
    }
    let (ma, ra, mb, rb) = (
        Clavis::nova()?,
        Clavis::nova()?,
        Clavis::nova()?,
        Clavis::nova()?,
    );
    let stirps = Stirps::ortus(&ma, &mb)?;
    let facta = now();
    let mut va = forge(
        &ma,
        &ra,
        verba_magistri,
        verba_ritus,
        nomen,
        Ordo::Prima,
        facta,
        labor,
        stirps.clone(),
    )?;
    let mut vb = forge(
        &mb,
        &rb,
        verba_magistri,
        verba_ritus,
        nomen,
        Ordo::Secunda,
        facta,
        labor,
        stirps,
    )?;
    let sa = stage(&a, &va)?;
    let sb = match stage(&b, &vb) {
        Ok(s) => s,
        Err(e) => {
            let _ = fs::remove_dir_all(&sa);
            return Err(e);
        }
    };
    if let Err(e) = fs::rename(&sa, a.join(DIR)) {
        let _ = fs::remove_dir_all(&sa);
        let _ = fs::remove_dir_all(&sb);
        return Err(format!("cannot put the wand in place: {e}"));
    }
    if let Err(e) = fs::rename(&sb, b.join(DIR)) {
        let _ = fs::remove_dir_all(a.join(DIR));
        let _ = fs::remove_dir_all(&sb);
        return Err(format!(
            "cannot put the spare in place: {e}; neither was made"
        ));
    }
    sync_dir(&a);
    sync_dir(&b);
    va.radix = a.join(DIR);
    vb.radix = b.join(DIR);
    Ok((va, vb))
}

/// A remaining wand makes a new spare on a virgin stick. The Operator's words must open
/// both of the remaining wand's secrets; the new spare is locked with the same words.
pub fn adde(
    remaining: &mut Virga,
    stick: &Path,
    verba_magistri: &str,
    verba_ritus: &str,
    labor: Labor,
) -> Result<Virga, String> {
    if remaining.status() != Status::Vivit {
        return Err("a revoked wand makes nothing".into());
    }
    verba_valida(verba_magistri, verba_ritus)?;
    if !labor.admissible() {
        return Err("a wand is made only with the standard amount of work".into());
    }
    let target = virgin(stick)?;
    let master = remaining.solve(Secretum::Magister, verba_magistri)?;
    remaining.solve(Secretum::Ritus, verba_ritus)?;
    let (mn, rn) = (Clavis::nova()?, Clavis::nova()?);
    let mut stirps = remaining.stirps.clone();
    stirps.adde(&mn, &master)?;
    let mut v = forge(
        &mn,
        &rn,
        verba_magistri,
        verba_ritus,
        &remaining.nomen.clone(),
        Ordo::Secunda,
        now(),
        labor,
        stirps.clone(),
    )?;
    // The order matters (audit V05): the new spare is written in full first, then the
    // remaining wand records it, then the spare is put in place. If the last step is
    // interrupted, the spare waits finished as `VIRGA.novum` and `perfice` places it.
    let staged = stage(&target, &v)?;
    if let Err(e) = remaining.scribe_stirpem(&stirps) {
        let _ = fs::remove_dir_all(&staged);
        return Err(e);
    }
    fs::rename(&staged, target.join(DIR)).map_err(|e| {
        format!(
            "the spare is made but not yet in place ({e}): run `virga perfice {}`",
            target.display()
        )
    })?;
    sync_dir(&target);
    v.radix = target.join(DIR);
    Ok(v)
}

/// Makes sure a renamed folder is on the stick, where the system allows it.
fn sync_dir(dir: &Path) {
    if let Ok(f) = fs::File::open(dir) {
        let _ = f.sync_all();
    }
}

/// Finishes an interrupted stroke: a stick holding a complete wand in `VIRGA.novum` and no
/// `VIRGA` has it put in place, once it is checked to be whole and of its lineage.
pub fn perfice(stick: &Path) -> Result<Virga, String> {
    let staged = stick.join(STAGED);
    if stick.join(DIR).exists() {
        return Err(format!("{} already holds a wand", stick.display()));
    }
    if !staged.join(FILE).is_file() {
        return Err(format!(
            "there is no unfinished wand on {}",
            stick.display()
        ));
    }
    Virga::aperi(&staged).map_err(|e| format!("the unfinished wand is not whole: {e}"))?;
    fs::rename(&staged, stick.join(DIR))
        .map_err(|e| format!("cannot put the wand in place: {e}"))?;
    sync_dir(stick);
    Virga::aperi(stick)
}

/// Where a plugged-in wand may be: every drive letter on Windows, the usual mount points
/// elsewhere. Returns each folder that holds a `VIRGA`.
pub fn quaere() -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    if cfg!(windows) {
        for l in b'A'..=b'Z' {
            roots.push(PathBuf::from(format!("{}:\\", l as char)));
        }
    } else {
        for base in ["/media", "/run/media", "/mnt", "/Volumes"] {
            let Ok(rd) = fs::read_dir(base) else { continue };
            for e in rd.flatten() {
                let p = e.path();
                roots.push(p.clone());
                if let Ok(inner) = fs::read_dir(&p) {
                    roots.extend(inner.flatten().map(|e| e.path()));
                }
            }
        }
    }
    roots
        .into_iter()
        .filter(|r| r.join(DIR).join(FILE).is_file())
        .collect()
}
