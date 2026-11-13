//! The wand: making, opening, unlocking, the lineage, and attacks on each.

use std::fs;
use std::path::PathBuf;
use virga::{Labor, Ordo, Secretum, Status, Stirps, Virga};

const LEVIS: Labor = Labor {
    log_n: 4,
    r: 1,
    p: 1,
};
const M: &str = "the master's own words";
const R: &str = "words for the rite alone";

fn stick(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("virga-test-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

fn pair(tag: &str) -> (Virga, Virga, PathBuf, PathBuf) {
    let (a, b) = (stick(&format!("{tag}-a")), stick(&format!("{tag}-b")));
    let (va, vb) = virga::fac(&a, &b, M, R, "test", LEVIS).unwrap();
    (va, vb, a, b)
}

#[test]
fn made_at_one_stroke_and_opened() {
    let (va, vb, a, b) = pair("made");
    assert_eq!(va.ordo, Ordo::Prima);
    assert_eq!(vb.ordo, Ordo::Secunda);
    assert_ne!(va.signum(), vb.signum());
    assert_eq!(va.stirps, vb.stirps);
    let oa = Virga::aperi(&a).unwrap();
    assert_eq!(oa.signum(), va.signum());
    assert_eq!(Virga::aperi(&b).unwrap().signum(), vb.signum());
    assert_eq!(oa.status(), Status::Vivit);
    let k = oa.solve(Secretum::Magister, M).unwrap();
    assert_eq!(k.publica(), oa.magister);
    let r = oa.solve(Secretum::Ritus, R).unwrap();
    assert_eq!(r.publica(), oa.ritus);
    assert!(oa.ancorae().is_dir());
    assert!(!a.join("VIRGA.novum").exists());
}

#[test]
fn the_wrong_words_open_nothing() {
    let (va, _, _, _) = pair("words");
    assert!(va.solve(Secretum::Magister, R).is_err());
    assert!(va.solve(Secretum::Ritus, M).is_err());
    assert!(va
        .solve(Secretum::Magister, "the master's own word")
        .is_err());
}

#[test]
fn words_must_be_long_and_different() {
    let (a, b) = (stick("short-a"), stick("short-b"));
    assert!(virga::fac(&a, &b, "short", R, "", LEVIS).is_err());
    assert!(virga::fac(&a, &b, M, M, "", LEVIS).is_err());
    assert!(!a.join("VIRGA").exists() && !b.join("VIRGA").exists());
}

#[test]
fn a_wand_is_never_recut() {
    let (_, _, a, b) = pair("recut");
    let c = stick("recut-c");
    assert!(virga::fac(&a, &c, M, R, "", LEVIS).is_err());
    assert!(virga::fac(&c, &b, M, R, "", LEVIS).is_err());
    assert!(!c.join("VIRGA").exists(), "a failed stroke leaves nothing");
    assert!(
        virga::fac(&c, &c, M, R, "", LEVIS).is_err(),
        "two sticks are needed"
    );
}

fn rewrite(stick: &std::path::Path, f: impl Fn(&str) -> String) {
    let p = stick.join("VIRGA").join("virga.txt");
    let t = fs::read_to_string(&p).unwrap();
    fs::write(&p, f(&t)).unwrap();
}

#[test]
fn a_doctored_wand_is_refused() {
    let (va, vb, a, _) = pair("doctor");
    // another rite key, bound by nobody
    let other = virga::Clavis::ex_semine([9; 32]).publica();
    rewrite(&a, |t| t.replace(&va.ritus, &other));
    assert!(Virga::aperi(&a).is_err());
    rewrite(&a, |t| t.replace(&other, &va.ritus));
    assert!(Virga::aperi(&a).is_ok());
    // the name and kind are under the bond too
    rewrite(&a, |t| t.replace("ordo\tprima", "ordo\tsecunda"));
    assert!(Virga::aperi(&a).is_err());
    rewrite(&a, |t| t.replace("ordo\tsecunda", "ordo\tprima"));
    // the spare's locked master secret moved into the wand does not open
    let spare = fs::read_to_string(vb.radix().join("virga.txt")).unwrap();
    let spare_arca = spare
        .lines()
        .find(|l| l.starts_with("arca\tmagister"))
        .unwrap()
        .to_string();
    rewrite(&a, |t| {
        t.lines()
            .map(|l| {
                if l.starts_with("arca\tmagister") {
                    spare_arca.clone()
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"
    });
    let v = Virga::aperi(&a).unwrap();
    assert!(v.solve(Secretum::Magister, M).is_err());
    // the rite secret moved into the master slot does not open either
    let own = fs::read_to_string(va.radix().join("virga.txt")).unwrap();
    let rite_arca = own.lines().find(|l| l.starts_with("arca\tritus")).unwrap();
    let as_master = rite_arca.replacen("arca\tritus", "arca\tmagister", 1);
    rewrite(&a, |t| {
        t.lines()
            .map(|l| {
                if l.starts_with("arca\tmagister") {
                    as_master.clone()
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"
    });
    assert!(Virga::aperi(&a)
        .unwrap()
        .solve(Secretum::Magister, R)
        .is_err());
    // a wand asking for absurd work is refused before any work is done
    let heavy = own.replacen("arca\tmagister\t4\t", "arca\tmagister\t30\t", 1);
    fs::write(va.radix().join("virga.txt"), heavy).unwrap();
    assert!(Virga::aperi(&a).is_err());
}

#[test]
fn the_spare_revokes_a_lost_wand() {
    let (va, _, a, b) = pair("revoke");
    let mut spare = Virga::aperi(&b).unwrap();
    assert!(
        spare.revoca(va.signum(), R).is_err(),
        "the rite words do not revoke"
    );
    spare.revoca(va.signum(), M).unwrap();
    let spare = Virga::aperi(&b).unwrap();
    assert!(spare.stirps.revocata(va.signum()));
    assert_eq!(spare.stirps.vivae(), vec![spare.signum().to_string()]);
    // the lost wand's own copy is behind; joined with the spare's, the later one wins
    let lost = Virga::aperi(&a).unwrap();
    let joined = Stirps::concilia(&lost.stirps, &spare.stirps).unwrap();
    assert!(joined.revocata(va.signum()));
    // once its copy is brought up to date, the lost wand is revoked and does nothing
    let mut lost = lost;
    lost.scribe_stirpem(&spare.stirps).unwrap();
    assert_eq!(Virga::aperi(&a).unwrap().status(), Status::Revocata);
    assert!(lost.revoca(spare.signum(), M).is_err());
    let c = stick("revoke-c");
    assert!(virga::adde(&mut lost, &c, M, R, LEVIS).is_err());
}

#[test]
fn the_last_wand_cannot_be_revoked_and_none_revokes_itself() {
    let (va, vb, _, b) = pair("last");
    let mut spare = Virga::aperi(&b).unwrap();
    assert!(spare.revoca(vb.signum(), M).is_err());
    spare.revoca(va.signum(), M).unwrap();
    assert!(
        spare.revoca(va.signum(), M).is_err(),
        "a wand is revoked once"
    );
}

#[test]
fn a_remaining_wand_makes_a_new_spare() {
    let (va, _, a, b) = pair("adde");
    let mut spare = Virga::aperi(&b).unwrap();
    spare.revoca(va.signum(), M).unwrap();
    let c = stick("adde-c");
    assert!(virga::adde(&mut spare, &c, "other words entirely", R, LEVIS).is_err());
    assert!(!c.join("VIRGA").exists());
    let n = virga::adde(&mut spare, &c, M, R, LEVIS).unwrap();
    let n2 = Virga::aperi(&c).unwrap();
    assert_eq!(n2.signum(), n.signum());
    assert!(n2.solve(Secretum::Magister, M).is_ok());
    let s = Virga::aperi(&b).unwrap();
    assert!(s.stirps.vivit(n.signum()));
    assert!(s.stirps.revocata(va.signum()));
    // onto an old stick: refused, it already holds a wand
    assert!(virga::adde(&mut spare, &a, M, R, LEVIS).is_err());
}

#[test]
fn a_doctored_lineage_is_refused() {
    let (va, _, a, b) = pair("lineage");
    let mut spare = Virga::aperi(&b).unwrap();
    spare.revoca(va.signum(), M).unwrap();
    let text = fs::read_to_string(b.join("VIRGA").join("stirps.txt")).unwrap();
    // drop the revocation: the lineage is shorter, but still a true prefix
    let first: String = text.lines().next().unwrap().to_string() + "\n";
    let short = Stirps::decode(&first).unwrap();
    assert!(
        spare.scribe_stirpem(&short).is_ok(),
        "an older copy changes nothing"
    );
    assert!(Virga::aperi(&b).unwrap().stirps.revocata(va.signum()));
    // a forged act, signed by a stranger, is refused
    let stranger = virga::Clavis::ex_semine([3; 32]);
    let mut forged = Virga::aperi(&a).unwrap().stirps;
    assert!(forged.revoca(spare.signum(), &stranger).is_err());
    // editing a line breaks the chain or a signature
    let edited = text.replacen("REVOCAT", "REVOCAT ", 1);
    assert!(Stirps::decode(&edited).is_err());
    let swapped = text.replace(va.signum(), "x");
    assert!(Stirps::decode(&swapped).is_err());
    // a wand from another lineage cannot be joined to this one
    let (_, other, _, _) = pair("lineage-other");
    assert!(Stirps::concilia(&other.stirps, &spare.stirps).is_err());
}

#[test]
fn diverged_copies_are_refused() {
    let (va, vb, a, b) = pair("diverge");
    let mut wand = Virga::aperi(&a).unwrap();
    let mut spare = Virga::aperi(&b).unwrap();
    let (c, d) = (stick("diverge-c"), stick("diverge-d"));
    virga::adde(&mut wand, &c, M, R, LEVIS).unwrap();
    virga::adde(&mut spare, &d, M, R, LEVIS).unwrap();
    assert!(Stirps::concilia(&wand.stirps, &spare.stirps).is_err());
    let _ = (va, vb);
}

#[test]
fn a_wand_asking_for_other_work_is_refused_before_any_work() {
    let (va, _, a, _) = pair("labor");
    let own = fs::read_to_string(va.radix().join("virga.txt")).unwrap();
    // within the old bounds, but not the work a wand is made with (audit V02)
    let heavy = own.replacen("arca\tritus\t4\t1\t1\t", "arca\tritus\t20\t16\t1\t", 1);
    assert_ne!(heavy, own);
    fs::write(va.radix().join("virga.txt"), heavy).unwrap();
    let e = Virga::aperi(&a).unwrap_err();
    assert!(e.contains("inadmissible"), "{e}");
    let (c, d) = (stick("labor-c"), stick("labor-d"));
    let other = Labor {
        log_n: 10,
        r: 8,
        p: 1,
    };
    assert!(virga::fac(&c, &d, M, R, "", other).is_err());
}

#[test]
fn an_interrupted_stroke_is_finished() {
    let (_, vb, _, b) = pair("perfice");
    // as if the power failed before the spare was put in place
    fs::rename(vb.radix(), b.join("VIRGA.novum")).unwrap();
    assert!(Virga::aperi(&b).is_err());
    let v = virga::perfice(&b).unwrap();
    assert_eq!(v.signum(), vb.signum());
    assert!(virga::perfice(&b).is_err(), "only once");
    let empty = stick("perfice-empty");
    assert!(virga::perfice(&empty).is_err());
}

#[cfg(unix)]
#[test]
fn a_planted_link_beside_the_lineage_is_not_followed() {
    // second review: the lineage was rewritten through the fixed name stirps.novum
    let (va, _, _, b) = pair("link");
    let victim = stick("link-victim").join("precious.txt");
    fs::write(&victim, "untouched").unwrap();
    std::os::unix::fs::symlink(&victim, b.join("VIRGA").join("stirps.novum")).unwrap();
    let mut spare = Virga::aperi(&b).unwrap();
    spare.revoca(va.signum(), M).unwrap();
    assert_eq!(fs::read_to_string(&victim).unwrap(), "untouched");
    assert!(Virga::aperi(&b).unwrap().stirps.revocata(va.signum()));
}

#[test]
fn a_revoked_wand_gives_no_key() {
    let (va, _, a, b) = pair("nokey");
    let mut spare = Virga::aperi(&b).unwrap();
    spare.revoca(va.signum(), M).unwrap();
    let mut lost = Virga::aperi(&a).unwrap();
    lost.scribe_stirpem(&spare.stirps).unwrap();
    assert!(lost.solve(Secretum::Magister, M).is_err());
    assert!(lost.solve(Secretum::Ritus, R).is_err());
}

#[test]
fn two_acts_on_one_wand_cannot_both_be_written() {
    // two copies of the spare, as two programs would hold, each adding a new spare
    let (_, _, _, b) = pair("concurrent");
    let mut one = Virga::aperi(&b).unwrap();
    let mut two = Virga::aperi(&b).unwrap();
    let (c, d) = (stick("concurrent-c"), stick("concurrent-d"));
    virga::adde(&mut one, &c, M, R, LEVIS).unwrap();
    assert!(
        virga::adde(&mut two, &d, M, R, LEVIS).is_err(),
        "the second finds the first's act"
    );
    let on_stick = Virga::aperi(&b).unwrap().stirps;
    assert_eq!(on_stick.longitudo(), 2);
}
