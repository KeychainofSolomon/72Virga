//! `virga`: makes and keeps the Operator's wand.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use virga::{breviter, verba, Labor, Ordo, Secretum, Status, Virga};

const USAGE: &str = "\
virga: the Operator's wand for Annulus

  virga fac <stick> <spare-stick> [--nomen NAME]
        make the wand and its spare at one stroke, on two sticks that hold no wand
  virga inspice [<stick>]      show a wand, its lineage and which wands still live
  virga proba [<stick>]        check that your words open both secrets
  virga revoca <lost> [<stick>]
        revoke a lost or stolen wand, by its fingerprint, with a remaining wand
  virga adde <new-stick> [<stick>]
        with a remaining wand, make a new spare on a stick that holds no wand
  virga quaere                 list the wands plugged into this computer

<stick> is the drive or folder holding the VIRGA folder (for example E:\\). Left out,
the one wand plugged in is used, or the folder named by the VIRGA variable.
";

fn say(s: &str) {
    eprintln!("{s}");
}

fn find(given: Option<&String>) -> Result<PathBuf, String> {
    if let Some(p) = given {
        return Ok(PathBuf::from(p));
    }
    if let Ok(p) = std::env::var("VIRGA") {
        return Ok(PathBuf::from(p));
    }
    let found = virga::quaere();
    match found.as_slice() {
        [one] => Ok(one.clone()),
        [] => Err("no wand is plugged in: name its drive, for example `virga inspice E:\\`".into()),
        _ => Err("more than one wand is plugged in: name the one you mean".into()),
    }
}

fn show(v: &Virga) {
    println!("wand        {}", v.radix().display());
    if !v.nomen.is_empty() {
        println!("name        {}", v.nomen);
    }
    println!(
        "kind        {}",
        match v.ordo {
            Ordo::Prima => "the wand (prima)",
            Ordo::Secunda => "a spare (secunda)",
        }
    );
    println!("fingerprint {}", breviter(v.signum()));
    println!("            {}", v.signum());
    println!(
        "standing    {}",
        match v.status() {
            Status::Vivit => "living",
            Status::Revocata => "REVOKED: this wand opens nothing",
        }
    );
    println!("lineage     {} acts", v.stirps.acta().len());
    for w in v.stirps.vivae() {
        let me = if w == v.signum() { "  (this wand)" } else { "" };
        println!("  living    {}{me}", breviter(&w));
    }
    for w in v.stirps.revocatae() {
        println!("  revoked   {}", breviter(w));
    }
}

fn words() -> Result<(String, String), String> {
    say("Choose the words for the MASTER secret. They prove you yourself, and are asked only");
    say("outside a rite. Use a sentence you will not forget, at least 12 characters.");
    let m = verba::elige("master words")?;
    say("Choose different words for the RITE secret, asked when the wand is taken up in a rite.");
    let r = verba::elige("rite words")?;
    Ok((m, r))
}

fn run(args: &[String]) -> Result<(), String> {
    let (cmd, rest) = args.split_first().ok_or(USAGE)?;
    let mut plain: Vec<&String> = Vec::new();
    let mut nomen = String::new();
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        if a == "--nomen" {
            nomen = it.next().ok_or("--nomen needs a name")?.clone();
        } else if a.starts_with("--") {
            return Err(format!("unknown option {a}\n\n{USAGE}"));
        } else {
            plain.push(a);
        }
    }
    match (cmd.as_str(), plain.as_slice()) {
        ("fac", [a, b]) => {
            for stick in [a, b] {
                if Path::new(stick).join(virga::DIR).exists() {
                    return Err(format!(
                        "{stick} already holds a wand: a wand is cut once, and never re-cut"
                    ));
                }
            }
            say("Making the wand and its spare at one stroke. Both sticks must hold no wand.");
            let (m, r) = words()?;
            say("Locking the secrets (this takes a few seconds)...");
            let (va, vb) = virga::fac(Path::new(a), Path::new(b), &m, &r, &nomen, Labor::VERA)?;
            println!("Made.");
            println!(
                "  wand  {}  on {}",
                breviter(va.signum()),
                va.radix().display()
            );
            println!(
                "  spare {}  on {}",
                breviter(vb.signum()),
                vb.radix().display()
            );
            println!("Keep the spare somewhere safe, apart from the wand. Write the two fingerprints down.");
            println!("Anyone who has a stick AND your words holds the wand; the words alone, or the stick alone, are useless.");
            Ok(())
        }
        ("inspice", rest) if rest.len() <= 1 => {
            let v = Virga::aperi(&find(rest.first().copied())?)?;
            show(&v);
            Ok(())
        }
        ("proba", rest) if rest.len() <= 1 => {
            let v = Virga::aperi(&find(rest.first().copied())?)?;
            let m = verba::roga("master words")?;
            v.solve(Secretum::Magister, &m)
                .map_err(|e| format!("master secret: {e}"))?;
            let r = verba::roga("rite words")?;
            v.solve(Secretum::Ritus, &r)
                .map_err(|e| format!("rite secret: {e}"))?;
            println!("Both secrets open with your words.");
            if v.status() == Status::Revocata {
                println!("But this wand is REVOKED: Annulus will refuse it.");
            }
            Ok(())
        }
        ("revoca", rest) if !rest.is_empty() && rest.len() <= 2 => {
            let mut v = Virga::aperi(&find(rest.get(1).copied())?)?;
            let wanted: String = rest[0]
                .chars()
                .filter(|c| *c != '-')
                .collect::<String>()
                .to_lowercase();
            let matches: Vec<String> = v
                .stirps
                .vivae()
                .into_iter()
                .filter(|w| w.starts_with(&wanted))
                .collect();
            let lost = match matches.as_slice() {
                [one] => one.clone(),
                [] => return Err("no living wand of this lineage has that fingerprint".into()),
                _ => return Err("that fingerprint is too short to name one wand".into()),
            };
            if lost == v.signum() {
                return Err("a wand does not revoke itself: use the other wand".into());
            }
            say(&format!(
                "Revoking {} with {}.",
                breviter(&lost),
                breviter(v.signum())
            ));
            let m = verba::roga("master words")?;
            v.revoca(&lost, &m)?;
            println!(
                "Revoked. Annulus learns of it the next time this wand is used with each house."
            );
            println!("Make a new spare with `virga adde <new-stick>`.");
            Ok(())
        }
        ("adde", rest) if !rest.is_empty() && rest.len() <= 2 => {
            let mut v = Virga::aperi(&find(rest.get(1).copied())?)?;
            say("Making a new spare with this wand. Give the words of this wand; the spare takes the same words.");
            let m = verba::roga("master words")?;
            let r = verba::roga("rite words")?;
            say("Locking the secrets (this takes a few seconds)...");
            let n = virga::adde(&mut v, Path::new(rest[0]), &m, &r, Labor::VERA)?;
            println!(
                "Made the spare {} on {}.",
                breviter(n.signum()),
                n.radix().display()
            );
            Ok(())
        }
        ("quaere", []) => {
            let found = virga::quaere();
            if found.is_empty() {
                println!("No wand is plugged in.");
            }
            for p in found {
                match Virga::aperi(&p) {
                    Ok(v) => println!("{}  {}", p.display(), breviter(v.signum())),
                    Err(e) => println!("{}  unreadable: {e}", p.display()),
                }
            }
            Ok(())
        }
        ("help" | "--help" | "-h", _) => {
            print!("{USAGE}");
            Ok(())
        }
        _ => Err(USAGE.to_string()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            say(&e);
            ExitCode::FAILURE
        }
    }
}
