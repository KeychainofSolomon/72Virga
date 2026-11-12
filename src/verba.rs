//! Taking the Operator's words. On Windows, at a terminal, they are asked in a small window
//! with dotted fields ([`crate::fenestra`]); at another terminal they are typed unseen, and
//! if the terminal's echo cannot be turned off nothing is asked (audit V04). When the input
//! is not a terminal (a script, a test) they are read one per line.

use std::io::{BufRead, IsTerminal, Write};

/// Turns the terminal's echo off for as long as it lives, and restores it on every way out.
struct Silentium;

impl Silentium {
    fn new() -> Result<Silentium, String> {
        if crate::os::echo(false) {
            Ok(Silentium)
        } else {
            Err("the words cannot be hidden on this terminal, so they are not asked here".into())
        }
    }
}

impl Drop for Silentium {
    fn drop(&mut self) {
        crate::os::echo(true);
    }
}

fn line(prompt: &str, terminal: bool) -> Result<String, String> {
    let mut err = std::io::stderr();
    let _ = write!(err, "{prompt}: ");
    let _ = err.flush();
    let mut line = String::new();
    let read = {
        let _quiet = if terminal {
            Some(Silentium::new()?)
        } else {
            None
        };
        std::io::stdin().lock().read_line(&mut line)
    };
    if terminal {
        let _ = writeln!(err);
    }
    match read {
        Ok(0) => Err("no words were given".into()),
        Ok(_) => {
            while line.ends_with('\n') || line.ends_with('\r') {
                line.pop();
            }
            Ok(line)
        }
        Err(e) => Err(format!("cannot read the words: {e}")),
    }
}

/// Asks for several words at once (`title` names the act); the answers come back in order.
pub fn roga_plura(title: &str, prompts: &[&str]) -> Result<Vec<String>, String> {
    let terminal = std::io::stdin().is_terminal();
    #[cfg(windows)]
    if terminal && std::env::var_os("VIRGA_CONSOLE").is_none() {
        return crate::fenestra::verba(title, prompts);
    }
    let _ = title;
    prompts.iter().map(|p| line(p, terminal)).collect()
}

/// Asks for one set of words.
pub fn roga(prompt: &str) -> Result<String, String> {
    Ok(roga_plura(prompt, &[prompt])?.remove(0))
}

/// Asks twice and insists the two agree, for words that are being chosen.
pub fn elige(prompt: &str) -> Result<String, String> {
    let both = roga_plura(prompt, &[prompt, "the same words again"])?;
    if both[0] != both[1] {
        return Err("the two entries differ".into());
    }
    Ok(both[0].clone())
}
