//! Taking the Operator's words. At a terminal they are not shown; when the input is not
//! a terminal (a script, a test) they are read one per line.

use std::io::{BufRead, IsTerminal, Write};

/// Asks for words with `prompt` on standard error and reads one line from standard input.
pub fn roga(prompt: &str) -> Result<String, String> {
    let stdin = std::io::stdin();
    let terminal = stdin.is_terminal();
    let mut err = std::io::stderr();
    let _ = write!(err, "{prompt}: ");
    let _ = err.flush();
    let hidden = terminal && crate::os::echo(false);
    let mut line = String::new();
    let read = stdin.lock().read_line(&mut line);
    if hidden {
        crate::os::echo(true);
    }
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

/// Asks twice and insists the two agree, for words that are being chosen.
pub fn elige(prompt: &str) -> Result<String, String> {
    let a = roga(prompt)?;
    let b = roga("the same words again")?;
    if a != b {
        return Err("the two entries differ".into());
    }
    Ok(a)
}
