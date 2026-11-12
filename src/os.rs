//! What the wand needs from the operating system: fresh randomness for the secrets, and
//! a way to take the Operator's words without showing them on the screen. This is the
//! only module with `unsafe`: two small calls into Windows.

/// Fills `out` from the operating system's random source, or fails: a wand is never made
/// from weak randomness.
pub fn random(out: &mut [u8]) -> Result<(), String> {
    imp::random(out)
}

/// Turns the terminal's echo off (`false`) or back on (`true`). Returns whether it could.
pub fn echo(on: bool) -> bool {
    imp::echo(on)
}

#[cfg(unix)]
mod imp {
    use std::io::Read;

    pub fn random(out: &mut [u8]) -> Result<(), String> {
        let mut f = std::fs::File::open("/dev/urandom")
            .map_err(|e| format!("no source of randomness: {e}"))?;
        f.read_exact(out)
            .map_err(|e| format!("the source of randomness failed: {e}"))
    }

    pub fn echo(on: bool) -> bool {
        std::process::Command::new("stty")
            .arg(if on { "echo" } else { "-echo" })
            .stdin(std::process::Stdio::inherit())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod imp {
    use std::ffi::c_void;

    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
    const STD_INPUT_HANDLE: u32 = -10i32 as u32;
    const ENABLE_ECHO_INPUT: u32 = 0x0004;

    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(alg: *mut c_void, buf: *mut u8, len: u32, flags: u32) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetStdHandle(which: u32) -> *mut c_void;
        fn GetConsoleMode(handle: *mut c_void, mode: *mut u32) -> i32;
        fn SetConsoleMode(handle: *mut c_void, mode: u32) -> i32;
    }

    pub fn random(out: &mut [u8]) -> Result<(), String> {
        for chunk in out.chunks_mut(1 << 20) {
            // SAFETY: the buffer is valid for `chunk.len()` bytes, which fits in a u32.
            let status = unsafe {
                BCryptGenRandom(
                    std::ptr::null_mut(),
                    chunk.as_mut_ptr(),
                    chunk.len() as u32,
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                )
            };
            if status != 0 {
                return Err(format!(
                    "the source of randomness failed (status {status:#x})"
                ));
            }
        }
        Ok(())
    }

    pub fn echo(on: bool) -> bool {
        // SAFETY: plain console calls on the process's own input handle.
        unsafe {
            let handle = GetStdHandle(STD_INPUT_HANDLE);
            if handle.is_null() || handle as isize == -1 {
                return false;
            }
            let mut mode = 0u32;
            if GetConsoleMode(handle, &mut mode) == 0 {
                return false;
            }
            let mode = if on {
                mode | ENABLE_ECHO_INPUT
            } else {
                mode & !ENABLE_ECHO_INPUT
            };
            SetConsoleMode(handle, mode) != 0
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    pub fn random(_: &mut [u8]) -> Result<(), String> {
        Err("no source of randomness on this system".into())
    }

    pub fn echo(_: bool) -> bool {
        false
    }
}
