//! The wand's window on Windows (`fenestra`): plain Windows controls, no outside code.
//!
//! One kind of window serves every act: a heading, a text, some fields, buttons and a
//! status line. Word fields show a dot for each character, how many characters were typed,
//! and, for a field that repeats another, whether the two agree. The words are read out of
//! the fields once, and the fields are emptied before the window closes.

#![allow(unsafe_code, clippy::upper_case_acronyms, non_snake_case)]

use std::cell::RefCell;
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;

use crate::verba::Verba;
use crate::{breviter, Labor, Ordo, Secretum, Status, Virga};

type HWND = *mut c_void;
type HANDLE = *mut c_void;
type WndProc = unsafe extern "system" fn(HWND, u32, usize, isize) -> isize;

#[repr(C)]
struct WNDCLASSEXW {
    cbSize: u32,
    style: u32,
    lpfnWndProc: WndProc,
    cbClsExtra: i32,
    cbWndExtra: i32,
    hInstance: HANDLE,
    hIcon: HANDLE,
    hCursor: HANDLE,
    hbrBackground: HANDLE,
    lpszMenuName: *const u16,
    lpszClassName: *const u16,
    hIconSm: HANDLE,
}

#[repr(C)]
struct POINT {
    x: i32,
    y: i32,
}

#[repr(C)]
struct MSG {
    hwnd: HWND,
    message: u32,
    wParam: usize,
    lParam: isize,
    time: u32,
    pt: POINT,
    lPrivate: u32,
}

#[link(name = "user32")]
extern "system" {
    fn RegisterClassExW(c: *const WNDCLASSEXW) -> u16;
    fn CreateWindowExW(
        ex: u32,
        class: *const u16,
        name: *const u16,
        style: u32,
        x: i32,
        y: i32,
        w: i32,
        h: i32,
        parent: HWND,
        menu: HANDLE,
        inst: HANDLE,
        param: *mut c_void,
    ) -> HWND;
    fn DefWindowProcW(h: HWND, m: u32, w: usize, l: isize) -> isize;
    fn GetMessageW(msg: *mut MSG, h: HWND, a: u32, b: u32) -> i32;
    fn TranslateMessage(msg: *const MSG) -> i32;
    fn DispatchMessageW(msg: *const MSG) -> isize;
    fn IsDialogMessageW(h: HWND, msg: *mut MSG) -> i32;
    fn PostQuitMessage(code: i32);
    fn DestroyWindow(h: HWND) -> i32;
    fn SendMessageW(h: HWND, m: u32, w: usize, l: isize) -> isize;
    fn GetWindowTextW(h: HWND, buf: *mut u16, max: i32) -> i32;
    fn GetWindowTextLengthW(h: HWND) -> i32;
    fn SetWindowTextW(h: HWND, text: *const u16) -> i32;
    fn ShowWindow(h: HWND, cmd: i32) -> i32;
    fn SetFocus(h: HWND) -> HWND;
    fn LoadCursorW(inst: HANDLE, name: *const u16) -> HANDLE;
    fn GetSystemMetrics(i: i32) -> i32;
    fn SetForegroundWindow(h: HWND) -> i32;
}

#[link(name = "gdi32")]
extern "system" {
    fn CreateSolidBrush(color: u32) -> HANDLE;
    fn CreateFontW(
        h: i32,
        w: i32,
        esc: i32,
        orient: i32,
        weight: i32,
        italic: u32,
        underline: u32,
        strike: u32,
        charset: u32,
        out: u32,
        clip: u32,
        quality: u32,
        pitch: u32,
        face: *const u16,
    ) -> HANDLE;
    fn SetTextColor(dc: HANDLE, c: u32) -> u32;
    fn SetBkColor(dc: HANDLE, c: u32) -> u32;
}

#[link(name = "kernel32")]
extern "system" {
    fn GetModuleHandleW(name: *const u16) -> HANDLE;
    fn FreeConsole() -> i32;
}

#[link(name = "dwmapi")]
extern "system" {
    fn DwmSetWindowAttribute(h: HWND, attr: u32, value: *const c_void, size: u32) -> i32;
}

const WS_CAPTION: u32 = 0x00C0_0000;
const WS_SYSMENU: u32 = 0x0008_0000;
const WS_MINIMIZEBOX: u32 = 0x0002_0000;
const WS_CHILD: u32 = 0x4000_0000;
const WS_VISIBLE: u32 = 0x1000_0000;
const WS_TABSTOP: u32 = 0x0001_0000;
const WS_BORDER: u32 = 0x0080_0000;
const ES_PASSWORD: u32 = 0x0020;
const ES_AUTOHSCROLL: u32 = 0x0080;
const BS_DEFPUSHBUTTON: u32 = 0x0001;
const WM_DESTROY: u32 = 0x0002;
const WM_CLOSE: u32 = 0x0010;
const WM_SETFONT: u32 = 0x0030;
const WM_COMMAND: u32 = 0x0111;
const WM_CTLCOLOREDIT: u32 = 0x0133;
const WM_CTLCOLORSTATIC: u32 = 0x0138;
const EN_CHANGE: usize = 0x0300;
const EM_LIMITTEXT: u32 = 0x00C5;
const IDC_ARROW: usize = 32512;
const SW_SHOW: i32 = 5;

// Colours as 0x00BBGGRR: Spiri72's binding page, deep blue with gold.
const GROUND: u32 = 0x006e_290e;
const FIELD: u32 = 0x005e_220b;
const GOLD: u32 = 0x005c_b8e6;
const PALE: u32 = 0x00f5_e6e0;
const DIM: u32 = 0x00cd_a596;
const RED: u32 = 0x0078_8cff;

const ID_OK: usize = 1;
const ID_CANCEL: usize = 2;
const ID_BUTTON: usize = 100;
const ID_FIELD: usize = 200;
const MAX_WORDS: usize = crate::MAX_VERBA;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// One field of a form.
pub struct Campus {
    pub label: String,
    pub secret: bool,
    pub value: String,
    /// For a field that repeats another: that field's index.
    pub repeats: Option<usize>,
}

impl Campus {
    fn text(label: &str, value: &str) -> Campus {
        Campus {
            label: label.into(),
            secret: false,
            value: value.into(),
            repeats: None,
        }
    }

    fn words(label: &str) -> Campus {
        Campus {
            label: label.into(),
            secret: true,
            value: String::new(),
            repeats: None,
        }
    }

    fn again(label: &str, of: usize) -> Campus {
        Campus {
            repeats: Some(of),
            ..Campus::words(label)
        }
    }
}

/// A form: the one kind of window.
pub struct Forma {
    pub title: String,
    pub heading: String,
    pub text: String,
    pub fields: Vec<Campus>,
    pub buttons: Vec<String>,
    pub status: String,
    pub error: bool,
}

struct Live {
    edits: Vec<HWND>,
    counts: Vec<HWND>,
    secret: Vec<bool>,
    repeats: Vec<Option<usize>>,
    status: HWND,
    error: bool,
    chosen: Option<usize>,
    values: Vec<Verba>,
    brush_ground: HANDLE,
    brush_field: HANDLE,
}

thread_local! {
    static LIVE: RefCell<Option<Live>> = const { RefCell::new(None) };
}

fn text_of(h: HWND) -> String {
    // SAFETY: the buffer is as long as the length asked for, plus the terminating zero.
    unsafe {
        let n = GetWindowTextLengthW(h).max(0) as usize;
        let mut buf = vec![0u16; n + 1];
        let got = GetWindowTextW(h, buf.as_mut_ptr(), buf.len() as i32).max(0) as usize;
        let s = String::from_utf16_lossy(&buf[..got]);
        buf.fill(0);
        s
    }
}

fn set_text(h: HWND, s: &str) {
    let w = wide(s);
    // SAFETY: a zero-terminated string that lives through the call.
    unsafe {
        SetWindowTextW(h, w.as_ptr());
    }
}

fn refresh_counts(live: &Live) {
    for (i, &count) in live.counts.iter().enumerate() {
        if count.is_null() {
            continue;
        }
        let mut here = text_of(live.edits[i]);
        let n = here.chars().count();
        let mut label = match n {
            0 => String::new(),
            1 => "1 character".to_string(),
            n => format!("{n} characters"),
        };
        if let Some(of) = live.repeats[i] {
            if n > 0 {
                let mut there = text_of(live.edits[of]);
                label.push_str(if here == there {
                    "  ·  the same"
                } else {
                    "  ·  differs"
                });
                crate::wipe(unsafe_bytes(&mut there));
            }
        }
        crate::wipe(unsafe_bytes(&mut here));
        set_text(count, &label);
    }
}

/// The bytes of a string, to wipe them before it is dropped.
fn unsafe_bytes(s: &mut str) -> &mut [u8] {
    // SAFETY: only ever overwritten with zeros, which is valid UTF-8.
    unsafe { s.as_bytes_mut() }
}

fn finish(h: HWND, chosen: Option<usize>) {
    let edits = LIVE.with(|l| {
        let mut b = l.borrow_mut();
        let Some(live) = b.as_mut() else {
            return Vec::new();
        };
        live.chosen = chosen;
        if chosen.is_some() {
            live.values = live.edits.iter().map(|&e| Verba::new(text_of(e))).collect();
        }
        live.edits.clone()
    });
    // emptied after the borrow ends: each change calls back into the window
    for e in edits {
        set_text(e, "");
    }
    // SAFETY: our own window.
    unsafe {
        DestroyWindow(h);
    }
}

unsafe extern "system" fn proc_(h: HWND, m: u32, w: usize, l: isize) -> isize {
    match m {
        WM_COMMAND => {
            let id = w & 0xffff;
            let code = (w >> 16) & 0xffff;
            if code == EN_CHANGE {
                LIVE.with(|live| {
                    if let Ok(b) = live.try_borrow() {
                        if let Some(live) = b.as_ref() {
                            refresh_counts(live);
                        }
                    }
                });
                return 0;
            }
            match id {
                ID_OK => finish(h, Some(0)),
                ID_CANCEL => finish(h, None),
                id if (ID_BUTTON..ID_FIELD).contains(&id) => finish(h, Some(id - ID_BUTTON)),
                _ => {}
            }
            0
        }
        WM_CTLCOLOREDIT | WM_CTLCOLORSTATIC => {
            let dc = w as HANDLE;
            let control = l as HWND;
            LIVE.with(|live| {
                let Ok(live) = live.try_borrow() else {
                    return DefWindowProcW(h, m, w, l);
                };
                let Some(live) = live.as_ref() else {
                    return DefWindowProcW(h, m, w, l);
                };
                if m == WM_CTLCOLOREDIT {
                    SetTextColor(dc, PALE);
                    SetBkColor(dc, FIELD);
                    return live.brush_field as isize;
                }
                let color = if control == live.status {
                    if live.error {
                        RED
                    } else {
                        GOLD
                    }
                } else if live.counts.contains(&control) {
                    DIM
                } else {
                    PALE
                };
                SetTextColor(dc, color);
                SetBkColor(dc, GROUND);
                live.brush_ground as isize
            })
        }
        WM_CLOSE => {
            finish(h, None);
            0
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(h, m, w, l),
    }
}

fn class() -> Vec<u16> {
    let name = wide("VirgaFenestra");
    thread_local! {
        static DONE: RefCell<bool> = const { RefCell::new(false) };
    }
    DONE.with(|d| {
        if !*d.borrow() {
            // SAFETY: the class structure is complete and its strings outlive registration
            // (the class name is leaked once, for the life of the program).
            unsafe {
                let leaked: &'static [u16] = Box::leak(name.clone().into_boxed_slice());
                let c = WNDCLASSEXW {
                    cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
                    style: 0,
                    lpfnWndProc: proc_,
                    cbClsExtra: 0,
                    cbWndExtra: 0,
                    hInstance: GetModuleHandleW(null_mut()),
                    hIcon: null_mut(),
                    hCursor: LoadCursorW(null_mut(), IDC_ARROW as *const u16),
                    hbrBackground: CreateSolidBrush(GROUND),
                    lpszMenuName: std::ptr::null(),
                    lpszClassName: leaked.as_ptr(),
                    hIconSm: null_mut(),
                };
                RegisterClassExW(&c);
            }
            *d.borrow_mut() = true;
        }
    });
    name
}

/// Shows a form and waits. Returns the button chosen (0 for the first, also on Enter) and
/// the fields' values, or `None` if the window was closed.
pub fn ostende(f: &Forma) -> Option<(usize, Vec<Verba>)> {
    let class = class();
    const W: i32 = 600;
    const PAD: i32 = 24;
    let text_lines = f
        .text
        .lines()
        .count()
        .max(if f.text.is_empty() { 0 } else { 1 }) as i32;
    let mut y = PAD;
    let heading_h = 36;
    let text_h = text_lines * 22;
    let fields_h = f.fields.len() as i32 * 58;
    // buttons stand one above another, the first (the most used) on top
    let buttons_h = f.buttons.len() as i32 * 44;
    let height = PAD + heading_h + 8 + text_h + 12 + fields_h + 40 + buttons_h + PAD + 40;
    // SAFETY: plain window creation and messages on this thread's own windows; every
    // string passed lives until the call returns.
    unsafe {
        let inst = GetModuleHandleW(null_mut());
        let sw = GetSystemMetrics(0);
        let sh = GetSystemMetrics(1);
        let title = wide(&f.title);
        let win = CreateWindowExW(
            0,
            class.as_ptr(),
            title.as_ptr(),
            WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
            (sw - W) / 2,
            (sh - height) / 2,
            W,
            height,
            null_mut(),
            null_mut(),
            inst,
            null_mut(),
        );
        if win.is_null() {
            return None;
        }
        let dark: i32 = 1;
        DwmSetWindowAttribute(win, 20, &dark as *const i32 as *const c_void, 4);
        let face = wide("Georgia");
        let big = CreateFontW(-26, 0, 0, 0, 700, 0, 0, 0, 0, 0, 0, 5, 0, face.as_ptr());
        let body = CreateFontW(-17, 0, 0, 0, 400, 0, 0, 0, 0, 0, 0, 5, 0, face.as_ptr());
        let ui_face = wide("Segoe UI");
        let small = CreateFontW(-15, 0, 0, 0, 400, 0, 0, 0, 0, 0, 0, 5, 0, ui_face.as_ptr());
        #[allow(clippy::too_many_arguments)]
        let child = |cls: &str,
                     text: &str,
                     style: u32,
                     ex: u32,
                     x: i32,
                     yy: i32,
                     w: i32,
                     hh: i32,
                     id: usize,
                     font: HANDLE| {
            let c = wide(cls);
            let t = wide(text);
            let hw = CreateWindowExW(
                ex,
                c.as_ptr(),
                t.as_ptr(),
                WS_CHILD | WS_VISIBLE | style,
                x,
                yy,
                w,
                hh,
                win,
                id as HANDLE,
                inst,
                null_mut(),
            );
            SendMessageW(hw, WM_SETFONT, font as usize, 1);
            hw
        };
        let heading = child(
            "STATIC",
            &f.heading,
            0,
            0,
            PAD,
            y,
            W - 2 * PAD,
            heading_h,
            0,
            big,
        );
        y += heading_h + 8;
        if text_lines > 0 {
            child(
                "STATIC",
                &f.text,
                0,
                0,
                PAD,
                y,
                W - 2 * PAD - 16,
                text_h,
                0,
                body,
            );
            y += text_h;
        }
        y += 12;
        let mut edits = Vec::new();
        let mut counts = Vec::new();
        for (i, field) in f.fields.iter().enumerate() {
            child(
                "STATIC",
                &field.label,
                0,
                0,
                PAD,
                y,
                W - 2 * PAD,
                22,
                0,
                body,
            );
            let style = WS_TABSTOP
                | WS_BORDER
                | ES_AUTOHSCROLL
                | if field.secret { ES_PASSWORD } else { 0 };
            let edit_w = if field.secret { 330 } else { W - 2 * PAD - 16 };
            let e = child(
                "EDIT",
                &field.value,
                style,
                0,
                PAD,
                y + 24,
                edit_w,
                28,
                ID_FIELD + i,
                body,
            );
            SendMessageW(e, EM_LIMITTEXT, MAX_WORDS, 0);
            edits.push(e);
            counts.push(if field.secret {
                child(
                    "STATIC",
                    "",
                    0,
                    0,
                    PAD + edit_w + 12,
                    y + 28,
                    W - 2 * PAD - edit_w - 28,
                    22,
                    0,
                    small,
                )
            } else {
                null_mut()
            });
            y += 58;
        }
        let status = child(
            "STATIC",
            &f.status,
            0,
            0,
            PAD,
            y + 6,
            W - 2 * PAD - 16,
            24,
            0,
            small,
        );
        y += 40;
        for (i, b) in f.buttons.iter().enumerate() {
            let (id, style) = if i == 0 {
                (ID_OK, WS_TABSTOP | BS_DEFPUSHBUTTON)
            } else {
                (ID_BUTTON + i, WS_TABSTOP)
            };
            child(
                "BUTTON",
                b,
                style,
                0,
                PAD,
                y,
                W - 2 * PAD - 16,
                36,
                id,
                small,
            );
            y += 44;
        }
        let _ = heading;
        LIVE.with(|l| {
            *l.borrow_mut() = Some(Live {
                secret: f.fields.iter().map(|c| c.secret).collect(),
                repeats: f.fields.iter().map(|c| c.repeats).collect(),
                edits: edits.clone(),
                counts,
                status,
                error: f.error,
                chosen: None,
                values: Vec::new(),
                brush_ground: CreateSolidBrush(GROUND),
                brush_field: CreateSolidBrush(FIELD),
            })
        });
        ShowWindow(win, SW_SHOW);
        SetForegroundWindow(win);
        let first_empty = f
            .fields
            .iter()
            .position(|c| c.value.is_empty())
            .unwrap_or(0);
        if let Some(&e) = edits.get(first_empty) {
            SetFocus(e);
        }
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            if IsDialogMessageW(win, &mut msg) == 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        let live = LIVE.with(|l| l.borrow_mut().take())?;
        let _ = live.secret;
        live.chosen.map(|c| (c, live.values))
    }
}

/// Asks for words in a window: one dotted field per prompt.
pub fn verba(title: &str, prompts: &[&str]) -> Result<Vec<Verba>, String> {
    let repeats_previous = |p: &str| p.contains("again");
    let fields = prompts
        .iter()
        .enumerate()
        .map(|(i, p)| {
            if i > 0 && repeats_previous(p) {
                Campus::again(p, i - 1)
            } else {
                Campus::words(p)
            }
        })
        .collect();
    let f = Forma {
        title: "Virga".into(),
        heading: title.to_string(),
        text: "Your words are shown as dots. Nothing you type here is kept.".into(),
        fields,
        buttons: vec!["Take up the wand".into(), "Cancel".into()],
        status: String::new(),
        error: false,
    };
    match ostende(&f) {
        Some((0, values)) => Ok(values),
        _ => Err("no words were given".into()),
    }
}

fn describe() -> String {
    let found = crate::quaere();
    if found.is_empty() {
        let drives: Vec<String> = (b'A'..=b'Z')
            .map(|l| format!("{}:", l as char))
            .filter(|d| Path::new(&format!("{d}\\")).exists())
            .collect();
        return format!(
            "No wand found on {}.\nType its drive (for example D:\\) in the box of the act you choose.",
            drives.join(" ")
        );
    }
    let mut out = String::new();
    for p in found {
        match Virga::aperi(&p) {
            Ok(v) => {
                out.push_str(&format!(
                    "{}   {}   {}{}\n",
                    p.display(),
                    breviter(v.signum()),
                    match v.ordo {
                        Ordo::Prima => "the wand",
                        Ordo::Secunda => "a spare",
                    },
                    match v.status() {
                        Status::Vivit => "",
                        Status::Revocata => ", REVOKED",
                    }
                ));
            }
            Err(e) => out.push_str(&format!("{}   unreadable: {e}\n", p.display())),
        }
    }
    out.trim_end().to_string()
}

fn first_wand() -> String {
    crate::quaere()
        .first()
        .map(|p| p.display().to_string())
        .unwrap_or_default()
}

fn word_fields() -> Vec<Campus> {
    vec![
        Campus::words("Master words"),
        Campus::again("Master words again", 0),
        Campus::words("Rite words"),
        Campus::again("Rite words again", 2),
    ]
}

/// Shows `f` until `act` succeeds or the Operator goes back; the result's text is shown.
fn act(mut f: Forma, act: impl Fn(&[Verba]) -> Result<String, String>) {
    loop {
        let Some((0, values)) = ostende(&f) else {
            return;
        };
        match act(&values) {
            Ok(done) => {
                ostende(&Forma {
                    title: "Virga".into(),
                    heading: "Done".into(),
                    text: done,
                    fields: Vec::new(),
                    buttons: vec!["Back".into()],
                    status: String::new(),
                    error: false,
                });
                return;
            }
            Err(e) => {
                for (field, v) in f.fields.iter_mut().zip(values) {
                    if !field.secret {
                        field.value = v.to_string();
                    }
                }
                f.status = e;
                f.error = true;
            }
        }
    }
}

fn same(a: &str, b: &str) -> Result<(), String> {
    if a != b {
        return Err("the two entries of the same words differ".into());
    }
    Ok(())
}

fn make() {
    let mut fields = vec![
        Campus::text(
            "The wand's stick (a drive, for example D:\\)",
            &first_wand(),
        ),
        Campus::text("The spare's stick or folder (for example E:\\)", ""),
        Campus::text("A name for the wand (may be left empty)", ""),
    ];
    fields.extend(word_fields().into_iter().map(|mut c| {
        c.repeats = c.repeats.map(|r| r + 3);
        c
    }));
    act(
        Forma {
            title: "Virga".into(),
            heading: "Make the wand and its spare".into(),
            text: "Both are made at one stroke, on two places that hold no wand.\nThe master words and the rite words must differ; a sentence each, at least 12 characters.\nNobody can recover forgotten words: write them down and keep them apart from the sticks.".into(),
            fields,
            buttons: vec!["Make".into(), "Back".into()],
            status: String::new(),
            error: false,
        },
        |v| {
            same(&v[3], &v[4])?;
            same(&v[5], &v[6])?;
            let (a, b) = crate::fac(Path::new(&*v[0]), Path::new(&*v[1]), &v[3], &v[5], &v[2], Labor::VERA)?;
            Ok(format!(
                "The wand {} is on {}.\nThe spare {} is on {}.\n\nWrite both fingerprints down. Keep the spare apart from the wand.",
                breviter(a.signum()),
                a.radix().display(),
                breviter(b.signum()),
                b.radix().display()
            ))
        },
    );
}

fn check() {
    act(
        Forma {
            title: "Virga".into(),
            heading: "Check your words".into(),
            text: "Tries your words on both secrets of a wand. Nothing is changed.".into(),
            fields: vec![
                Campus::text("The wand's stick or folder", &first_wand()),
                Campus::words("Master words"),
                Campus::words("Rite words"),
            ],
            buttons: vec!["Check".into(), "Back".into()],
            status: String::new(),
            error: false,
        },
        |v| {
            let w = Virga::aperi(&PathBuf::from(&*v[0]))?;
            w.solve(Secretum::Magister, &v[1])
                .map_err(|e| format!("master secret: {e}"))?;
            w.solve(Secretum::Ritus, &v[2])
                .map_err(|e| format!("rite secret: {e}"))?;
            Ok(if w.status() == Status::Revocata {
                "Both secrets open with your words, but this wand is REVOKED: Annulus refuses it."
                    .into()
            } else {
                format!(
                    "Both secrets of {} open with your words.",
                    breviter(w.signum())
                )
            })
        },
    );
}

fn revoke() {
    act(
        Forma {
            title: "Virga".into(),
            heading: "Revoke a lost wand".into(),
            text: "A remaining wand (usually the spare) revokes the lost one.\nAnnulus then refuses the lost wand everywhere this wand is used.".into(),
            fields: vec![
                Campus::text("The remaining wand's stick or folder", &first_wand()),
                Campus::text("The lost wand's fingerprint (for example D85E-25B4)", ""),
                Campus::words("Master words"),
            ],
            buttons: vec!["Revoke".into(), "Back".into()],
            status: String::new(),
            error: false,
        },
        |v| {
            let mut w = Virga::aperi(&PathBuf::from(&*v[0]))?;
            let wanted: String = v[1].chars().filter(|c| *c != '-' && !c.is_whitespace()).collect::<String>().to_lowercase();
            if wanted.len() < 8 {
                return Err("give at least the first 8 digits of the fingerprint".into());
            }
            let matches: Vec<String> = w.stirps.vivae().into_iter().filter(|x| x.starts_with(&wanted)).collect();
            let lost = match matches.as_slice() {
                [one] => one.clone(),
                [] => return Err("no living wand of this lineage has that fingerprint".into()),
                _ => return Err("that fingerprint names more than one wand".into()),
            };
            if lost == w.signum() {
                return Err("a wand does not revoke itself: use the other wand".into());
            }
            w.revoca(&lost, &v[2])?;
            Ok(format!("{} is revoked. Make a new spare when you can.", breviter(&lost)))
        },
    );
}

fn spare() {
    act(
        Forma {
            title: "Virga".into(),
            heading: "Make a new spare".into(),
            text: "A remaining wand makes a new spare on a place that holds no wand.\nThe new spare takes the same words.".into(),
            fields: vec![
                Campus::text("The remaining wand's stick or folder", &first_wand()),
                Campus::text("The new spare's stick or folder", ""),
                Campus::words("Master words"),
                Campus::words("Rite words"),
            ],
            buttons: vec!["Make the spare".into(), "Back".into()],
            status: String::new(),
            error: false,
        },
        |v| {
            let mut w = Virga::aperi(&PathBuf::from(&*v[0]))?;
            let n = crate::adde(&mut w, Path::new(&*v[1]), &v[2], &v[3], Labor::VERA)?;
            Ok(format!("The spare {} is on {}.", breviter(n.signum()), n.radix().display()))
        },
    );
}

fn finish_stroke() {
    act(
        Forma {
            title: "Virga".into(),
            heading: "Finish an interrupted making".into(),
            text: "If the making stopped part-way, a stick may hold a finished wand that was\nnot yet put in place (a folder VIRGA.novum). This puts it in place.".into(),
            fields: vec![Campus::text("The stick or folder", "")],
            buttons: vec!["Finish".into(), "Back".into()],
            status: String::new(),
            error: false,
        },
        |v| {
            let w = crate::perfice(Path::new(&*v[0]))?;
            Ok(format!("{} is in place on {}.", breviter(w.signum()), w.radix().display()))
        },
    );
}

/// The wand's own window, opened when `virga` is started with nothing after it.
pub fn app() {
    // SAFETY: lets go of the console window Windows opened for the program.
    unsafe {
        FreeConsole();
    }
    loop {
        let f = Forma {
            title: "Virga".into(),
            heading: "Virga, the Operator's wand".into(),
            text: describe(),
            fields: Vec::new(),
            buttons: vec![
                "Check my words".into(),
                "Make the wand and its spare".into(),
                "Make a new spare".into(),
                "Revoke a lost wand".into(),
                "Finish an interrupted making".into(),
                "Close".into(),
            ],
            status: "Plug in a wand, then choose. The list above refreshes when you come back."
                .into(),
            error: false,
        };
        match ostende(&f) {
            Some((0, _)) => check(),
            Some((1, _)) => make(),
            Some((2, _)) => spare(),
            Some((3, _)) => revoke(),
            Some((4, _)) => finish_stroke(),
            _ => return,
        }
    }
}
