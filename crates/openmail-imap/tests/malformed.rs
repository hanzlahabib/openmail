//! Malformed / hostile MIME corpus. Each case must finish within a wall-time budget and
//! within a peak-memory budget (peak RSS growth from /proc/self), and the
//! output must still respect the body cap and hygiene rules.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::fmt::Write as _;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use openmail_imap::mime::{ParsedMessage, attachment_bytes, parse_headers, parse_message};
use openmail_imap::utf7;

/// Process-wide RSS counters are shared by every test thread, so each test holds this for
/// its whole body (input construction included) to keep measurements independent.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Memory proxy without `unsafe` (the workspace forbids it, so no counting allocator):
/// reset the kernel's peak-RSS high-water mark, run, read it back. Linux only; elsewhere
/// (or when `/proc` is not writable) the memory bound is skipped and only time is checked.
fn status_kib(key: &str) -> Option<usize> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with(key))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

fn reset_peak() -> bool {
    // "5" resets VmHWM to the current RSS (Documentation/filesystems/proc.rst).
    std::fs::write("/proc/self/clear_refs", "5").is_ok()
}

struct Measured<T> {
    value: T,
    elapsed: Duration,
    /// Peak RSS growth in bytes during the call, when measurable.
    peak_extra: Option<usize>,
}

fn measure<T>(f: impl FnOnce() -> T) -> Measured<T> {
    let tracked = reset_peak();
    let base = status_kib("VmRSS:");
    let t = Instant::now();
    let value = f();
    let elapsed = t.elapsed();
    let peak = status_kib("VmHWM:");
    let peak_extra = match (tracked, base, peak) {
        (true, Some(b), Some(p)) => Some(p.saturating_sub(b) * 1024),
        _ => None,
    };
    Measured {
        value,
        elapsed,
        peak_extra,
    }
}

const MIB: usize = 1024 * 1024;
const CAP: usize = 64 * 1024;
/// Generous for an unoptimised test build on a loaded CI host; the point is "bounded",
/// not "fast": a quadratic or unbounded-recursion bug misses it by orders of magnitude.
const TIME_BUDGET: Duration = Duration::from_secs(20);

fn check<T>(name: &str, m: &Measured<T>, max_peak: usize) {
    assert!(m.elapsed < TIME_BUDGET, "{name}: took {:?}", m.elapsed);
    if let Some(peak) = m.peak_extra {
        assert!(
            peak <= max_peak,
            "{name}: peak RSS growth {} MiB exceeds {} MiB",
            peak / MIB,
            max_peak / MIB
        );
    }
}

fn assert_bounded_output(name: &str, p: &ParsedMessage) {
    if let Some(t) = &p.body.text {
        assert!(t.0.len() <= CAP, "{name}: text {} > cap", t.0.len());
    }
    if let Some(h) = &p.body.html_sanitized {
        assert!(h.0.len() <= CAP, "{name}: html {} > cap", h.0.len());
    }
}

fn run(name: &str, raw: &[u8], max_peak: usize) -> ParsedMessage {
    let m = measure(|| parse_message(raw, CAP));
    check(name, &m, max_peak);
    assert_bounded_output(name, &m.value);
    m.value
}

#[test]
fn truncated_multipart_still_yields_the_text_that_was_received() {
    let _serial = serial();
    let raw = b"From: a@b.c\r\nSubject: cut\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n\
--B\r\nContent-Type: text/plain\r\n\r\nthe visible part\r\n--B\r\nContent-Type: application/pdf\r\n\
Content-Disposition: attachment; filename=\"x.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQK";
    let p = run("truncated multipart", raw, 4 * MIB);
    assert!(p.body.text.as_ref().unwrap().0.contains("the visible part"));
    assert_eq!(p.headers.subject, "cut");
    // Multipart with a boundary that never closes and no parts at all.
    let p = run(
        "boundary only",
        b"Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\n",
        4 * MIB,
    );
    assert!(p.attachments.is_empty());
}

#[test]
fn unknown_and_bad_charsets_do_not_fail_the_read() {
    let _serial = serial();
    let raw = b"From: a@b.c\r\nSubject: =?x-no-such-charset?Q?caf=E9?=\r\n\
Content-Type: text/plain; charset=\"x-no-such-charset\"\r\n\r\ncaf\xe9 \xff\xfe still here";
    let p = run("unknown charset", raw, 4 * MIB);
    assert!(p.body.text.as_ref().unwrap().0.contains("still here"));
    // Declared UTF-8 but the bytes are not.
    let raw = b"Content-Type: text/plain; charset=utf-8\r\n\r\nok \xc3\x28 \xf0\x28\x8c\xbc tail";
    let p = run("invalid utf-8", raw, 4 * MIB);
    assert!(p.body.text.as_ref().unwrap().0.contains("tail"));
    // Declared charset whose label is malformed.
    run(
        "garbage charset label",
        b"Content-Type: text/plain; charset=\"\x00\xff\"\r\n\r\nbody",
        4 * MIB,
    );
}

#[test]
fn deeply_nested_multipart_is_bounded() {
    let _serial = serial();
    for depth in [100usize, 10_000] {
        let mut raw =
            String::from("From: a@b.c\r\nContent-Type: multipart/mixed; boundary=b0\r\n\r\n");
        for i in 0..depth {
            let _ = write!(
                raw,
                "--b{i}\r\nContent-Type: multipart/mixed; boundary=b{}\r\n\r\n",
                i + 1
            );
        }
        raw.push_str("--b");
        let _ = write!(
            raw,
            "{depth}\r\nContent-Type: text/plain\r\n\r\ndeep text\r\n"
        );
        let m = measure(|| parse_message(raw.as_bytes(), CAP));
        check(&format!("nested multipart depth {depth}"), &m, 64 * MIB);
        assert_bounded_output("nested multipart", &m.value);
    }
}

#[test]
fn deeply_nested_html_is_bounded() {
    let _serial = serial();
    for depth in [1_000usize, 200_000] {
        let body = format!(
            "{}deep text{}",
            "<div>".repeat(depth),
            "</div>".repeat(depth)
        );
        let raw = format!("Content-Type: text/html\r\n\r\n{body}");
        let m = measure(|| parse_message(raw.as_bytes(), CAP));
        check(&format!("nested html depth {depth}"), &m, 256 * MIB);
        assert_bounded_output("nested html", &m.value);
    }
    let formatting = format!("Content-Type: text/html\r\n\r\n{}", "<b><i>".repeat(50_000));
    run(
        "unclosed formatting elements",
        formatting.as_bytes(),
        256 * MIB,
    );
    let tables = format!(
        "Content-Type: text/html\r\n\r\n{}",
        "<table><tr><td>".repeat(20_000)
    );
    run("nested tables", tables.as_bytes(), 256 * MIB);
}

#[test]
fn ten_thousand_headers() {
    let _serial = serial();
    let mut raw = String::new();
    for i in 0..10_000 {
        let _ = write!(raw, "X-Junk-{i}: value {i}\r\n");
    }
    raw.push_str("Subject: after the flood\r\nFrom: a@b.c\r\n\r\nbody text\r\n");
    let m = measure(|| {
        (
            parse_headers(raw.as_bytes()),
            parse_message(raw.as_bytes(), CAP),
        )
    });
    check("10k headers", &m, 64 * MIB);
    let (h, p) = m.value;
    assert_eq!(h.subject, "after the flood");
    assert_eq!(p.body.text.as_ref().unwrap().0.trim(), "body text");

    // One header folded across 100k continuation lines.
    let mut raw = String::from("Subject: start");
    for _ in 0..100_000 {
        raw.push_str("\r\n  fold");
    }
    raw.push_str("\r\n\r\nbody");
    let m = measure(|| parse_message(raw.as_bytes(), CAP));
    check("100k folded header lines", &m, 64 * MIB);

    // A single header of 4 MiB with no newline.
    let raw = format!("Subject: {}", "s".repeat(4 * MIB));
    let m = measure(|| parse_headers(raw.as_bytes()));
    check("4 MiB header line", &m, 64 * MIB);
}

#[test]
fn fifty_megabyte_base64_attachment() {
    let _serial = serial();
    // 50 MiB of base64 text (~37.5 MiB decoded), in 76-column lines as an MTA would send it.
    let line = format!("{}\r\n", "QUJD".repeat(19));
    let lines = 50 * MIB / line.len();
    let mut raw = String::with_capacity(lines * line.len() + 512);
    raw.push_str(
        "From: a@b.c\r\nSubject: big\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n\
--B\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n--B\r\n\
Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"big.bin\"\r\n\
Content-Transfer-Encoding: base64\r\n\r\n",
    );
    for _ in 0..lines {
        raw.push_str(&line);
    }
    raw.push_str("\r\n--B--\r\n");
    assert!(raw.len() >= 50 * MIB);
    let raw = raw.into_bytes();

    // Listing a message must not retain the attachment payload in the result, and the
    // transient decode must stay within a small multiple of the input.
    let m = measure(|| parse_message(&raw, CAP));
    check("50 MB attachment parse", &m, 4 * raw.len());
    let p = m.value;
    assert_eq!(p.body.text.as_ref().unwrap().0.trim(), "see attached");
    assert_eq!(p.attachments.len(), 1);
    assert_eq!(p.attachments[0].filename.as_deref(), Some("big.bin"));
    assert!(p.attachments[0].size as usize > 30 * MIB);
    drop(p);

    // Header-only parsing is what list views use; it must not decode the body at all.
    let m = measure(|| parse_headers(&raw));
    check("50 MB attachment headers", &m, 4 * raw.len());
    assert_eq!(m.value.subject, "big");

    // Download path decodes once: payload plus bounded overhead.
    let m = measure(|| attachment_bytes(&raw, 0));
    check("50 MB attachment download", &m, 4 * raw.len());
    let (_, bytes) = m.value.unwrap();
    assert!(bytes.starts_with(b"ABC"));
}

#[test]
fn duplicate_message_ids_and_headers() {
    let _serial = serial();
    let raw =
        b"Message-ID: <first@x>\r\nMessage-ID: <second@x>\r\nSubject: one\r\nSubject: two\r\n\
From: a@b.c\r\nFrom: evil@example.net\r\nIn-Reply-To: <p@x>\r\nIn-Reply-To: <q@x>\r\n\
References: <r1@x>\r\nReferences: <r2@x> <r1@x> <r1@x>\r\n\r\nbody\r\n";
    let p = run("duplicate headers", raw, 4 * MIB);
    // Whichever occurrence the parser picks, exactly one id is reported and it is one of ours.
    let id = p.headers.message_id.as_deref().unwrap();
    assert!(id == "first@x" || id == "second@x", "{id}");
    assert!(p.headers.from.len() <= 2);
    assert_eq!(parse_headers(raw).message_id.as_deref(), Some(id));

    // Thousands of identical Message-IDs.
    let mut raw = "Message-ID: <same@x>\r\n".repeat(10_000);
    raw.push_str("Subject: s\r\n\r\nb");
    let m = measure(|| parse_message(raw.as_bytes(), CAP));
    check("10k duplicate Message-ID", &m, 64 * MIB);
    assert_eq!(m.value.headers.message_id.as_deref(), Some("same@x"));
}

#[test]
fn nul_bytes_never_reach_output() {
    let _serial = serial();
    let raw =
        b"From: a\0@b.c\r\nSubject: sub\0ject\r\nContent-Type: text/plain\r\n\r\nbo\0dy\0\0text";
    let p = run("nul bytes", raw, 4 * MIB);
    assert_eq!(p.headers.subject, "subject");
    let text = p.body.text.as_ref().unwrap().0.as_str();
    assert!(!text.contains('\0'), "{text:?}");
    assert!(text.contains("body"), "{text:?}");
    for e in p.headers.from.iter().map(|a| &a.email) {
        assert!(!e.contains('\0'));
    }
    // A NUL inside the media type makes it an unknown type, so the part is not a text body;
    // the contract is only that nothing panics and no NUL reaches the output.
    let odd = run(
        "nul in content-type",
        b"Subject: s\r\nContent-Type: text/pl\0ain\r\n\r\nbo\0dy",
        4 * MIB,
    );
    assert!(odd.body.text.is_none_or(|t| !t.0.contains('\0')));
    let all_nul = vec![0u8; 4 * MIB];
    let m = measure(|| parse_message(&all_nul, CAP));
    check("4 MiB of NUL", &m, 64 * MIB);
    assert!(m.value.body.text.is_none_or(|t| !t.0.contains('\0')));
}

#[test]
fn utf7_folder_names_are_bounded_and_lossless_where_valid() {
    let _serial = serial();
    let hostile = [
        "&".repeat(100_000),
        "&-".repeat(50_000),
        format!("&{}", "A".repeat(200_000)),
        format!("&{}-", "AAAA".repeat(50_000)),
        "&AOk-&AOk".to_owned(),
        "&2D3eAA-".to_owned(), // lone surrogate pair half
        "&2D0-".to_owned(),
        "&///,,,-".to_owned(),
        "\0&\0-\0".to_owned(),
        "日本語/メール".to_owned(),
    ];
    for name in &hostile {
        let m = measure(|| (utf7::decode(name), utf7::encode(name)));
        check("utf7", &m, 64 * MIB);
        let (decoded, encoded) = m.value;
        // Decode of arbitrary input never loses the "no raw non-ASCII on the wire" rule on encode.
        assert!(
            encoded.is_ascii() || name.chars().any(|c| !c.is_ascii() && c.is_control()),
            "{encoded:?}"
        );
        // Whatever decode produced must re-encode to ASCII and decode back to itself.
        assert_eq!(utf7::decode(&utf7::encode(&decoded)), decoded);
    }
    for good in ["Entwürfe", "日本語", "a&b", "Sent 📤", "INBOX/ünï/cödé"] {
        assert_eq!(utf7::decode(&utf7::encode(good)), good);
    }
}
