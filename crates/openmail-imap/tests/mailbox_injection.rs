//! A hostile folder name (e.g. from a LIST reply or a model-supplied argument) must never
//! be able to terminate the IMAP command line and start another one. A scripted server
//! records the bytes the real async-imap client writes for each folder-taking command.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use async_imap::Client;
use openmail_imap::ops::mailbox_name;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, duplex};

const HOSTILE: [&str; 5] = [
    "INBOX\r\nA9 DELETE Archive",
    "x\nA9 LOGOUT",
    "nul\0byte",
    "quote\" A9 DELETE \"Archive",
    "back\\slash\r{5}\r\nabcde",
];

/// Runs `cmd` against a scripted server and returns every raw line it received after login.
async fn wire_lines<F, Fut>(cmd: F) -> Vec<String>
where
    F: FnOnce(async_imap::Session<tokio::io::DuplexStream>) -> Fut,
    Fut: Future<Output = ()>,
{
    let (client_io, server_io) = duplex(8192);
    let server = tokio::spawn(async move {
        let (r, mut w) = tokio::io::split(server_io);
        let mut r = BufReader::new(r);
        w.write_all(b"* OK ready\r\n").await.unwrap();
        let mut seen = Vec::new();
        let mut buf = Vec::new();
        loop {
            buf.clear();
            if r.read_until(b'\n', &mut buf).await.unwrap() == 0 {
                break;
            }
            let line = String::from_utf8_lossy(&buf).into_owned();
            let tag = line.split(' ').next().unwrap_or("A0").to_owned();
            if line.contains(" LOGIN ") {
                w.write_all(format!("{tag} OK logged in\r\n").as_bytes())
                    .await
                    .unwrap();
                continue;
            }
            seen.push(line);
            w.write_all(format!("{tag} NO nope\r\n").as_bytes())
                .await
                .unwrap();
        }
        seen
    });
    let session = Client::new(client_io)
        .login("u", "p")
        .await
        .map_err(|(e, _)| e)
        .unwrap();
    cmd(session).await;
    server.await.unwrap()
}

fn assert_single_command(lines: &[String]) {
    // Every received line must be a complete, CRLF-terminated command with the client's own
    // tag sequence: an injected second command would show up as an extra/foreign line.
    for (i, l) in lines.iter().enumerate() {
        assert!(l.ends_with("\r\n"), "unterminated line {l:?}");
        assert_eq!(l.matches('\n').count(), 1, "embedded newline in {l:?}");
        assert_eq!(l.matches('\r').count(), 1, "embedded CR in {l:?}");
        assert!(!l.contains('\0'), "NUL on the wire in {l:?}");
        assert!(
            l.starts_with(&format!("A{:04} ", i + 2)),
            "foreign tag in {l:?}"
        );
    }
}

#[test]
fn mailbox_names_are_pure_printable_ascii_on_the_wire() {
    for h in HOSTILE {
        let w = mailbox_name(h);
        assert!(
            w.bytes().all(|b| (0x20..=0x7e).contains(&b)),
            "{h:?} -> {w:?} contains raw control bytes"
        );
    }
}

#[tokio::test]
async fn hostile_folder_names_cannot_inject_commands() {
    let lines = wire_lines(|mut s| async move {
        for h in HOSTILE {
            let n = mailbox_name(h);
            // Server answers NO to everything; only the bytes written matter here.
            let _ = s.select(&n).await;
            let _ = s.examine(&n).await;
            let _ = s.status(&n, "(MESSAGES)").await;
            let _ = s.create(&n).await;
        }
    })
    .await;
    assert_eq!(lines.len(), HOSTILE.len() * 4, "{lines:#?}");
    assert_single_command(&lines);
    assert!(lines.iter().all(|l| !l.contains("DELETE Archive\r\n")));
}

#[tokio::test]
async fn raw_cr_lf_in_unencoded_names_is_rejected_client_side() {
    // Defence in depth: even if a caller skipped `mailbox_name`, async-imap refuses
    // CR/LF in a mailbox argument instead of writing it.
    let lines = wire_lines(|mut s| async move {
        let e = s.select("INBOX\r\nA9 DELETE Archive").await.unwrap_err();
        assert!(matches!(e, async_imap::error::Error::Validate(_)), "{e:?}");
        let e = s.select("a\nb").await.unwrap_err();
        assert!(matches!(e, async_imap::error::Error::Validate(_)), "{e:?}");
    })
    .await;
    assert!(lines.is_empty(), "nothing may be written: {lines:?}");
}
