//! Property tests for send-request validation and the canonical content hash.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use openmail_core::model::Address;
use openmail_smtp::{Attachment, SendRequest, SmtpLimits};
use proptest::prelude::*;

fn base() -> SendRequest {
    SendRequest {
        idempotency_key: "k1".into(),
        from: Address {
            name: Some("Me".into()),
            email: "me@example.com".into(),
        },
        to: vec![Address {
            name: Some("You".into()),
            email: "you@example.org".into(),
        }],
        cc: vec![Address {
            name: None,
            email: "cc@example.org".into(),
        }],
        bcc: vec![Address {
            name: None,
            email: "bcc@example.org".into(),
        }],
        subject: "Hi".into(),
        text: Some("hello".into()),
        html: Some("<p>hello</p>".into()),
        attachments: vec![Attachment {
            filename: "a.txt".into(),
            content_type: "text/plain".into(),
            data: b"data".to_vec(),
        }],
        in_reply_to: Some("<a@b.c>".into()),
        references: vec!["<r@b.c>".into()],
    }
}

#[test]
fn base_request_is_valid() {
    base()
        .validate(&SmtpLimits::default())
        .expect("baseline must validate");
}

/// Every header-bound string field of a request, addressable by index, so a property
/// can inject a control character into exactly one of them.
const HEADER_FIELDS: usize = 16;

fn inject(req: &mut SendRequest, field: usize, pos: usize, ctl: char) {
    fn put(s: &mut String, pos: usize, ctl: char) {
        let at = s.floor_char_boundary(pos.min(s.len()));
        s.insert(at, ctl);
    }
    fn put_opt(s: &mut Option<String>, pos: usize, ctl: char) {
        put(s.get_or_insert_with(String::new), pos, ctl);
    }
    match field {
        0 => put(&mut req.idempotency_key, pos, ctl),
        1 => put(&mut req.subject, pos, ctl),
        2 => put(&mut req.from.email, pos, ctl),
        3 => put_opt(&mut req.from.name, pos, ctl),
        4 => put(&mut req.to[0].email, pos, ctl),
        5 => put_opt(&mut req.to[0].name, pos, ctl),
        6 => put(&mut req.cc[0].email, pos, ctl),
        7 => put_opt(&mut req.cc[0].name, pos, ctl),
        8 => put(&mut req.bcc[0].email, pos, ctl),
        9 => put_opt(&mut req.bcc[0].name, pos, ctl),
        10 => put(&mut req.attachments[0].filename, pos, ctl),
        11 => put(&mut req.attachments[0].content_type, pos, ctl),
        12 => put_opt(&mut req.in_reply_to, pos, ctl),
        13 => put(&mut req.references[0], pos, ctl),
        14 => put(&mut req.to[0].email, 0, ctl),
        _ => put_opt(&mut req.to[0].name, 0, ctl),
    }
}

proptest! {
    #[test]
    fn crlf_nul_never_accepted_in_any_header_field(
        field in 0..HEADER_FIELDS,
        pos in 0usize..32,
        ctl in prop::sample::select(vec!['\r', '\n', '\0']),
    ) {
        let mut req = base();
        inject(&mut req, field, pos, ctl);
        prop_assert!(
            req.validate(&SmtpLimits::default()).is_err(),
            "field {} accepted {:?}", field, ctl
        );
    }

    #[test]
    fn header_injection_payloads_are_rejected(
        payload in "[ -~]{0,20}",
        ctl in prop::sample::select(vec!["\r\n", "\n", "\r", "\0", "\r\nBcc: ", "\n\n"]),
    ) {
        let mut req = base();
        req.subject = format!("{payload}{ctl}Bcc: evil@example.net");
        prop_assert!(req.validate(&SmtpLimits::default()).is_err());
    }

    #[test]
    fn validate_never_panics_on_arbitrary_fields(
        subject in any::<String>(),
        email in any::<String>(),
        name in proptest::option::of(any::<String>()),
        key in any::<String>(),
        text in proptest::option::of(any::<String>()),
        reply in proptest::option::of(any::<String>()),
        filename in any::<String>(),
    ) {
        let mut req = base();
        req.subject = subject;
        req.to[0] = Address { name, email };
        req.idempotency_key = key;
        req.text = text;
        req.in_reply_to = reply;
        req.attachments[0].filename = filename;
        let _ = req.validate(&SmtpLimits::default());
    }

    #[test]
    fn content_hash_is_stable_and_ignores_idempotency_key(key in "[!-~]{1,64}") {
        let a = base();
        let mut b = base();
        b.idempotency_key = key;
        prop_assert_eq!(a.content_hash(), a.clone().content_hash());
        prop_assert_eq!(a.content_hash(), b.content_hash());
    }

    #[test]
    fn content_hash_ignores_email_case_only(email in "[a-zA-Z]{1,8}@[a-zA-Z]{1,8}\\.org") {
        let mut a = base();
        let mut b = base();
        a.to[0].email = email.clone();
        b.to[0].email = email.to_uppercase();
        prop_assert_eq!(a.content_hash(), b.content_hash());
    }

    /// Moving bytes across an adjacent field boundary must change the hash: the
    /// length-prefixed encoding is what stops "ab"+"c" colliding with "a"+"bc".
    #[test]
    fn content_hash_is_injective_across_subject_and_text(s in "[a-z]{2,16}", split in 1usize..15) {
        let split = split.min(s.len() - 1);
        let (l, r) = s.split_at(split);
        let mut a = base();
        a.subject = s.clone();
        a.text = Some(String::new());
        let mut b = base();
        b.subject = l.to_owned();
        b.text = Some(r.to_owned());
        prop_assert_ne!(a.content_hash(), b.content_hash());
    }

    #[test]
    fn content_hash_distinguishes_recipient_lists(local in "[a-z]{1,8}") {
        let addr = Address { name: None, email: format!("{local}@example.org") };
        let mut as_to = base();
        as_to.to = vec![addr.clone()];
        as_to.cc = vec![];
        let mut as_cc = base();
        as_cc.to = vec![];
        as_cc.cc = vec![addr];
        prop_assert_ne!(as_to.content_hash(), as_cc.content_hash());
    }

    #[test]
    fn content_hash_distinguishes_name_from_email_boundary(a in "[a-z]{1,6}", b in "[a-z]{1,6}") {
        let mut x = base();
        x.to[0] = Address { name: Some(format!("{a}{b}")), email: "x@example.org".into() };
        let mut y = base();
        y.to[0] = Address { name: Some(a.clone()), email: format!("{b}x@example.org") };
        prop_assert_ne!(x.content_hash(), y.content_hash());
    }

    #[test]
    fn content_hash_distinguishes_body_none_from_empty(html in proptest::option::of("[a-z]{0,5}")) {
        let mut none = base();
        none.html = None;
        let mut some = base();
        some.html = Some(html.unwrap_or_default());
        prop_assert_ne!(none.content_hash(), some.content_hash());
    }

    #[test]
    fn content_hash_changes_with_attachment_bytes(
        d1 in prop::collection::vec(any::<u8>(), 0..64),
        d2 in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        prop_assume!(d1 != d2);
        let mut a = base();
        a.attachments[0].data = d1;
        let mut b = base();
        b.attachments[0].data = d2;
        prop_assert_ne!(a.content_hash(), b.content_hash());
    }

    #[test]
    fn recipient_and_size_limits_hold_for_any_counts(n in 0usize..80) {
        let mut req = base();
        req.cc.clear();
        req.bcc.clear();
        req.to = (0..n)
            .map(|i| Address { name: None, email: format!("u{i}@example.org") })
            .collect();
        let ok = req.validate(&SmtpLimits::default()).is_ok();
        prop_assert_eq!(ok, (1..=SmtpLimits::default().max_recipients).contains(&n));
    }
}
