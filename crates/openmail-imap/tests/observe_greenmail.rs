//! Pool metrics on real flows against GreenMail: a rejected login moves `auth_failures`, an
//! unreachable server moves `imap_connection_failures`, a healthy login moves neither, and the
//! labels carry the account id only.
#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

#[path = "greenmail/harness.rs"]
mod harness;

use std::sync::Arc;

use harness::*;
use openmail_core::backend::MailBackend;
use openmail_core::config::{Limits, TlsMode};
use openmail_core::ids::AccountId;
use openmail_imap::ImapBackend;
use openmail_observe::metrics::{Counter, Labels, Metrics};
use openmail_observe::observer::Observer;

const PW: &str = "secret";

fn id(s: &str) -> AccountId {
    AccountId::new(s).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_and_connection_failures_are_counted_per_account() {
    let Some(gm) = Greenmail::start(&[("alice", PW)]) else {
        return;
    };
    let proxy = TlsProxy::spawn(gm.port, Mode::Implicit, false).await;
    let good = account("alice", "alice", "PW", proxy.port, TlsMode::Implicit);
    let bad = account("badpw", "alice", "BAD", proxy.port, TlsMode::Implicit);
    // Nothing listens on port 1: a connection failure, not an auth failure.
    let down = account("down", "alice", "PW", 1, TlsMode::Implicit);
    let backend = ImapBackend::with_extra_roots(
        vec![good, bad, down],
        Limits::default(),
        secrets(&[("PW", PW), ("BAD", "wrong")]),
        std::slice::from_ref(&proxy.cert),
    )
    .unwrap();
    let metrics = Arc::new(Metrics::new());
    backend
        .pool()
        .set_observer(Observer::recording(Arc::clone(&metrics)));

    backend.list_folders(&id("alice")).await.unwrap();
    assert_eq!(metrics.counter(Counter::AuthFailures), 0);
    assert_eq!(metrics.counter(Counter::ImapConnectionFailures), 0);

    assert!(backend.list_folders(&id("badpw")).await.is_err());
    assert!(backend.list_folders(&id("down")).await.is_err());

    let bad_label = Labels::none().account("badpw");
    let down_label = Labels::none().account("down");
    assert_eq!(metrics.counter_with(Counter::AuthFailures, &bad_label), 1);
    assert_eq!(
        metrics.counter_with(Counter::ImapConnectionFailures, &bad_label),
        0
    );
    assert!(metrics.counter_with(Counter::ImapConnectionFailures, &down_label) >= 1);
    assert_eq!(metrics.counter_with(Counter::AuthFailures, &down_label), 0);
    let text = metrics.render_prometheus();
    assert!(!text.contains("alice@"), "{text}");
}
