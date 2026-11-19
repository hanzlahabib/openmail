//! Parses every example config with `openmail_core::config::Config` and every
//! client JSON as JSON. Usage: `validator <config.toml|client.json>...`
use std::process::ExitCode;

use openmail_core::config::Config;

fn main() -> ExitCode {
    let mut failed = false;
    for path in std::env::args().skip(1) {
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("FAIL {path}: {e}");
                failed = true;
                continue;
            }
        };
        let result = if path.ends_with(".toml") {
            Config::from_toml(&text)
                .map(|c| format!("{} accounts", c.accounts.len()))
                .map_err(|e| e.to_string())
        } else {
            serde_json::from_str::<serde_json::Value>(&text)
                .map(|_| "valid JSON".to_owned())
                .map_err(|e| e.to_string())
        };
        match result {
            Ok(note) => eprintln!("ok   {path} ({note})"),
            Err(e) => {
                eprintln!("FAIL {path}: {e}");
                failed = true;
            }
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
