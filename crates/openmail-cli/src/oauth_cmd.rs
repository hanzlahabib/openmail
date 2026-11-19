//! `oauth hash-password`: turns the owner password into the Argon2id hash the built-in
//! authorization server verifies. The password is read from stdin so it never appears in
//! argv or shell history; only the hash is written to stdout.

use std::io::{Read, Write as _};

use anyhow::{Context, Result, anyhow};

use crate::cli::{OauthAction, OauthArgs};

/// A password is a line, not a file: refuse anything larger instead of hashing garbage.
const MAX_PASSWORD_BYTES: u64 = 1024;

pub fn run(args: OauthArgs) -> Result<()> {
    match args.action {
        OauthAction::HashPassword => {
            let mut raw = String::new();
            std::io::stdin()
                .lock()
                .take(MAX_PASSWORD_BYTES)
                .read_to_string(&mut raw)
                .context("reading the password from stdin")?;
            let hash = hash_line(&raw)?;
            writeln!(std::io::stdout().lock(), "{hash}").context("writing the hash")
        }
    }
}

fn hash_line(raw: &str) -> Result<String> {
    // Trailing newline from `echo`/here-strings is not part of the password.
    let password = raw.trim_end_matches(['\r', '\n']);
    openmail_authserver::hash_password(password).map_err(|e| anyhow!("{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newline_is_stripped_and_short_passwords_are_refused() -> Result<()> {
        let a = hash_line("correct horse battery staple\n")?;
        assert!(a.starts_with("$argon2id$"), "{a}");
        assert!(hash_line("short\n").is_err());
        Ok(())
    }
}
