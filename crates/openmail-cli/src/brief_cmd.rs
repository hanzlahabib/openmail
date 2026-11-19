//! `brief now` / `brief schedule list` glue toward `openmail-briefs`.

use anyhow::{Context, Result, bail};
use openmail_core::config::Config;

use crate::cli::{BriefAction, BriefArgs, ScheduleAction};

pub fn run(args: BriefArgs) -> Result<()> {
    let config = load_config(&args.config)?;
    ensure_accounts(&config)?;
    match args.action {
        BriefAction::Now => bail!(
            "`brief now` is not wired yet: the openmail-briefs aggregation entry point is not linked into the CLI"
        ),
        BriefAction::Schedule {
            action: ScheduleAction::List,
        } => bail!(
            "`brief schedule list` is not wired yet: the openmail-briefs scheduler is not linked into the CLI"
        ),
    }
}

fn load_config(path: &std::path::Path) -> Result<Config> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading config {}", path.display()))?;
    let config = Config::from_toml(&text)?;
    config.validate()?;
    Ok(config)
}

/// A brief over zero accounts is meaningless; say so rather than emit an empty one.
fn ensure_accounts(config: &Config) -> Result<()> {
    if config.accounts.is_empty() {
        bail!("no accounts configured; add one to the config before generating briefs");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_has_no_accounts() -> Result<()> {
        let config = Config::from_toml("version = 1\n")?;
        let text = match ensure_accounts(&config) {
            Ok(()) => String::new(),
            Err(e) => e.to_string(),
        };
        assert!(text.contains("no accounts"));
        Ok(())
    }

    #[test]
    fn missing_file_is_reported() {
        let text = match load_config(std::path::Path::new("/nonexistent/c.toml")) {
            Ok(_) => String::new(),
            Err(e) => format!("{e:#}"),
        };
        assert!(text.contains("reading config"));
    }
}
