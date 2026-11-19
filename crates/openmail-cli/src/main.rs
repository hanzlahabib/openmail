mod accounts;
mod brief_cmd;
mod cli;
mod doctor;
mod init;
mod serve;

use std::process::ExitCode;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use cli::{Cli, Command};

/// Exit code for runtime failures; clap itself exits 2 on usage errors.
const EXIT_FAILURE: u8 = 1;

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(&cli.log);
    let config = cli::resolve_config_path(cli.config.as_deref());

    let result = match cli.command {
        Command::Init(mut args) => {
            args.config = config;
            init::run(args)
        }
        Command::Doctor(mut args) => {
            args.config = config;
            doctor::run(args)
        }
        Command::Accounts(mut args) => {
            args.config = config;
            accounts::run(args)
        }
        Command::Serve(mut args) => {
            args.config = config;
            serve::run(args)
        }
        Command::Brief(mut args) => {
            args.config = config;
            brief_cmd::run(args)
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(EXIT_FAILURE)
        }
    }
}

/// Logs go to stderr only: stdout is the MCP JSON-RPC channel in stdio mode.
fn init_tracing(filter: &str) {
    let filter = EnvFilter::try_new(filter).unwrap_or_else(|_| EnvFilter::new("warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}
