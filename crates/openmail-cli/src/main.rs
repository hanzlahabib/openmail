mod account_store;
mod accounts;
mod approvals;
mod brief_cmd;
mod cli;
mod doctor;
mod init;
mod oauth_cmd;
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
        Command::Approvals(mut args) => {
            args.config = config;
            approvals::run(args)
        }
        Command::Oauth(args) => oauth_cmd::run(args),
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
    let mut env_filter = EnvFilter::try_new(filter).unwrap_or_else(|_| EnvFilter::new("warn"));
    // rmcp logs whole tool results (mail bodies) at debug, so a blanket `--log debug` would copy
    // mailbox content into stderr. Cap it unless the user asks for rmcp explicitly.
    if !filter.contains("rmcp")
        && let Ok(cap) = "rmcp=info".parse()
    {
        env_filter = env_filter.add_directive(cap);
    }
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr)
        .init();
}
