//! Black-box tests of the binary surface that need no config or network.

use assert_cmd::Command;

fn run(args: &[&str]) -> assert_cmd::assert::Assert {
    Command::new(env!("CARGO_BIN_EXE_openmail-mcp"))
        .args(args)
        .assert()
}

fn stdout_of(args: &[&str]) -> String {
    let out = run(args).success().get_output().stdout.clone();
    String::from_utf8_lossy(&out).into_owned()
}

#[test]
fn version_prints_crate_version() {
    assert!(stdout_of(&["--version"]).contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn help_lists_subcommands_and_global_config() {
    let text = stdout_of(&["--help"]);
    for sub in ["init", "doctor", "accounts", "serve", "brief", "--config"] {
        assert!(text.contains(sub), "help missing {sub}");
    }
}

#[test]
fn serve_help_documents_transports() {
    let text = stdout_of(&["serve", "--help"]);
    assert!(text.contains("stdio") && text.contains("http"));
}

#[test]
fn unknown_transport_is_usage_error() {
    run(&["serve", "--transport", "smtp"]).code(2);
}

#[test]
fn missing_subcommand_is_usage_error() {
    run(&[]).code(2);
}
