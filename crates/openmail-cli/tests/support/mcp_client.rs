//! Minimal real MCP client over the child's stdio: newline-delimited JSON-RPC 2.0.
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const REPLY_TIMEOUT: Duration = Duration::from_secs(60);

pub struct McpProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    stderr: JoinHandle<String>,
    next_id: u64,
    /// Every raw stdout line seen, for the "no credentials in output" assertions.
    pub transcript: Vec<String>,
}

pub struct StartOpts<'a> {
    pub config: &'a Path,
    pub ca_pem: &'a Path,
    pub env: &'a [(&'a str, &'a str)],
}

impl McpProcess {
    pub fn spawn(o: &StartOpts<'_>) -> Self {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_openmail-mcp"));
        cmd.args(["--config"]).arg(o.config).args([
            "--log",
            "debug",
            "serve",
            "--transport",
            "stdio",
        ]);
        cmd.env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("SSL_CERT_FILE", o.ca_pem)
            // Defeat any system-wide override so the CA file is the only trust source.
            .env_remove("SSL_CERT_DIR");
        for (k, v) in o.env {
            cmd.env(k, v);
        }
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().expect("spawn openmail-mcp");
        let stdin = child.stdin.take();
        let out = child.stdout.take().expect("stdout");
        let err = child.stderr.take().expect("stderr");
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for l in BufReader::new(out).lines().map_while(Result::ok) {
                if tx.send(l).is_err() {
                    break;
                }
            }
        });
        let stderr = std::thread::spawn(move || {
            let mut s = String::new();
            for l in BufReader::new(err).lines().map_while(Result::ok) {
                s.push_str(&l);
                s.push('\n');
            }
            s
        });
        Self {
            child,
            stdin,
            lines,
            stderr,
            next_id: 1,
            transcript: Vec::new(),
        }
    }

    fn write(&mut self, v: &Value) {
        let stdin = self.stdin.as_mut().expect("stdin open");
        writeln!(stdin, "{v}").expect("write request");
        stdin.flush().expect("flush");
    }

    pub fn notify(&mut self, method: &str, params: Value) {
        self.write(&json!({"jsonrpc":"2.0","method":method,"params":params}));
    }

    /// Sends a request and returns the full JSON-RPC response (result or error).
    pub fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.write(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}));
        let deadline = Instant::now() + REPLY_TIMEOUT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    self.transcript.push(line.clone());
                    let v: Value = serde_json::from_str(&line)
                        .unwrap_or_else(|e| panic!("stdout line is not JSON ({e}): {line}"));
                    if v.get("id") == Some(&json!(id)) {
                        return v;
                    }
                }
                Err(RecvTimeoutError::Timeout) => panic!("timed out waiting for reply to {method}"),
                Err(RecvTimeoutError::Disconnected) => {
                    panic!("server closed stdout while waiting for {method}")
                }
            }
        }
    }

    pub fn initialize(&mut self) -> Value {
        let r = self.request(
            "initialize",
            json!({"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"openmail-e2e","version":"0"}}),
        );
        self.notify("notifications/initialized", json!({}));
        r
    }

    /// Calls a tool; returns (is_error, parsed JSON payload or text).
    pub fn call_tool(&mut self, name: &str, args: Value) -> ToolOutcome {
        let r = self.request("tools/call", json!({"name":name,"arguments":args}));
        if let Some(err) = r.get("error") {
            return ToolOutcome {
                is_error: true,
                payload: err.clone(),
                raw: r.to_string(),
            };
        }
        let res = &r["result"];
        let is_error = res.get("isError").and_then(Value::as_bool).unwrap_or(false);
        let payload = res
            .get("structuredContent")
            .cloned()
            .or_else(|| {
                res["content"][0]["text"].as_str().map(|t| {
                    serde_json::from_str(t).unwrap_or_else(|_| Value::String(t.to_owned()))
                })
            })
            .unwrap_or(Value::Null);
        ToolOutcome {
            is_error,
            payload,
            raw: r.to_string(),
        }
    }

    /// Closes stdin (EOF) and waits for a clean exit; returns (exit success, stderr).
    pub fn shutdown_on_eof(mut self) -> (bool, String, Vec<String>) {
        drop(self.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(15);
        let status = loop {
            if let Some(s) = self.child.try_wait().expect("try_wait") {
                break Some(s);
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                break None;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        while let Ok(l) = self.lines.try_recv() {
            self.transcript.push(l);
        }
        let stderr = self.stderr.join().unwrap_or_default();
        (status.is_some_and(|s| s.success()), stderr, self.transcript)
    }
}

#[derive(Debug)]
pub struct ToolOutcome {
    pub is_error: bool,
    pub payload: Value,
    pub raw: String,
}
