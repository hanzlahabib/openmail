//! stdio transport: stdout carries only JSON-RPC (rmcp owns it); diagnostics go through
//! `tracing`, which the host binary must route to stderr.
use openmail_core::backend::MailBackend;
use std::future::Future;

use rmcp::ServiceExt;
use rmcp::service::{QuitReason, ServerInitializeError};
use rmcp::transport::stdio_pipes;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::server::OpenMailServer;

#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error("MCP initialization failed: {0}")]
    Initialize(#[from] Box<ServerInitializeError>),
    #[error("MCP service task failed: {0}")]
    Join(#[from] tokio::task::JoinError),
}

/// Serve over arbitrary async byte streams until the peer closes them or `shutdown` resolves.
/// Split out of [`serve_stdio`] so the exact same lifecycle is testable without a real process.
pub async fn serve_io<B, R, W>(
    server: OpenMailServer<B>,
    reader: R,
    writer: W,
    shutdown: impl Future<Output = ()>,
) -> Result<(), ServeError>
where
    B: MailBackend,
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    let running = server.serve((reader, writer)).await.map_err(Box::new)?;
    let cancel = running.cancellation_token();
    let waiting = running.waiting();
    tokio::pin!(waiting);
    let reason = tokio::select! {
        r = &mut waiting => r?,
        () = shutdown => {
            tracing::info!("shutdown requested, closing MCP session");
            cancel.cancel();
            waiting.await?
        }
    };
    match reason {
        QuitReason::Closed => tracing::info!("client closed the connection"),
        other => tracing::info!(?other, "MCP session ended"),
    }
    Ok(())
}

/// Serve on the process's stdin/stdout. Returns on EOF, SIGTERM or SIGINT.
pub async fn serve_stdio<B: MailBackend>(server: OpenMailServer<B>) -> Result<(), ServeError> {
    let (reader, writer) = stdio_pipes();
    serve_io(server, reader, writer, termination_signal()).await
}

#[cfg(unix)]
async fn termination_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    // If a handler cannot be installed we must not fire shutdown spuriously: wait forever on it.
    let mut term = signal(SignalKind::terminate()).ok();
    let mut int = signal(SignalKind::interrupt()).ok();
    tokio::select! {
        () = recv(&mut term) => {}
        () = recv(&mut int) => {}
    }
}

#[cfg(unix)]
async fn recv(s: &mut Option<tokio::signal::unix::Signal>) {
    match s {
        Some(s) => {
            s.recv().await;
        }
        None => std::future::pending::<()>().await,
    }
}

#[cfg(not(unix))]
async fn termination_signal() {
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}
