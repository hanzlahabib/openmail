//! Hook for the briefing tools (`brief_*`), owned by the briefing task. It is deliberately an
//! empty router today: when the tools land they must be added in an
//! `#[tool_router(router = brief_router, vis = "pub(crate)")]` impl in this file, replacing this
//! function, and must call `OpenMailServer::authorized*` like every other tool
//! (`tests/authz.rs` enumerates the registered tools and fails if one skips it).
use rmcp::handler::server::router::tool::ToolRouter;

use crate::backend::FullBackend;
use crate::server::OpenMailServer;

impl<B: FullBackend> OpenMailServer<B> {
    pub(crate) fn brief_router() -> ToolRouter<Self> {
        ToolRouter::new()
    }
}
