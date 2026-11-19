use rmcp::handler::server::router::tool::ToolRouter;

use crate::backend::FullBackend;
use crate::server::OpenMailServer;

impl<B: FullBackend> OpenMailServer<B> {
    pub(crate) fn organize_router() -> ToolRouter<Self> {
        ToolRouter::new()
    }
}
