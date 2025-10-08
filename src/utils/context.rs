use once_cell::sync::OnceCell;
use std::sync::Arc;

use crate::{config::Config, utils::http::HttpCtx};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OutputMode {
    Console,
    Json,
    NdJson,
}

static APP_CONTEXT: OnceCell<AppContext> = OnceCell::new();

#[derive(Clone)]
pub struct AppContext {
    pub output_mode: OutputMode,
    pub quiet: bool,
    #[allow(dead_code)]
    pub colors_enabled: bool,
    pub http: Arc<HttpCtx>,
    pub config: Arc<Config>,
}

#[derive(Clone)]
pub struct ExecutionCtx {
    pub http: Arc<HttpCtx>,
    pub config: Arc<Config>,
}

impl AppContext {
    pub fn initialize(ctx: AppContext) {
        let _ = APP_CONTEXT.set(ctx);
    }

    pub fn current() -> &'static AppContext {
        APP_CONTEXT.get().expect("AppContext not initialised")
    }

    pub fn http(&self) -> Arc<HttpCtx> {
        Arc::clone(&self.http)
    }

    pub fn execution(&self) -> ExecutionCtx {
        ExecutionCtx {
            http: Arc::clone(&self.http),
            config: Arc::clone(&self.config),
        }
    }
}
