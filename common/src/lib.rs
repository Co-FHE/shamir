// my_workspace/common/src/lib.rs
mod config;
mod logging;
pub use config::Settings;
pub use logging::init_logging;
