// my_workspace/common/src/lib.rs
mod config;
mod logging;
pub mod message;

pub use config::SETTINGS;
pub use logging::init_logging;
