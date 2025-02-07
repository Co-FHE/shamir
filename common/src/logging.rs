use crate::config::Settings;
use chrono;
use rand::{thread_rng, Rng};
use std::path::PathBuf;
use std::time::SystemTime;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter, Layer}; // Import extension traits

// if base_path is None, log to stdout
pub fn init_logging(
    tag: Option<&str>,
    base_path: Option<PathBuf>,
) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    let settings = Settings::global();
    let console_level = &settings.logging.console.level;

    let console_filter = EnvFilter::try_new(console_level)
        .or_else(|_| EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let random_hex: String = (0..4)
        .map(|_| format!("{:02x}", thread_rng().gen_range(0..=255)))
        .collect();

    let now = SystemTime::now();
    let datetime: chrono::DateTime<chrono::Local> = now.into();
    let date_str = datetime.format("%Y-%m-%d").to_string();
    let time_str = datetime.format("%H-%M-%S").to_string();
    let file_guard = if let Some(base_path) = base_path {
        let console_layer = fmt::layer()
            .with_writer(std::io::stdout)
            .with_file(true)
            .with_line_number(true)
            .with_target(false)
            .with_thread_ids(true)
            .with_thread_names(true)
            .pretty()
            .with_filter(console_filter);
        let file_level = &settings.logging.file.level;
        let log_path = base_path.join(&settings.logging.file.dir_path);
        // Create two separate filters for file and console
        let file_filter = EnvFilter::try_new(file_level)
            .or_else(|_| EnvFilter::try_from_default_env())
            .unwrap_or_else(|_| EnvFilter::new("info"));

        let filename = if let Some(tag) = tag {
            let sanitized_tag = tag.replace(|c: char| !c.is_alphanumeric(), "_");
            format!(
                "log_{}_{}_{}.{}",
                sanitized_tag, date_str, time_str, random_hex
            )
        } else {
            format!("log_{}_{}.{}", date_str, time_str, random_hex)
        };

        let file_appender = RollingFileAppender::builder()
            .filename_suffix("log")
            .rotation(Rotation::DAILY)
            .filename_prefix(&filename)
            .build(log_path)
            .unwrap();
        let (file_writer, file_guard) = tracing_appender::non_blocking(file_appender);
        let file_layer = fmt::layer()
            .with_writer(file_writer)
            .with_file(true)
            .with_line_number(true)
            .with_target(false)
            .with_thread_ids(true)
            .with_thread_names(true)
            .with_ansi(false)
            .with_filter(file_filter);
        tracing_subscriber::registry()
            .with(file_layer)
            .with(console_layer)
            .init();
        Some(file_guard)
    } else {
        let console_layer = fmt::layer()
            .with_writer(std::io::stdout)
            .with_file(true)
            .with_line_number(true)
            .with_target(false)
            .with_thread_ids(true)
            .with_thread_names(true)
            .pretty()
            .with_filter(console_filter);
        tracing_subscriber::registry().with(console_layer).init();
        None
    };

    let args: Vec<String> = std::env::args().collect();
    tracing::info!("Program started with args: {}", args.join(" "));

    file_guard
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::{debug, error, info, trace, warn};

    #[test]
    fn test_init_logging() {
        let _guard = init_logging(Some("test_tag"), None);
        info!("test_init_logging - info");
        debug!("test_init_logging - debug");
        error!("test_init_logging - error");
        warn!("test_init_logging - warn");
        trace!("test_init_logging - trace");
    }
}
