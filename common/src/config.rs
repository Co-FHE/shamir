// Configuration settings for the application
use config::{Config, Environment, File};
use lazy_static::lazy_static;
use serde::Deserialize;
use std::sync::RwLock;

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub logging: LoggingSettings,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LoggingSettings {
    pub console: LoggingLevelSettings,
    pub file: LoggingFileSettings,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LoggingLevelSettings {
    pub level: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LoggingFileSettings {
    pub level: String,
    pub dir_path: String,
}

lazy_static! {
    pub static ref SETTINGS: RwLock<Option<Settings>> = RwLock::new(None);
}

impl Settings {
    pub fn global() -> Settings {
        let settings = SETTINGS.read().unwrap();
        if let Some(settings) = settings.clone() {
            return settings;
        }
        drop(settings);

        let mut settings = SETTINGS.write().unwrap();
        if settings.is_none() {
            println!("Loading config.yaml");
            *settings = Some(
                Config::builder()
                    .add_source(File::with_name("config.yaml"))
                    .add_source(Environment::with_prefix("TSS"))
                    .build()
                    .unwrap()
                    .try_deserialize::<Settings>()
                    .unwrap(),
            );
        }
        settings.clone().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_settings() {
        let settings = Settings::global();
        println!("{:?}", settings);
    }
}
