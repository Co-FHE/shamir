// Configuration settings for the application
use config::{Config, Environment, File};
use lazy_static::lazy_static;
use serde::Deserialize;
use std::{
    collections::{BTreeMap, HashSet},
    sync::RwLock,
};

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub logging: LoggingSettings,
    pub coordinator: CoordinatorSettings,
    pub signer: SignerSettings,
    pub connection: ConnectionSettings,
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

#[derive(Debug, Deserialize, Clone)]
pub struct CoordinatorSettings {
    pub keypair_path: String,
    pub port: u16,
    pub remote_addr: String,
    pub peer_id: String,
    pub ipc_socket_path: String,
    pub peer_id_whitelist: HashSet<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SignerSettings {
    pub keypair_path_mapping: BTreeMap<u16, String>,
    pub ipc_socket_path: String,
    pub allow_external_address: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ConnectionSettings {
    pub ping_interval: u64,
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
