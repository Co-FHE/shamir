// Configuration settings for the application
use config::{Config, Environment, File, FileFormat};
use lazy_static::lazy_static;
use serde::Deserialize;
use std::{
    collections::{BTreeMap, HashSet},
    path::PathBuf,
    sync::RwLock,
};

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub logging: LoggingSettings,
    pub coordinator: CoordinatorSettings,
    pub signer: SignerSettings,
    pub node: NodeSettings,
    pub connection: ConnectionSettings,
    pub session: SessionSettings,
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
    pub enable: bool,
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
    pub keystore_path: PathBuf,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SignerSettings {
    pub keypair_path_mapping: BTreeMap<u16, String>,
    pub ipc_socket_path: String,
    pub allow_external_address: bool,
    pub keystore_path: PathBuf,
    pub connection_timeout: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NodeSettings {
    pub keypair_path: String,
    pub ipc_socket_path: String,
    pub connection_timeout: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ConnectionSettings {
    pub ping_interval: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SessionSettings {
    pub state_channel_retry_interval: u64,
    pub signing_round1_timeout: u64,
    pub signing_round2_timeout: u64,
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
            let config_bytes = include_bytes!("../config.yaml");
            let config_str = String::from_utf8_lossy(config_bytes);
            *settings = Some(
                Config::builder()
                    .add_source(File::from_str(&config_str, FileFormat::Yaml))
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
