use libp2p::identify::Behaviour;
use std::any;
use std::collections::BTreeMap;
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task;

use common::Settings;
use futures::StreamExt;
use libp2p::{
    identify::{self},
    noise,
    swarm::SwarmEvent,
    tcp, yamux, Multiaddr,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct Coordinator {
    p2p_keypair: libp2p::identity::Keypair,
    swarm: libp2p::Swarm<Behaviour>,
    signer_keypairs: BTreeMap<u16, Multiaddr>,
    ipc_path: PathBuf,
}
enum Command {
    PeerId,
    Help,
    ListSignerAddr,
    Unknown(String),
}

impl Command {
    fn parse(input: &str) -> Self {
        match input
            .trim()
            .to_lowercase()
            .replace("-", " ")
            .replace("_", " ")
            .as_str()
        {
            "peer id" => Command::PeerId,
            "help" => Command::Help,
            "list signer addr" => Command::ListSignerAddr,
            other => Command::Unknown(other.to_string()),
        }
    }

    fn help_text() -> &'static str {
        "Available commands:
        - peer id: Show the peer ID
        - help: Show this help message
        - list signer addr: List signer addresses"
    }
}

impl Coordinator {
    pub fn new(p2p_keypair: libp2p::identity::Keypair) -> anyhow::Result<Self> {
        let swarm = libp2p::SwarmBuilder::with_existing_identity(p2p_keypair.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(|key| {
                identify::Behaviour::new(identify::Config::new(
                    "/ipfs/id/1.0.0".to_string(),
                    key.public(),
                ))
            })?
            .build();
        Ok(Self {
            p2p_keypair,
            swarm,
            signer_keypairs: BTreeMap::new(),
            ipc_path: Settings::global().coordinator.ipc_socket_path.into(),
        })
    }

    pub async fn start_listening(&mut self) -> Result<(), anyhow::Error> {
        self.swarm.listen_on(
            format!("/ip4/0.0.0.0/tcp/{}", Settings::global().coordinator.port).parse()?,
        )?;
        let listener = self.start_ipc_listening().await?;
        loop {
            tokio::select! {
                event = self.swarm.select_next_some()=> {
                    match event {
                        SwarmEvent::NewListenAddr { address, .. } => tracing::info!("Listening on {address:?}"),
                        SwarmEvent::Behaviour(event) => {
                            match event {
                                identify::Event::Received { connection_id, peer_id, info } => {
                                    tracing::info!("Received identify info from {peer_id:?}: {info:?}");
                                },
                                identify::Event::Sent { connection_id, peer_id } => todo!(),
                                identify::Event::Pushed { connection_id, peer_id, info } => todo!(),
                                identify::Event::Error { connection_id, peer_id, error } => todo!(),
                            }
                        }
                        _ => {}
                    }
                },
                event = listener.accept()=> {
                    match event {
                        Ok((mut stream, _addr)) => {
                            tracing::info!("IPC accept success");
                            // Spawn a new task to handle the stream
                            let mut reader = BufReader::new(stream);
                            let mut line = String::new();
                            let bytes_read = reader.read_line(&mut line).await?;
                            if bytes_read == 0 {
                                continue;
                            }
                            let command = Command::parse(&line);
                            match command {
                                Command::PeerId => {
                                    reader.get_mut().write_all(self.p2p_keypair.public().to_peer_id().to_base58().as_bytes()).await?;
                                    reader.get_mut().write_all(b"\n").await?;
                                },
                                Command::Help => {
                                    reader.get_mut().write_all(Command::help_text().as_bytes()).await?;
                                    reader.get_mut().write_all(b"\n").await?;
                                },
                                Command::ListSignerAddr => {
                                    let addresses = self.signer_keypairs.keys()
                                        .map(|k| k.to_string())
                                        .collect::<Vec<_>>()
                                        .join(", ");
                                    reader.get_mut().write_all(addresses.as_bytes()).await?;
                                    reader.get_mut().write_all(b"\n").await?;
                                },
                                Command::Unknown(cmd) => {
                                    let msg = format!("Unknown command: {}\n", cmd);
                                    reader.get_mut().write_all(msg.as_bytes()).await?;
                                    reader.get_mut().write_all(Command::help_text().as_bytes()).await?;
                                    reader.get_mut().write_all(b"\n").await?;
                                },
                            }                        }
                        Err(e) => {
                            tracing::error!("IPC accept error: {}", e);
                        }
                    }
                }
            }
        }
    }
    pub async fn start_ipc_listening(&mut self) -> anyhow::Result<UnixListener> {
        // Remove existing IPC socket file if it exists
        if self.ipc_path.exists() {
            std::fs::remove_file(&self.ipc_path)?;
        }

        let listener = UnixListener::bind(&self.ipc_path)?;
        tracing::info!("IPC Listening on {:?}", self.ipc_path);
        return Ok(listener);
    }
}
