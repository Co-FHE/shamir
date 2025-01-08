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
    identify::{self, Behaviour},
    noise,
    swarm::SwarmEvent,
    tcp, yamux, Multiaddr,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct Signer {
    validator_keypair: libp2p::identity::Keypair,
    p2p_keypair: libp2p::identity::Keypair,
    swarm: libp2p::Swarm<Behaviour>,
    coordinator_addr: Multiaddr,
    ipc_path: PathBuf,
}
enum Command {
    PeerId,
    ValidatorPeerId,
    CoordinatorPeerId,
    P2pPeerId,
    Help,
    PingCoordinator,
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
            "peer id" | "id" | "pid" => Command::PeerId,
            "validator peer id" | "vpid" => Command::ValidatorPeerId,
            "coordinator peer id" | "cpid" => Command::CoordinatorPeerId,
            "p2p peer id" | "ppid" => Command::P2pPeerId,
            "help" | "h" => Command::Help,
            "ping coordinator" | "pc" => Command::PingCoordinator,
            other => Command::Unknown(other.to_string()),
        }
    }
    fn help_text() -> &'static str {
        "Available commands:
        - `peer id`/`id`/`pid`: Show the peer ID
            - `validator peer id`/`vpid`: Show the validator peer ID
            - `coordinator peer id`/`cpid`: Show the coordinator peer ID
            - `p2p peer id`/`ppid`: Show the p2p peer ID
        - `help`/`h`: Show this help message
        - `ping coordinator`/`pc`: Ping the coordinator"
    }
}

impl Signer {
    pub fn new(validator_keypair: libp2p::identity::Keypair) -> Result<Self, anyhow::Error> {
        let keypair = libp2p::identity::Keypair::generate_ed25519();
        let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair.clone())
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
        let coordinator_addr: Multiaddr = format!(
            "/ip4/{}/tcp/{}/p2p/{}",
            Settings::global().coordinator.remote_addr,
            Settings::global().coordinator.port,
            Settings::global().coordinator.peer_id
        )
        .parse()?;
        Ok(Self {
            validator_keypair: validator_keypair.clone(),
            p2p_keypair: keypair,
            swarm,
            coordinator_addr,
            ipc_path: PathBuf::from(Settings::global().signer.ipc_socket_path).join(format!(
                "signer_{}.sock",
                validator_keypair.public().to_peer_id().to_string()
            )),
        })
    }
    pub(crate) async fn start_listening(&mut self) -> Result<(), anyhow::Error> {
        self.swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

        let listener = self.start_ipc_listening().await?;
        loop {
            tokio::select! {
                event = self.swarm.select_next_some()=> {
                    match event {
                        SwarmEvent::NewListenAddr { address, .. } => tracing::info!("Listening on {address:?}"),
                        // Prints peer id identify info is being sent to.
                        SwarmEvent::Behaviour(identify::Event::Sent { peer_id, .. }) => {
                        tracing::info!("Sent identify info to {peer_id:?}")
                    }
                    // Prints out the info received via the identify event
                    SwarmEvent::Behaviour(identify::Event::Received { info, .. }) => {
                        tracing::info!("Received {info:?}")
                    }
                    _ => {}
                }
                },
                event = listener.accept()=> {
                    match event {
                        Ok((stream, _addr)) => {

                            let mut reader = BufReader::new(stream);
                            let mut line = String::new();
                            let bytes_read = reader.read_line(&mut line).await?;
                            if bytes_read == 0 {
                                continue;
                            }
                            tracing::info!("Received command: {}", line);
                            let command = Command::parse(&line);
                            match command {
                                Command::PeerId => {
                                    tracing::info!("Sending peer id");
                                    reader.get_mut().write_all(format!("p2p peer id: {}\nvalidator peer id: {}\ncoordinator peer id: {}", self.p2p_keypair.public().to_peer_id().to_base58(), self.validator_keypair.public().to_peer_id().to_base58(), self.coordinator_addr.to_string()).as_bytes()).await?;
                                    reader.get_mut().write_all(b"\n").await?;
                                },
                                Command::Help => {
                                    tracing::info!("Sending help text");
                                    reader.get_mut().write_all(Command::help_text().as_bytes()).await?;
                                    reader.get_mut().write_all(b"\n").await?;
                                },
                                Command::ValidatorPeerId => {
                                    reader.get_mut().write_all(self.validator_keypair.public().to_peer_id().to_base58().as_bytes()).await?;
                                    reader.get_mut().write_all(b"\n").await?;
                                },
                                Command::CoordinatorPeerId => {
                                    tracing::info!("Sending coordinator peer id");
                                    reader.get_mut().write_all(self.coordinator_addr.to_string().as_bytes()).await?;
                                    reader.get_mut().write_all(b"\n").await?;
                                },
                                Command::P2pPeerId => {
                                    tracing::info!("Sending p2p peer id");
                                    reader.get_mut().write_all(self.p2p_keypair.public().to_peer_id().to_base58().as_bytes()).await?;
                                    reader.get_mut().write_all(b"\n").await?;
                                },
                                Command::PingCoordinator => {
                                    tracing::info!("Pinging coordinator");
                                    if let Err(e) = self.dial_coordinator() {
                                        reader.get_mut().write_all(e.to_string().as_bytes()).await?;
                                    } else {
                                        reader.get_mut().write_all(b"Coordinator pinged\n").await?;
                                    }
                                },
                                Command::Unknown(cmd) => {
                                    tracing::info!("Unknown command: {}", cmd);
                                    let msg = format!("Unknown command: {}\n", cmd);
                                    reader.get_mut().write_all(msg.as_bytes()).await?;
                                    reader.get_mut().write_all(Command::help_text().as_bytes()).await?;
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!("IPC accept error: {}", e);
                        }
                    }
                }
            }
        }
    }
    pub(crate) fn dial_coordinator(&mut self) -> Result<(), anyhow::Error> {
        self.swarm.dial(self.coordinator_addr.clone())?;

        Ok(())
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
