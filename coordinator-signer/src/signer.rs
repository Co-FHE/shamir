use common::Settings;
use futures::StreamExt;
use libp2p::{
    identify::{self, Behaviour},
    noise,
    swarm::SwarmEvent,
    tcp, yamux, Multiaddr,
};

pub struct Signer {
    validator_keypair: libp2p::identity::Keypair,
    p2p_keypair: libp2p::identity::Keypair,
    swarm: libp2p::Swarm<Behaviour>,
    coordinator_addr: Multiaddr,
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
            validator_keypair,
            p2p_keypair: keypair,
            swarm,
            coordinator_addr,
        })
    }
    pub(crate) async fn start_listening(&mut self) -> Result<(), anyhow::Error> {
        self.swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

        loop {
            match self.swarm.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => println!("Listening on {address:?}"),
                // Prints peer id identify info is being sent to.
                SwarmEvent::Behaviour(identify::Event::Sent { peer_id, .. }) => {
                    println!("Sent identify info to {peer_id:?}")
                }
                // Prints out the info received via the identify event
                SwarmEvent::Behaviour(identify::Event::Received { info, .. }) => {
                    println!("Received {info:?}")
                }
                _ => {}
            }
        }
    }
    pub(crate) async fn dial_coordinator(&mut self) -> Result<(), anyhow::Error> {
        self.swarm.dial(self.coordinator_addr.clone())?;
        Ok(())
    }
}
