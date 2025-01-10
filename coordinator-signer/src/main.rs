use std::{
    error::Error,
    fs::File,
    io::{Read, Write},
};
mod commands;
mod coordinator;
// mod dkgp;
mod behaviour;
mod crypto;
mod signer;
mod utils;
use common::Settings;
use coordinator::Coordinator;
use crypto::P2pIdentity;
#[allow(unused)]
fn generate_keypair(path: &str) {
    let keypair = libp2p::identity::Keypair::generate_ed25519();
    //save to file
    let mut file = File::create(path).unwrap();
    file.write_all(keypair.to_protobuf_encoding().unwrap().as_slice())
        .unwrap();
}
fn load_keypair(path: &str) -> libp2p::identity::Keypair {
    let mut f = File::open(path).unwrap();
    // read the file into a buffer
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).unwrap();
    libp2p::identity::Keypair::from_protobuf_encoding(buffer.as_slice()).unwrap()
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let _ = common::init_logging(None);
    let cmd = commands::parse_args();
    match cmd {
        commands::Commands::Coordinator => {
            // default keypair = 12D3KooWB3LpKiErRF3byUAsCvY6JL8TtQeSCrF5Hw23UoKJ7F88
            let keypair = load_keypair(Settings::global().coordinator.keypair_path.as_str());
            let mut coordinator = Coordinator::<P2pIdentity>::new(keypair)?;
            // coordinator.start_listening().await?;
            coordinator.start_listening().await?;
        }
        commands::Commands::Signer { id } => {
            let keypair = load_keypair(
                Settings::global()
                    .signer
                    .keypair_path_mapping
                    .get(&id)
                    .unwrap(),
            );
            // convert id to peer id
            let peer_id = keypair.public().to_peer_id();
            tracing::info!("Starting signer with validator peer id: {}", peer_id);
            let mut signer = signer::Signer::<P2pIdentity>::new(keypair)?;
            signer.start_listening().await?;
        }
    }
    Ok(())
}
