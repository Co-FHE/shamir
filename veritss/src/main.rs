mod commands;
use common::Settings;
use coordinator_signer::crypto;
use coordinator_signer::crypto::validator_identity::p2p_identity::P2pIdentity;
use coordinator_signer::crypto::PkId;
use coordinator_signer::node::Node;
use coordinator_signer::signer::Signer;
use coordinator_signer::{
    coordinator::Coordinator, crypto::validator_identity::ValidatorIdentityIdentity,
};
use std::{error::Error, fs::File, io::Read};
use tokio;
use tracing;

pub fn load_keypair(path: &str) -> libp2p::identity::Keypair {
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
            let coordinator = Coordinator::<P2pIdentity>::new(keypair)?;
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
            let signer = Signer::<P2pIdentity>::new(keypair)?;
            signer.start_listening().await?;
        }
        commands::Commands::DKG {
            min_signer,
            crypto_type,
        } => {
            let keypair = load_keypair(Settings::global().node.keypair_path.as_str());
            let mut node = Node::<P2pIdentity>::new(keypair)?;
            let participants = Settings::global()
                .coordinator
                .peer_id_whitelist
                .iter()
                .map(|peer_id| libp2p::identity::PeerId::from_fmt_str(peer_id).unwrap())
                .collect::<Vec<_>>();
            let resp = node
                .key_generate(crypto_type, participants, min_signer)
                .unwrap();
            let r = resp.await.unwrap().unwrap();
            tracing::info!("{:?}", r.to_string());
        }
        commands::Commands::Sign {
            pkid,
            message,
            tweak,
        } => {
            println!("pkid: {}", pkid);
            println!("message: {}", message);
            println!("tweak: {:?}", tweak);
            let keypair = load_keypair(Settings::global().node.keypair_path.as_str());
            let mut node = Node::<P2pIdentity>::new(keypair)?;
            let resp = node
                .sign(
                    PkId::new(hex::decode(&pkid).unwrap()),
                    message.as_bytes().to_vec(),
                    tweak.map(|t| t.as_bytes().to_vec()),
                )
                .unwrap();
            let r = resp.await.unwrap().unwrap();
            println!("{}", r.pretty_print());
            println!("{:?}", r.verify::<crypto::Secp256K1Sha256TR>());
        }
    }
    Ok(())
}
