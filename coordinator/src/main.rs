use libp2p::{
    development_transport, identity, swarm::NetworkBehaviourEventProcess, Multiaddr,
    NetworkBehaviour, PeerId, Swarm,
};
use std::collections::HashSet;
use tokio::io::{self, AsyncBufReadExt};

#[derive(NetworkBehaviour)]
struct CoordinatorBehaviour {
    // 添加所需的协议，例如Gossipsub、Ping等
    // 这里简单使用一个自定义协议
}

#[tokio::main]
async fn main() {
    // 生成密钥对
    let id_keys = identity::Keypair::generate_ed25519();
    // save to file
    let mut file = File::create("coordinator.key").unwrap();
    file.write_all(&id_keys.encode()).unwrap();
}
