use async_trait::async_trait;
use libp2p::{
    development_transport, identity, swarm::NetworkBehaviourEventProcess, Multiaddr,
    NetworkBehaviour, PeerId, Swarm,
};
use tokio::io::{self, AsyncBufReadExt};

#[derive(NetworkBehaviour)]
struct SignerBehaviour {
    // 添加所需的协议，例如Gossipsub、Ping等
}

#[tokio::main]
async fn main() {
    // 生成密钥对
    let id_keys = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(id_keys.public());
    println!("Signer Peer ID: {}", peer_id);

    // 设置传输
    let transport = development_transport(id_keys.clone()).await.unwrap();

    // 创建Swarm
    let behaviour = SignerBehaviour {
        // 初始化所需协议
    };
    let mut swarm = Swarm::new(transport, behaviour, peer_id.clone());

    // 连接到Coordinator
    let coordinator_addr: Multiaddr = "/ip4/127.0.0.1/tcp/4001/p2p/<COORDINATOR_PEER_ID>"
        .parse()
        .unwrap();
    swarm.dial(coordinator_addr).unwrap();
    println!("Dialed Coordinator");

    // 事件循环
    loop {
        tokio::select! {
            event = swarm.next_event() => {
                // 处理事件，例如新连接、消息接收等
            },
            // 可以添加更多事件处理
        }
    }
}
