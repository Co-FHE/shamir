use crate::crypto::CryptoType;

pub(crate) enum Command {
    PeerId,
    Help,
    ListSignerAddr,
    ListPkId,
    StartDkg(u16, CryptoType),
    Unknown(String),
    Dial(String),
    Sign(String, String),
}

impl Command {
    pub(crate) fn parse(input: &str) -> Self {
        let origin = input.trim().split_whitespace().collect::<Vec<&str>>();
        let binding = input
            .trim()
            .to_lowercase()
            .replace("-", " ")
            .replace("_", " ");
        let parts: Vec<&str> = binding.split_whitespace().collect();

        match parts.as_slice() {
            ["peer", "id"] | ["peerid"] | ["pid"] => Command::PeerId,
            ["help"] | ["h"] => Command::Help,
            ["dial", _] => {
                let peer_id = origin[1].to_string();
                Command::Dial(peer_id.to_string())
            }
            ["list", "signer", "info"] | ["ls"] | ["list"] => Command::ListSignerAddr,
            ["sign", _public_key, _message] => {
                Command::Sign(origin[1].to_string(), origin[2].to_string())
            }
            ["lspk"] => Command::ListPkId,
            ["start", "dkg", num, crypto_type] | ["dkg", num, crypto_type] => {
                if let Ok(n) = num.parse::<u16>() {
                    if let Ok(c) = crypto_type.parse::<u8>() {
                        match c {
                            0 => Command::StartDkg(n, CryptoType::Ed25519),
                            1 => Command::StartDkg(n, CryptoType::Secp256k1),
                            2 => Command::StartDkg(n, CryptoType::Secp256k1Tr),
                            _ => Command::Unknown(parts.join(" ")),
                        }
                    } else {
                        Command::Unknown(parts.join(" "))
                    }
                } else {
                    Command::Unknown(parts.join(" "))
                }
            }
            other => Command::Unknown(other.join(" ")),
        }
    }

    pub(crate) fn help_text() -> &'static str {
        "Available commands:
        - peer id | peerid | pid: Show the peer ID
        - help | h: Show this help message
        - list signer info | ls: List signer info
        - lspk: List pkid
        - sign <public_key> <message>: Sign a message with the given public key
        - start dkg <n> <crypto_type> | dkg <n> <crypto_type>: Start DKG with min n signers and crypto type:
          0: Ed25519
          1: Secp256k1 
          2: Secp256k1Tr"
    }
}
