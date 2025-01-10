use crate::crypto::CryptoType;

pub(crate) enum Command {
    PeerId,
    Help,
    ListSignerAddr,
    StartDkg(u16, CryptoType),
    Unknown(String),
}

impl Command {
    pub(crate) fn parse(input: &str) -> Self {
        let binding = input
            .trim()
            .to_lowercase()
            .replace("-", " ")
            .replace("_", " ");
        let parts: Vec<&str> = binding.split_whitespace().collect();

        match parts.as_slice() {
            ["peer", "id"] | ["peerid"] | ["pid"] => Command::PeerId,
            ["help"] | ["h"] => Command::Help,
            ["list", "signer", "info"] | ["ls"] => Command::ListSignerAddr,
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
        - start dkg <n> <crypto_type> | dkg <n> <crypto_type>: Start DKG with min n signers and crypto type:
          0: Ed25519
          1: Secp256k1 
          2: Secp256k1Tr"
    }
}
