pub(crate) enum Command {
    PeerId,
    Help,
    ListSignerAddr,
    StartDkg,
    Unknown(String),
}

impl Command {
    pub(crate) fn parse(input: &str) -> Self {
        match input
            .trim()
            .to_lowercase()
            .replace("-", " ")
            .replace("_", " ")
            .as_str()
        {
            "peer id" | "peerid" | "pid" => Command::PeerId,
            "help" | "h" => Command::Help,
            "list signer info" | "ls" => Command::ListSignerAddr,
            "start dkg" | "dkg" => Command::StartDkg,
            other => Command::Unknown(other.to_string()),
        }
    }

    pub(crate) fn help_text() -> &'static str {
        "Available commands:
        - peer id | peerid | pid: Show the peer ID
        - help | h: Show this help message
        - list signer info | ls: List signer info
        - start dkg | dkg: Start DKG"
    }
}
