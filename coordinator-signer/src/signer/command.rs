pub(crate) enum Command {
    PeerId,
    ValidatorPeerId,
    CoordinatorPeerId,
    P2pPeerId,
    Help,
    PingCoordinator,
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
            "peer id" | "id" | "pid" => Command::PeerId,
            "validator peer id" | "vpid" => Command::ValidatorPeerId,
            "coordinator peer id" | "cpid" => Command::CoordinatorPeerId,
            "p2p peer id" | "ppid" => Command::P2pPeerId,
            "help" | "h" => Command::Help,
            "ping coordinator" | "pc" => Command::PingCoordinator,
            other => Command::Unknown(other.to_string()),
        }
    }
    pub(crate) fn help_text() -> &'static str {
        "Available commands:
        - `peer id`/`id`/`pid`: Show the peer ID
            - `validator peer id`/`vpid`: Show the validator peer ID
            - `coordinator peer id`/`cpid`: Show the coordinator peer ID
            - `p2p peer id`/`ppid`: Show the p2p peer ID
        - `help`/`h`: Show this help message
        - `ping coordinator`/`pc`: Ping the coordinator"
    }
}
