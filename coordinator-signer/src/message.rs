use serde::{Deserialize, Serialize};

#[derive(Serialize, Debug)]
pub enum SignerMessage {
    Register,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum SignerResponse {
    RegistrationSuccess { identifier: u16 },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum CoordinatorMessage {
    StartDKG,
    StartTSS { message: String },
    DKGRound1 { from: u16, package: Vec<u8> },
    DKGRound2 { from: u16, package: Vec<u8> },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum CoordinatorResponse {
    DKGResult {},
}
