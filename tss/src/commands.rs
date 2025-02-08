use clap::{command, Parser, Subcommand};
use coordinator_signer::crypto::CryptoType;

// Define the structure for the command-line application
#[derive(Parser)]
#[command(name = "Role Based CLI")]
#[command(about = "CLI for Coordinator and Signer roles")]
#[command(version = "1.0")]
pub struct CommandLineApp {
    // Use the Subcommand attribute to specify subcommands
    #[command(subcommand)]
    pub command: Commands,
}

// Define the supported subcommands
#[derive(Subcommand)]
pub enum Commands {
    /// Run as a coordinator role
    Coordinator,
    /// Run as a node role
    DKG {
        min_signer: u16,
        #[arg(value_parser = parse_crypto_type)]
        crypto_type: CryptoType,
    },
    LoopSign {
        pkid: String,
        times: usize,
    },
    AutoDKG,
    Lspk,
    Pk {
        pkid: String,
        tweak: Option<String>,
    },
    ///
    Sign {
        pkid: String,
        message: String,
        tweak: Option<String>,
    },

    /// Run as a signer role and require the 'id' argument
    Signer {
        /// The ID of the signer
        id: u16,
    },
}

fn parse_crypto_type(s: &str) -> Result<CryptoType, String> {
    let value = s.parse::<u8>().map_err(|e| e.to_string())?;
    CryptoType::try_from(value).map_err(|e| e.to_string())
}

pub fn parse_args() -> Commands {
    CommandLineApp::parse().command
}
