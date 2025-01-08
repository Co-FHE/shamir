use clap::{command, Args, Parser, Subcommand};

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

    /// Run as a signer role and require the 'id' argument
    Signer {
        /// The ID of the signer
        id: u16,
    },
}
pub fn parse_args() -> Commands {
    CommandLineApp::parse().command
}
