pub mod commands;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "cra-auditflow",
    version,
    about = "CRA compliance pipeline: Ingest SBOM, check vulnerabilities, classify risk, generate report"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Path to the vulnerability database (default: ~/.local/share/cra-auditflow/vuln.db)
    #[arg(long, global = true)]
    pub db_path: Option<PathBuf>,

    /// Increase logging verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run a full CRA compliance audit on an SBOM file
    Audit {
        /// Path to the SBOM file (CycloneDX or SPDX JSON)
        sbom_file: PathBuf,

        /// Product name for the audit report
        #[arg(short = 'n', long)]
        product_name: Option<String>,

        /// Product description (used for CRA risk classification)
        #[arg(short = 'd', long)]
        description: Option<String>,

        /// Report format: markdown or plaintext
        #[arg(short = 'f', long, default_value = "markdown")]
        format: String,

        /// Output file path (default: stdout)
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,

        /// Path to custom CRA classification rules TOML
        #[arg(long)]
        rules: Option<PathBuf>,
    },

    /// SBOM operations
    Sbom {
        #[command(subcommand)]
        command: SbomCommands,
    },

    /// Vulnerability database operations
    Vuln {
        #[command(subcommand)]
        command: VulnCommands,
    },
}

#[derive(Subcommand)]
pub enum SbomCommands {
    /// Validate an SBOM file and print a summary
    Validate {
        /// Path to the SBOM file
        sbom_file: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum VulnCommands {
    /// Download/update vulnerability data from OSV
    Update {
        /// Comma-separated list of ecosystems to download
        #[arg(long, value_delimiter = ',')]
        ecosystems: Option<Vec<String>>,
    },

    /// Show vulnerability database status
    Status,
}
