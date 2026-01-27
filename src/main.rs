use clap::Parser;
use tracing_subscriber::EnvFilter;

use cra_auditflow::cli::commands;
use cra_auditflow::cli::{Cli, Commands, SbomCommands, VulnCommands};

fn main() {
    let cli = Cli::parse();

    // Set up logging based on verbosity level
    let filter = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter)),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    let result = match cli.command {
        Commands::Audit {
            sbom_file,
            product_name,
            description,
            format,
            output,
            rules,
        } => commands::run_audit(
            &sbom_file,
            product_name.as_deref(),
            description.as_deref(),
            &format,
            output.as_deref(),
            rules.as_deref(),
            cli.db_path.as_deref(),
        ),
        Commands::Sbom { command } => match command {
            SbomCommands::Validate { sbom_file } => commands::run_sbom_validate(&sbom_file),
        },
        Commands::Vuln { command } => match command {
            VulnCommands::Update { ecosystems } => {
                commands::run_vuln_update(ecosystems.as_deref(), cli.db_path.as_deref())
            }
            VulnCommands::Status => commands::run_vuln_status(cli.db_path.as_deref()),
        },
    };

    if let Err(e) = result {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}
