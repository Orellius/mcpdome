use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "mcpdome",
    about = "Iron Dome for AI Agents — MCP security gateway proxy",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the security proxy
    Proxy {
        /// The MCP server command to wrap (e.g. "npx -y @modelcontextprotocol/server-filesystem /tmp")
        #[arg(long)]
        upstream: String,

        /// Log level (off, error, warn, info, debug, trace)
        #[arg(long, default_value = "info")]
        log_level: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Proxy { upstream, log_level } => {
            // Initialize tracing
            tracing_subscriber::fmt()
                .with_env_filter(
                    EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| EnvFilter::new(&log_level)),
                )
                .with_target(false)
                .with_writer(std::io::stderr) // logs go to stderr, MCP traffic goes through stdout
                .init();

            info!(upstream = upstream.as_str(), "MCPDome starting");

            // Parse the upstream command
            let parts: Vec<&str> = upstream.split_whitespace().collect();
            if parts.is_empty() {
                anyhow::bail!("--upstream cannot be empty");
            }

            let command = parts[0];
            let args = &parts[1..];

            dome_gate::Gate::run_stdio(command, args).await?;
        }
    }

    Ok(())
}
