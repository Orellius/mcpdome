use clap::{Parser, Subcommand};
use dome_gate::{Gate, GateConfig};
use dome_ledger::{Ledger, StderrSink};
use dome_sentinel::AnonymousAuthenticator;
use dome_throttle::{BudgetTrackerConfig, RateLimiterConfig};
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

        /// Enable policy enforcement
        #[arg(long, default_value_t = false)]
        enforce_policy: bool,

        /// Enable injection detection (ward)
        #[arg(long, default_value_t = false)]
        enable_ward: bool,

        /// Enable schema pinning
        #[arg(long, default_value_t = false)]
        enable_schema_pin: bool,

        /// Enable rate limiting
        #[arg(long, default_value_t = false)]
        enable_rate_limit: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Proxy {
            upstream,
            log_level,
            enforce_policy,
            enable_ward,
            enable_schema_pin,
            enable_rate_limit,
        } => {
            tracing_subscriber::fmt()
                .with_env_filter(
                    EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| EnvFilter::new(&log_level)),
                )
                .with_target(false)
                .with_writer(std::io::stderr)
                .init();

            info!(upstream = upstream.as_str(), "MCPDome starting");

            let parts: Vec<&str> = upstream.split_whitespace().collect();
            if parts.is_empty() {
                anyhow::bail!("--upstream cannot be empty");
            }

            let command = parts[0];
            let args = &parts[1..];

            let config = GateConfig {
                enforce_policy,
                enable_ward,
                enable_schema_pin,
                enable_rate_limit,
                enable_budget: false,
                allow_anonymous: true,
            };

            let ledger = Ledger::new(vec![Box::new(StderrSink::new())]);

            let gate = Gate::new(
                config,
                vec![Box::new(AnonymousAuthenticator)],
                None,
                RateLimiterConfig::default(),
                BudgetTrackerConfig::default(),
                ledger,
            );

            gate.run_stdio(command, args).await?;
        }
    }

    Ok(())
}
