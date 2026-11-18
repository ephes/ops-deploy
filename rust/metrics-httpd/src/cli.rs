//! The command line of PLAN.md 4.9 (clap). `main` dispatches on it; the
//! fixture replay parses a variant's argv with the same definitions.

use clap::{Parser, Subcommand};

use crate::modes::apt_state::AptStateArgs;
use crate::modes::json_file::JsonFileArgs;
use crate::modes::logyard_health::LogyardHealthArgs;
use crate::modes::script::ScriptArgs;
use crate::modes::static_site::StaticArgs;

/// Small authenticated HTTP endpoints for homelab metrics.
#[derive(Parser, Debug)]
#[command(
    name = "metrics-httpd",
    disable_version_flag = true,
    args_conflicts_with_subcommands = true
)]
pub struct Cli {
    /// Print "metrics-httpd <version> (<commit>)" and exit.
    #[arg(long)]
    pub version: bool,
    #[command(subcommand)]
    pub mode: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Serve a JSON file written by a timer, with a `meta` block (PLAN.md 4.2).
    JsonFile(JsonFileArgs),
    /// Run a metrics script per request and serve its stdout (PLAN.md 4.4).
    Script(ScriptArgs),
    /// Serve the os-apt-maintenance state with its summary (PLAN.md 4.5).
    AptState(AptStateArgs),
    /// Logyard health from the LOGYARD_* environment (PLAN.md 4.6).
    LogyardHealth(LogyardHealthArgs),
    /// Serve a static site read-only (PLAN.md 4.7).
    Static(StaticArgs),
}
