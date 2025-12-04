mod bash_selection;
mod constants;
mod os_release;
mod platform;
mod server;
mod types;

use crate::bash_selection::resolve_bash_path;
use crate::os_release::read_os_release;
use crate::platform::detect_platform;
use crate::platform::resolve_target_triple;
use crate::server::ShellToolServer;
use crate::types::HostOs;
use crate::types::OsReleaseInfo;
use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use clap::Parser;
use std::env;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;

#[derive(Debug, Parser)]
struct Cli {
    /// Root directory for file and command tools.
    #[arg(long, default_value = ".")]
    root: PathBuf,

    /// Override the Bash binary instead of using the vendored selector.
    #[arg(long)]
    bash: Option<PathBuf>,
}

fn find_vendor_root() -> Result<PathBuf> {
    let exe_path = env::current_exe().context("Unable to locate current executable")?;
    if let Some(dir) = exe_path.parent() {
        let candidate = dir.join("vendor");
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidate = manifest_dir.join("vendor");
    if candidate.exists() {
        return Ok(candidate);
    }

    bail!("Unable to locate vendor/ directory relative to the binary or crate root")
}

fn require_exists(path: &Path, description: &str) -> Result<()> {
    if !path.exists() {
        bail!("Required {} missing: {}", description, path.display());
    }
    Ok(())
}

fn read_darwin_release() -> Result<String> {
    let output = Command::new("uname")
        .arg("-r")
        .stdout(Stdio::piped())
        .output()
        .context("Failed to read Darwin release via uname")?;

    if !output.status.success() {
        bail!("uname -r exited with status {}", output.status);
    }

    let release = String::from_utf8(output.stdout).context("uname output was not UTF-8")?;
    Ok(release.trim().to_string())
}

fn select_os_info(os: HostOs) -> Option<OsReleaseInfo> {
    match os {
        HostOs::Linux => Some(read_os_release(Path::new("/etc/os-release"))),
        HostOs::MacOs => None,
    }
}

fn select_darwin_release(os: HostOs) -> Result<Option<String>> {
    match os {
        HostOs::Linux => Ok(None),
        HostOs::MacOs => Ok(Some(read_darwin_release()?)),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let platform = detect_platform()?;
    let target_triple = resolve_target_triple(platform)?;

    let bash_path = if let Some(bash) = cli.bash {
        bash.canonicalize()
            .with_context(|| format!("Failed to canonicalize bash override {}", bash.display()))?
    } else {
        let vendor_root = find_vendor_root()?;
        let target_root = vendor_root.join(target_triple);

        let os_info = select_os_info(platform.os);
        let darwin_release = select_darwin_release(platform.os)?;
        let bash_selection = resolve_bash_path(
            &target_root,
            platform.os,
            darwin_release.as_deref(),
            os_info.as_ref(),
        )?;
        require_exists(&bash_selection.path, "Bash binary")?;
        bash_selection.path
    };

    let server = ShellToolServer::new(cli.root, bash_path)?;
    let running = server.serve_stdio().await?;
    running.waiting().await?;
    tokio::task::yield_now().await;
    Ok(())
}
