mod bash_selection;
mod constants;
mod os_release;
mod platform;
mod types;

use crate::bash_selection::resolve_bash_path;
use crate::os_release::read_os_release;
use crate::platform::detect_platform;
use crate::platform::resolve_target_triple;
use crate::types::HostOs;
use crate::types::OsReleaseInfo;
use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use signal_hook::consts::signal::SIGHUP;
use signal_hook::consts::signal::SIGINT;
use signal_hook::consts::signal::SIGTERM;
use signal_hook::iterator::Signals;
use std::env;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::process::{self};

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

fn spawn_server(
    server_path: &Path,
    execve_wrapper: &Path,
    bash_path: &Path,
    passthrough_args: impl Iterator<Item = String>,
) -> Result<i32> {
    let mut command = Command::new(server_path);
    command
        .arg("--execve")
        .arg(execve_wrapper)
        .arg("--bash")
        .arg(bash_path)
        .args(passthrough_args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let mut child = command
        .spawn()
        .with_context(|| format!("Failed to spawn {}", server_path.display()))?;
    let pid = child.id();

    let mut signals =
        Signals::new([SIGINT, SIGTERM, SIGHUP]).context("Failed to set up signal forwarding")?;
    let handle = signals.handle();
    let signal_thread = std::thread::spawn(move || {
        for signal in signals.forever() {
            let _ = unsafe { libc::kill(pid as i32, signal) };
        }
    });

    let status = child
        .wait()
        .context("Failed to wait for codex-exec-mcp-server")?;
    handle.close();
    let _ = signal_thread.join();

    if let Some(signal) = status.signal() {
        unsafe {
            libc::raise(signal);
        }
        Ok(1)
    } else {
        Ok(status.code().unwrap_or(1))
    }
}

fn main() -> Result<()> {
    let platform = detect_platform()?;
    let target_triple = resolve_target_triple(platform)?;

    let vendor_root = find_vendor_root()?;
    let target_root = vendor_root.join(target_triple);
    let execve_wrapper = target_root.join("codex-execve-wrapper");
    let server_path = target_root.join("codex-exec-mcp-server");

    let os_info = select_os_info(platform.os);
    let darwin_release = select_darwin_release(platform.os)?;
    let bash_selection = resolve_bash_path(
        &target_root,
        platform.os,
        darwin_release.as_deref(),
        os_info.as_ref(),
    )?;

    require_exists(&execve_wrapper, "execve wrapper")?;
    require_exists(&server_path, "server binary")?;
    require_exists(&bash_selection.path, "Bash binary")?;

    let exit_code = spawn_server(
        &server_path,
        &execve_wrapper,
        &bash_selection.path,
        env::args().skip(1),
    )?;

    process::exit(exit_code);
}
