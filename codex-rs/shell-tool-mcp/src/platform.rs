use crate::types::HostArch;
use crate::types::HostOs;
use crate::types::HostPlatform;
use anyhow::Result;
use anyhow::bail;
use std::env;

pub fn detect_platform() -> Result<HostPlatform> {
    let os = match env::consts::OS {
        "linux" => HostOs::Linux,
        "macos" => HostOs::MacOs,
        other => bail!("Unsupported platform: {}", other),
    };

    let arch = match env::consts::ARCH {
        "x86_64" => HostArch::X86_64,
        "aarch64" => HostArch::Aarch64,
        other => bail!("Unsupported architecture: {}", other),
    };

    Ok(HostPlatform { os, arch })
}

pub fn resolve_target_triple(platform: HostPlatform) -> Result<&'static str> {
    match (platform.os, platform.arch) {
        (HostOs::Linux, HostArch::X86_64) => Ok("x86_64-unknown-linux-musl"),
        (HostOs::Linux, HostArch::Aarch64) => Ok("aarch64-unknown-linux-musl"),
        (HostOs::MacOs, HostArch::X86_64) => Ok("x86_64-apple-darwin"),
        (HostOs::MacOs, HostArch::Aarch64) => Ok("aarch64-apple-darwin"),
    }
}

#[cfg(test)]
mod tests {
    use super::resolve_target_triple;
    use crate::types::HostArch;
    use crate::types::HostOs;
    use crate::types::HostPlatform;
    use pretty_assertions::assert_eq;

    #[test]
    fn resolves_linux_targets() {
        let platform = HostPlatform {
            os: HostOs::Linux,
            arch: HostArch::X86_64,
        };

        assert_eq!(
            resolve_target_triple(platform).unwrap(),
            "x86_64-unknown-linux-musl"
        );
    }

    #[test]
    fn resolves_macos_targets() {
        let platform = HostPlatform {
            os: HostOs::MacOs,
            arch: HostArch::Aarch64,
        };

        assert_eq!(
            resolve_target_triple(platform).unwrap(),
            "aarch64-apple-darwin"
        );
    }
}
