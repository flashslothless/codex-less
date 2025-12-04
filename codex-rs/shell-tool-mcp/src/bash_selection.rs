use crate::constants::DARWIN_BASH_VARIANTS;
use crate::constants::LINUX_BASH_VARIANTS;
use crate::types::BashSelection;
use crate::types::HostOs;
use crate::types::OsReleaseInfo;
use anyhow::Context;
use anyhow::Result;
use std::path::Path;
use std::path::PathBuf;

fn supported_detail(variants: &[impl VariantName]) -> String {
    let names: Vec<&str> = variants.iter().map(VariantName::name).collect();
    format!("Supported variants: {}", names.join(", "))
}

fn variant_path(bash_root: &Path, name: &str) -> PathBuf {
    bash_root.join(name).join("bash")
}

trait VariantName {
    fn name(&self) -> &str;
}

impl VariantName for crate::types::LinuxBashVariant {
    fn name(&self) -> &str {
        self.name
    }
}

impl VariantName for crate::types::DarwinBashVariant {
    fn name(&self) -> &str {
        self.name
    }
}

fn select_linux_bash(bash_root: &Path, info: &OsReleaseInfo) -> Result<BashSelection> {
    let version_id = info.version_id.as_str();
    let mut candidates: Vec<(crate::types::LinuxBashVariant, bool)> = Vec::new();

    for variant in LINUX_BASH_VARIANTS {
        let matches_id = variant
            .ids
            .iter()
            .any(|id| info.id == *id || info.id_like.iter().any(|like| like == id));

        if !matches_id {
            continue;
        }

        let matches_version = variant
            .versions
            .iter()
            .any(|prefix| version_id.starts_with(prefix));

        candidates.push((*variant, matches_version));
    }

    let pick_variant = |items: &[(crate::types::LinuxBashVariant, bool)]| {
        items
            .iter()
            .find(|(_, matches_version)| *matches_version)
            .map(|(variant, _)| *variant)
    };

    if let Some(preferred) = pick_variant(candidates.as_slice()) {
        return Ok(BashSelection {
            path: variant_path(bash_root, preferred.name),
            variant: preferred.name.to_string(),
        });
    }

    if let Some((fallback, _)) = candidates.first() {
        return Ok(BashSelection {
            path: variant_path(bash_root, fallback.name),
            variant: fallback.name.to_string(),
        });
    }

    if let Some(default_variant) = LINUX_BASH_VARIANTS.first() {
        return Ok(BashSelection {
            path: variant_path(bash_root, default_variant.name),
            variant: default_variant.name.to_string(),
        });
    }

    let detail = supported_detail(LINUX_BASH_VARIANTS);
    anyhow::bail!(
        "Unable to select a Bash variant for {} {}. {}",
        info.id,
        info.version_id,
        detail
    );
}

fn select_darwin_bash(bash_root: &Path, darwin_release: &str) -> Result<BashSelection> {
    let darwin_major: i32 = darwin_release
        .split('.')
        .next()
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);

    if let Some(variant) = DARWIN_BASH_VARIANTS
        .iter()
        .find(|variant| darwin_major >= variant.min_darwin)
    {
        return Ok(BashSelection {
            path: variant_path(bash_root, variant.name),
            variant: variant.name.to_string(),
        });
    }

    if let Some(default_variant) = DARWIN_BASH_VARIANTS.first() {
        return Ok(BashSelection {
            path: variant_path(bash_root, default_variant.name),
            variant: default_variant.name.to_string(),
        });
    }

    let detail = supported_detail(DARWIN_BASH_VARIANTS);
    anyhow::bail!(
        "Unable to select a macOS Bash build (darwin {}). {}",
        darwin_major,
        detail
    );
}

pub fn resolve_bash_path(
    target_root: &Path,
    os: HostOs,
    darwin_release: Option<&str>,
    os_info: Option<&OsReleaseInfo>,
) -> Result<BashSelection> {
    let bash_root = target_root.join("bash");
    match os {
        HostOs::Linux => {
            let info = os_info.context("Linux OS info is required to select Bash")?;
            select_linux_bash(&bash_root, info)
        }
        HostOs::MacOs => {
            let release = darwin_release.context("Darwin release string is required")?;
            select_darwin_bash(&bash_root, release)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::resolve_bash_path;
    use crate::types::HostOs;
    use crate::types::OsReleaseInfo;
    use pretty_assertions::assert_eq;
    use std::path::Path;

    #[test]
    fn picks_linux_version_specific_variant() {
        let info = OsReleaseInfo {
            id: "ubuntu".to_string(),
            id_like: vec!["debian".to_string()],
            version_id: "22.04.4".to_string(),
        };

        let selection = resolve_bash_path(
            Path::new("/opt/tool/vendor/x86_64"),
            HostOs::Linux,
            None,
            Some(&info),
        )
        .unwrap();

        assert_eq!(selection.variant, "ubuntu-22.04");
        assert!(selection.path.ends_with("ubuntu-22.04/bash"));
    }

    #[test]
    fn falls_back_to_matching_linux_distribution() {
        let info = OsReleaseInfo {
            id: "ubuntu".to_string(),
            id_like: vec!["debian".to_string()],
            version_id: "18.04".to_string(),
        };

        let selection = resolve_bash_path(
            Path::new("/opt/tool/vendor/aarch64"),
            HostOs::Linux,
            None,
            Some(&info),
        )
        .unwrap();

        assert_eq!(selection.variant, "ubuntu-24.04");
    }

    #[test]
    fn selects_closest_darwin_variant() {
        let selection = resolve_bash_path(
            Path::new("/tmp/vendor/aarch64"),
            HostOs::MacOs,
            Some("24.0.0"),
            None,
        )
        .unwrap();

        assert_eq!(selection.variant, "macos-15");
    }
}
