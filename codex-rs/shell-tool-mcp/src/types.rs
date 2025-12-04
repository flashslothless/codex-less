use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOs {
    Linux,
    MacOs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostArch {
    X86_64,
    Aarch64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostPlatform {
    pub os: HostOs,
    pub arch: HostArch,
}

#[derive(Debug, Clone, Copy)]
pub struct LinuxBashVariant {
    pub name: &'static str,
    pub ids: &'static [&'static str],
    pub versions: &'static [&'static str],
}

#[derive(Debug, Clone, Copy)]
pub struct DarwinBashVariant {
    pub name: &'static str,
    pub min_darwin: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsReleaseInfo {
    pub id: String,
    pub id_like: Vec<String>,
    pub version_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BashSelection {
    pub path: PathBuf,
    pub variant: String,
}
