use crate::types::DarwinBashVariant;
use crate::types::LinuxBashVariant;

pub const LINUX_BASH_VARIANTS: &[LinuxBashVariant] = &[
    LinuxBashVariant {
        name: "ubuntu-24.04",
        ids: &["ubuntu"],
        versions: &["24.04"],
    },
    LinuxBashVariant {
        name: "ubuntu-22.04",
        ids: &["ubuntu"],
        versions: &["22.04"],
    },
    LinuxBashVariant {
        name: "ubuntu-20.04",
        ids: &["ubuntu"],
        versions: &["20.04"],
    },
    LinuxBashVariant {
        name: "debian-12",
        ids: &["debian"],
        versions: &["12"],
    },
    LinuxBashVariant {
        name: "debian-11",
        ids: &["debian"],
        versions: &["11"],
    },
    LinuxBashVariant {
        name: "centos-9",
        ids: &["centos", "rhel", "rocky", "almalinux"],
        versions: &["9"],
    },
];

pub const DARWIN_BASH_VARIANTS: &[DarwinBashVariant] = &[
    DarwinBashVariant {
        name: "macos-15",
        min_darwin: 24,
    },
    DarwinBashVariant {
        name: "macos-14",
        min_darwin: 23,
    },
    DarwinBashVariant {
        name: "macos-13",
        min_darwin: 22,
    },
];
