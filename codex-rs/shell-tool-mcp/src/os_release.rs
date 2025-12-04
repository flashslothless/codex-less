use crate::types::OsReleaseInfo;
use std::fs::read_to_string;
use std::path::Path;

pub fn parse_os_release(contents: &str) -> OsReleaseInfo {
    let mut info = OsReleaseInfo {
        id: String::new(),
        id_like: Vec::new(),
        version_id: String::new(),
    };

    for line in contents.lines() {
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, '=');
        let key = match parts.next() {
            Some(value) => value.trim().to_lowercase(),
            None => continue,
        };
        let value = match parts.next() {
            Some(value) => value.trim_matches('"').to_string(),
            None => continue,
        };

        match key.as_str() {
            "id" => info.id = value,
            "id_like" => {
                info.id_like = value
                    .split_whitespace()
                    .map(str::to_lowercase)
                    .filter(|item| !item.is_empty())
                    .collect();
            }
            "version_id" => info.version_id = value,
            _ => {}
        }
    }

    info
}

pub fn read_os_release(path: &Path) -> OsReleaseInfo {
    match read_to_string(path) {
        Ok(contents) => parse_os_release(&contents),
        Err(_) => OsReleaseInfo {
            id: String::new(),
            id_like: Vec::new(),
            version_id: String::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::parse_os_release;
    use crate::types::OsReleaseInfo;
    use pretty_assertions::assert_eq;

    #[test]
    fn parses_os_release_fields() {
        let contents = "ID=ubuntu\nVERSION_ID=22.04\nID_LIKE=debian";
        let parsed = parse_os_release(contents);

        assert_eq!(
            parsed,
            OsReleaseInfo {
                id: "ubuntu".to_string(),
                id_like: vec!["debian".to_string()],
                version_id: "22.04".to_string(),
            },
        );
    }

    #[test]
    fn handles_missing_values() {
        let parsed = parse_os_release("NAME=Example OS");

        assert_eq!(parsed.id, "");
        assert_eq!(parsed.id_like, Vec::<String>::new());
        assert_eq!(parsed.version_id, "");
    }
}
