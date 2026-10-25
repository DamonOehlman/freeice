//! Credentialed TURN targets.
//!
//! The shipped lists never carry credentials, and neither does this file: a
//! target names environment variables, and the secret lives in the environment
//! (CI) or in a git-ignored env file (a laptop). A target whose variables are
//! absent is skipped rather than failed, so a checkout without secrets still
//! runs cleanly.

use crate::json::{self, Value};
use crate::probe::Credentials;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub name: String,
    pub urls: Vec<String>,
    pub username_env: String,
    pub credential_env: String,
}

pub fn load(path: &Path) -> Result<Vec<Target>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    parse_targets(&text, &path.display().to_string())
}

fn parse_targets(text: &str, origin: &str) -> Result<Vec<Target>, String> {
    let value = json::parse(text).map_err(|error| format!("{origin}: {error}"))?;
    let Value::Array(items) = value else {
        return Err(format!("{origin}: expected an array of targets"));
    };

    let mut targets = Vec::new();
    for item in &items {
        let urls = match item.get("urls") {
            Some(Value::String(url)) => vec![url.clone()],
            Some(Value::Array(urls)) => urls
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect(),
            _ => return Err(format!("{origin}: a target needs urls")),
        };
        let username_env = item
            .get("username_env")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{origin}: a target needs username_env"))?;
        let credential_env = item
            .get("credential_env")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{origin}: a target needs credential_env"))?;
        let name = item
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_else(|| urls.first().map(String::as_str).unwrap_or("target"))
            .to_string();

        targets.push(Target {
            name,
            urls,
            username_env: username_env.to_string(),
            credential_env: credential_env.to_string(),
        });
    }
    Ok(targets)
}

pub fn load_env_file(path: &Path) -> Result<Vec<(String, String)>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    Ok(parse_env(&text))
}

fn parse_env(text: &str) -> Vec<(String, String)> {
    let mut values = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .or_else(|| {
                value
                    .strip_prefix('\'')
                    .and_then(|rest| rest.strip_suffix('\''))
            })
            .unwrap_or(value);
        values.push((key.trim().to_string(), value.to_string()));
    }
    values
}

/// The environment wins over the file, which is the usual dotenv convention:
/// a value exported for one run should not be shadowed by a stale file.
pub fn resolve(target: &Target, file: &[(String, String)]) -> Option<Credentials> {
    let username = lookup(&target.username_env, file)?;
    let password = lookup(&target.credential_env, file)?;
    Some(Credentials { username, password })
}

fn lookup(name: &str, file: &[(String, String)]) -> Option<String> {
    if let Ok(value) = std::env::var(name) {
        if !value.is_empty() {
            return Some(value);
        }
    }
    file.iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.clone())
        .filter(|value| !value.is_empty())
}

/// The probes speak UDP. `turns:` is TURN over TLS, and `?transport=tcp` asks
/// for TCP, so neither is something this tool can check.
pub fn udp_urls(target: &Target) -> Vec<&str> {
    target
        .urls
        .iter()
        .map(String::as_str)
        .filter(|url| {
            if !url.starts_with("turn:") {
                return false;
            }
            match url.split_once('?') {
                Some((_, query)) => !query.split('&').any(|part| part == "transport=tcp"),
                None => true,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_targets_and_their_variable_names() {
        let targets = parse_targets(
            r#"[
              {"name":"cf","urls":["turn:a.example:3478?transport=udp","turns:a.example:5349?transport=tcp"],"username_env":"U","credential_env":"P"},
              {"urls":"turn:b.example:3478","username_env":"U2","credential_env":"P2"}
            ]"#,
            "test",
        )
        .unwrap();

        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].name, "cf");
        assert_eq!(targets[0].username_env, "U");
        assert_eq!(targets[0].urls.len(), 2);
        assert_eq!(targets[1].name, "turn:b.example:3478");
        assert_eq!(udp_urls(&targets[1]), vec!["turn:b.example:3478"]);
    }

    #[test]
    fn rejects_a_target_without_variable_names() {
        assert!(parse_targets(r#"[{"urls":"turn:a.example:3478"}]"#, "test").is_err());
    }

    #[test]
    fn ignores_comments_and_strips_quotes_in_an_env_file() {
        assert_eq!(
            parse_env("# a comment\nA=1\nB=\"two\"\nC='three'\n\n"),
            vec![
                ("A".to_string(), "1".to_string()),
                ("B".to_string(), "two".to_string()),
                ("C".to_string(), "three".to_string()),
            ]
        );
    }

    #[test]
    fn picks_only_udp_urls() {
        let target = Target {
            name: "x".to_string(),
            urls: vec![
                "turn:a:3478?transport=udp".to_string(),
                "turn:a:3478?transport=tcp".to_string(),
                "turns:a:5349?transport=tcp".to_string(),
                "turn:a:3478".to_string(),
            ],
            username_env: "U".to_string(),
            credential_env: "P".to_string(),
        };
        assert_eq!(
            udp_urls(&target),
            vec!["turn:a:3478?transport=udp", "turn:a:3478"]
        );
    }
}
