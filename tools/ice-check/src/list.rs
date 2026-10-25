//! Reading `stun.json` and `turn.json` into entries the probe can use.

use crate::json::{self, Value};
use crate::stun::Kind;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct Entry {
    /// The entry as written in the list, so the report quotes the file.
    pub raw: String,
    pub kind: Kind,
    pub host: String,
    pub port: u16,
    /// A TURN object carried a username or credential. Reachability is still
    /// worth checking; whether the credential works is not this tool's job.
    pub credentialed: bool,
}

pub fn load(root: &Path, file: &str, default_kind: Kind) -> Result<Vec<Entry>, String> {
    let path = root.join(file);
    let text = std::fs::read_to_string(&path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let value = json::parse(&text).map_err(|error| format!("{}: {error}", path.display()))?;
    let Value::Array(items) = value else {
        return Err(format!("{}: expected an array of servers", path.display()));
    };

    let mut entries = Vec::new();
    for item in &items {
        match item {
            Value::String(text) => entries.push(parse_entry(default_kind, text, false)?),
            Value::Object(_) => {
                let credentialed =
                    item.get("username").is_some() || item.get("credential").is_some();
                match item.get("urls") {
                    Some(Value::String(text)) => {
                        entries.push(parse_entry(default_kind, text, credentialed)?)
                    }
                    Some(Value::Array(urls)) => {
                        for url in urls {
                            if let Some(text) = url.as_str() {
                                entries.push(parse_entry(default_kind, text, credentialed)?);
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    Ok(entries)
}

/// A list that may not exist yet: `turn.json` was added long after `stun.json`,
/// so a base revision from before it has to count as an empty list rather than
/// a failure.
pub fn load_optional(root: &Path, file: &str, default_kind: Kind) -> Result<Vec<Entry>, String> {
    if !root.join(file).is_file() {
        return Ok(Vec::new());
    }
    load(root, file, default_kind)
}

pub fn parse_entry(default_kind: Kind, raw: &str, credentialed: bool) -> Result<Entry, String> {
    let raw = raw.trim();
    let (kind, rest) = if let Some(rest) = raw.strip_prefix("turn:") {
        (Kind::Allocate, rest)
    } else if let Some(rest) = raw.strip_prefix("stun:") {
        (Kind::Binding, rest)
    } else {
        (default_kind, raw)
    };
    let (host, port) = split_host_port(rest)?;
    Ok(Entry {
        raw: raw.to_string(),
        kind,
        host,
        port,
        credentialed,
    })
}

fn split_host_port(text: &str) -> Result<(String, u16), String> {
    let text = text.split('?').next().unwrap_or(text);

    if let Some(rest) = text.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| format!("unterminated IPv6 literal in {text}"))?;
        let host = &rest[..end];
        let port = match rest[end + 1..].strip_prefix(':') {
            Some(port) => port.parse().map_err(|_| format!("bad port in {text}"))?,
            None => 3478,
        };
        return Ok((host.to_string(), port));
    }

    if text.matches(':').count() == 1 {
        let (host, port) = text.rsplit_once(':').expect("one colon");
        let port = port.parse().map_err(|_| format!("bad port in {text}"))?;
        return Ok((host.to_string(), port));
    }

    // No port, or a bare IPv6 literal.
    Ok((text.to_string(), 3478))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_host_takes_the_default_port() {
        let entry = parse_entry(Kind::Binding, "stun.ekiga.net", false).unwrap();
        assert_eq!(entry.host, "stun.ekiga.net");
        assert_eq!(entry.port, 3478);
        assert_eq!(entry.kind, Kind::Binding);
    }

    #[test]
    fn an_explicit_port_wins() {
        let entry = parse_entry(Kind::Binding, "stun.l.google.com:19302", false).unwrap();
        assert_eq!(entry.port, 19302);
    }

    #[test]
    fn a_turn_url_selects_the_allocate_probe() {
        let entry = parse_entry(
            Kind::Binding,
            "turn:relay.example.org:3478?transport=udp",
            true,
        )
        .unwrap();
        assert_eq!(entry.kind, Kind::Allocate);
        assert_eq!(entry.host, "relay.example.org");
        assert_eq!(entry.port, 3478);
        assert!(entry.credentialed);
    }

    #[test]
    fn a_bracketed_ipv6_literal_keeps_its_port() {
        let entry = parse_entry(Kind::Binding, "[2001:db8::1]:3478", false).unwrap();
        assert_eq!(entry.host, "2001:db8::1");
        assert_eq!(entry.port, 3478);
    }

    #[test]
    fn a_bad_port_is_an_error_not_a_default() {
        assert!(parse_entry(Kind::Binding, "stun.example.org:notaport", false).is_err());
    }
}
