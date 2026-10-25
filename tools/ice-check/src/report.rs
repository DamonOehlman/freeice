//! Turning probes into a table, a diversity summary and JSON.

use crate::cli::{Families, Options};
use crate::dns::{self, Lookup, Rcode};
use crate::json;
use crate::list::Entry;
use crate::probe::{self, Outcome};
use crate::stun::Kind;
use crate::targets::{self, Target};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Probing every address a large operator publishes would cost more time than
/// the answer is worth; four per entry is enough to separate "alive" from "one
/// address filtered".
const MAX_ADDRESSES: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub fn label(self) -> &'static str {
        match self {
            Family::V4 => "IPv4",
            Family::V6 => "IPv6",
        }
    }
}

#[derive(Clone, Debug)]
pub struct AddressResult {
    pub family: Family,
    pub address: IpAddr,
    pub outcome: Outcome,
}

#[derive(Clone, Debug)]
pub struct EntryResult {
    pub entry: String,
    pub kind: Kind,
    pub host: String,
    pub port: u16,
    pub credentialed: bool,
    pub lookup: Lookup,
    pub addresses: Vec<AddressResult>,
    pub hidden: usize,
}

impl EntryResult {
    pub fn answered(&self) -> bool {
        self.addresses
            .iter()
            .any(|address| address.outcome.answered())
    }
}

pub fn check_all(
    entries: &[Entry],
    servers: &[SocketAddr],
    timeout: Duration,
    attempts: u32,
    families: Families,
) -> Vec<EntryResult> {
    std::thread::scope(|scope| {
        let handles: Vec<_> = entries
            .iter()
            .map(|entry| {
                scope.spawn(move || check_entry(entry, servers, timeout, attempts, families))
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("probe thread panicked"))
            .collect()
    })
}

fn check_entry(
    entry: &Entry,
    servers: &[SocketAddr],
    timeout: Duration,
    attempts: u32,
    families: Families,
) -> EntryResult {
    let lookup = dns::lookup(&entry.host, servers, timeout);

    let mut candidates: Vec<(Family, IpAddr)> = Vec::new();
    if families.v4 {
        candidates.extend(
            lookup
                .a
                .iter()
                .map(|address| (Family::V4, IpAddr::V4(*address))),
        );
    }
    if families.v6 {
        candidates.extend(
            lookup
                .aaaa
                .iter()
                .map(|address| (Family::V6, IpAddr::V6(*address))),
        );
    }
    candidates.dedup_by_key(|(_, address)| *address);

    let hidden = candidates.len().saturating_sub(MAX_ADDRESSES);
    candidates.truncate(MAX_ADDRESSES);

    let mut addresses = Vec::new();
    for (family, address) in candidates {
        let outcome = match bogon_label(address) {
            Some(label) => Outcome::Bogon {
                detail: format!("in {label}"),
            },
            None => probe::probe(
                SocketAddr::new(address, entry.port),
                entry.kind,
                timeout,
                attempts,
            ),
        };
        addresses.push(AddressResult {
            family,
            address,
            outcome,
        });
    }

    EntryResult {
        entry: entry.raw.clone(),
        kind: entry.kind,
        host: entry.host.clone(),
        port: entry.port,
        credentialed: entry.credentialed,
        lookup,
        addresses,
        hidden,
    }
}

#[derive(Clone, Debug)]
pub struct TargetResult {
    pub name: String,
    pub url: Option<String>,
    pub skipped: Option<String>,
    pub outcome: Option<Outcome>,
}

impl TargetResult {
    /// A skipped target is not a failure: a checkout without secrets should
    /// still run cleanly. An attempted target must relay.
    pub fn passed(&self) -> bool {
        if self.skipped.is_some() {
            return true;
        }
        self.outcome.as_ref().map(Outcome::relayed).unwrap_or(false)
    }
}

pub fn check_targets(
    targets: &[Target],
    env_file: &[(String, String)],
    servers: &[SocketAddr],
    timeout: Duration,
    attempts: u32,
    families: Families,
) -> Vec<TargetResult> {
    let mut results = Vec::new();

    for target in targets {
        let urls = targets::udp_urls(target);
        let Some(url) = urls.first().copied() else {
            results.push(TargetResult {
                name: target.name.clone(),
                url: None,
                skipped: Some("no UDP url".to_string()),
                outcome: None,
            });
            continue;
        };

        let Some(credentials) = targets::resolve(target, env_file) else {
            results.push(TargetResult {
                name: target.name.clone(),
                url: Some(url.to_string()),
                skipped: Some(format!(
                    "{} and {} are not set",
                    target.username_env, target.credential_env
                )),
                outcome: None,
            });
            continue;
        };

        let outcome = probe_target(url, &credentials, servers, timeout, attempts, families);
        results.push(TargetResult {
            name: target.name.clone(),
            url: Some(url.to_string()),
            skipped: None,
            outcome: Some(outcome),
        });
    }

    results
}

fn probe_target(
    url: &str,
    credentials: &probe::Credentials,
    servers: &[SocketAddr],
    timeout: Duration,
    attempts: u32,
    families: Families,
) -> Outcome {
    let entry = match crate::list::parse_entry(Kind::Allocate, url, true) {
        Ok(entry) => entry,
        Err(error) => return Outcome::SendFailed { detail: error },
    };

    let lookup = dns::lookup(&entry.host, servers, timeout);
    let mut addresses: Vec<IpAddr> = Vec::new();
    if families.v4 {
        addresses.extend(lookup.a.iter().map(|address| IpAddr::V4(*address)));
    }
    if families.v6 {
        addresses.extend(lookup.aaaa.iter().map(|address| IpAddr::V6(*address)));
    }
    if addresses.is_empty() {
        return Outcome::Unreachable {
            detail: format!("{} did not resolve", entry.host),
        };
    }

    let mut best: Option<Outcome> = None;
    for address in addresses.into_iter().take(2) {
        let outcome = probe::probe_turn(
            SocketAddr::new(address, entry.port),
            timeout,
            attempts,
            Some(credentials),
        );
        if outcome.relayed() {
            return outcome;
        }
        if best.is_none() {
            best = Some(outcome);
        }
    }
    best.unwrap_or(Outcome::Timeout { attempts })
}

fn target_table(results: &[TargetResult], options: &Options) {
    if results.is_empty() {
        return;
    }

    println!("TURN TARGETS (credentials from the environment or --env-file)");
    println!();
    println!("{:<14} {:<44} {:<12} detail", "name", "url", "result");
    println!("{}", "-".repeat(104));

    for result in results {
        let (status, detail) = match (&result.outcome, &result.skipped) {
            (_, Some(reason)) => ("skipped".to_string(), reason.clone()),
            (Some(outcome), None) => {
                let mut status = outcome.label().to_string();
                if let Some(rtt) = outcome.rtt_ms() {
                    status.push_str(&format!(" ({rtt:.0} ms)"));
                }
                (status, outcome.detail())
            }
            (None, None) => ("not run".to_string(), String::new()),
        };
        println!(
            "{:<14} {:<44} {:<12} {}",
            result.name,
            result.url.as_deref().unwrap_or("-"),
            status,
            truncate(&detail, 60)
        );
    }
    println!();

    if !options.quiet {
        let failed = results.iter().filter(|result| !result.passed()).count();
        if failed == 0 {
            println!("targets: {} checked, all relayed or skipped", results.len());
        } else {
            println!("targets: {failed} of {} failed", results.len());
        }
        println!();
    }
}

pub fn print(
    results: &[EntryResult],
    candidates: &[EntryResult],
    targets: &[TargetResult],
    options: &Options,
) {
    if !options.quiet {
        println!("checking against {}", options.root.display());
        if let Some(base) = &options.base {
            println!("only entries added since {}", base.display());
        }
        println!();
    }

    table("SHIPPED (stun.json + turn.json)", results, options.families);
    if !options.quiet {
        summary(results, options.families);
    }

    if !candidates.is_empty() {
        table(
            "CANDIDATES (not endorsed -- check the operator's terms)",
            candidates,
            options.families,
        );
        if !options.quiet {
            summary(candidates, options.families);
        }
    }

    target_table(targets, options);
}

fn table(title: &str, results: &[EntryResult], families: Families) {
    println!("{title}");
    println!();
    println!(
        "{:<34} {:<6} {:<26} {:<20} detail",
        "entry", "family", "address", "result"
    );
    println!("{}", "-".repeat(104));

    for result in results {
        if result.addresses.is_empty() {
            let (status, detail) = empty_status(result, families);
            println!(
                "{:<34} {:<6} {:<26} {:<20} {}",
                result.entry, "-", "-", status, detail
            );
            continue;
        }

        for (index, address) in result.addresses.iter().enumerate() {
            let entry = if index == 0 {
                result.entry.as_str()
            } else {
                ""
            };
            let mut status = address.outcome.label().to_string();
            if let Some(rtt) = address.outcome.rtt_ms() {
                status.push_str(&format!(" ({rtt:.0} ms)"));
            }
            let mut detail = address.outcome.detail();
            if index == 0 && result.hidden > 0 {
                detail.push_str(&format!("  (+{} more)", result.hidden));
            }
            println!(
                "{:<34} {:<6} {:<26} {:<20} {}",
                entry,
                address.family.label(),
                address.address,
                status,
                truncate(&detail, 72)
            );
        }
    }
    println!();
}

fn truncate(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_string();
    }
    let mut out: String = text.chars().take(limit.saturating_sub(3)).collect();
    out.push_str("...");
    out
}

fn empty_status(result: &EntryResult, _families: Families) -> (&'static str, String) {
    if !result.lookup.addresses().is_empty() {
        return (
            "filtered",
            "--family excluded the resolved addresses".to_string(),
        );
    }
    if let Some(rcode) = result.lookup.rcode {
        if rcode != Rcode::NoError {
            let mut detail = rcode.detail();
            if let Some(note) = &result.lookup.note {
                detail.push_str(&format!(" ({note})"));
            }
            return ("dns", detail);
        }
    }
    if !result.lookup.cnames.is_empty() {
        return (
            "dns",
            format!("no address (chain: {})", result.lookup.cnames.join(" -> ")),
        );
    }
    (
        "dns",
        result
            .lookup
            .note
            .clone()
            .unwrap_or_else(|| "no records".to_string()),
    )
}

struct Diversity {
    entries: usize,
    answered: usize,
    failed: Vec<(String, String)>,
    v4: usize,
    v6: usize,
    blocks: usize,
    no_aaaa: Vec<String>,
    shared: Vec<Vec<String>>,
    unreachable_v6: usize,
}

fn summarise(results: &[EntryResult], families: Families) -> Diversity {
    let mut v4_addresses = Vec::new();
    let mut v6_addresses = Vec::new();
    let mut blocks = Vec::new();
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut failed = Vec::new();
    let mut no_aaaa = Vec::new();
    let mut answered = 0;
    let mut unreachable_v6 = 0;

    for result in results {
        for raw in &result.lookup.a {
            if bogon_label(IpAddr::V4(*raw)).is_some() {
                continue;
            }
            let address = IpAddr::V4(*raw);
            if !v4_addresses.contains(&address) {
                v4_addresses.push(address);
            }
            let block = IpAddr::V4(Ipv4Addr::from(u32::from(*raw) & 0xFFFF_FF00));
            if !blocks.contains(&block) {
                blocks.push(block);
            }
        }
        for raw in &result.lookup.aaaa {
            if bogon_label(IpAddr::V6(*raw)).is_some() {
                continue;
            }
            let address = IpAddr::V6(*raw);
            if !v6_addresses.contains(&address) {
                v6_addresses.push(address);
            }
            let block = IpAddr::V6(Ipv6Addr::from(u128::from(*raw) & (u128::MAX << 80)));
            if !blocks.contains(&block) {
                blocks.push(block);
            }
        }

        for address in &result.addresses {
            if address.family == Family::V6
                && matches!(address.outcome, Outcome::Unreachable { .. })
            {
                unreachable_v6 += 1;
            }
        }

        let mut resolved: Vec<String> = result
            .lookup
            .addresses()
            .iter()
            .map(ToString::to_string)
            .collect();
        resolved.sort();
        if !resolved.is_empty() {
            groups
                .entry(resolved.join(", "))
                .or_default()
                .push(result.entry.clone());
        }

        if result.answered() {
            answered += 1;
        } else {
            let (_, detail) = empty_status(result, families);
            let reason = if result.addresses.is_empty() {
                detail
            } else {
                // A local "no route" is not a verdict on the server, so it is
                // reported only when it is the whole story.
                let reached: Vec<_> = result
                    .addresses
                    .iter()
                    .filter(|address| !matches!(address.outcome, Outcome::Unreachable { .. }))
                    .collect();
                if reached.is_empty() {
                    "no route from this host (not a server verdict)".to_string()
                } else {
                    reached
                        .iter()
                        .map(|address| {
                            format!(
                                "{} {}: {}",
                                address.family.label(),
                                address.address,
                                address.outcome.detail()
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("; ")
                }
            };
            failed.push((result.entry.clone(), reason));
        }

        if !result.lookup.is_empty() && result.lookup.aaaa.is_empty() {
            no_aaaa.push(result.entry.clone());
        }
    }

    Diversity {
        entries: results.len(),
        answered,
        failed,
        v4: v4_addresses.len(),
        v6: v6_addresses.len(),
        blocks: blocks.len(),
        no_aaaa,
        shared: groups
            .into_values()
            .filter(|group| group.len() > 1)
            .collect(),
        unreachable_v6,
    }
}

fn summary(results: &[EntryResult], families: Families) {
    let diversity = summarise(results, families);

    println!(
        "entries {}  answered {}  failed {}",
        diversity.entries,
        diversity.answered,
        diversity.failed.len()
    );
    for (entry, reason) in &diversity.failed {
        println!("  FAILED  {entry}: {reason}");
    }

    println!(
        "diversity {} entries -> {} published addresses -> {} netblocks  (IPv4 {}, IPv6 {})",
        diversity.entries,
        diversity.v4 + diversity.v6,
        diversity.blocks,
        diversity.v4,
        diversity.v6
    );
    if !diversity.no_aaaa.is_empty() {
        println!("  no AAAA: {}", diversity.no_aaaa.join(", "));
    }
    if diversity.unreachable_v6 > 0 {
        println!(
            "  IPv6: {} addresses had no route from this host (not a server verdict)",
            diversity.unreachable_v6
        );
    }
    for group in &diversity.shared {
        println!(
            "  same addresses: {} ({} entries)",
            group.join(", "),
            group.len()
        );
    }
    println!();
}

pub fn to_json(
    results: &[EntryResult],
    candidates: &[EntryResult],
    targets: &[TargetResult],
    base: Option<&std::path::Path>,
) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str(&format!(
        "  \"generated\": {},\n",
        json::quote(&generated_at())
    ));
    match base {
        Some(path) => out.push_str(&format!(
            "  \"base\": {},\n",
            json::quote(&path.display().to_string())
        )),
        None => out.push_str("  \"base\": null,\n"),
    }
    out.push_str("  \"entries\": ");
    write_entries(&mut out, results);
    out.push_str(",\n  \"candidates\": ");
    write_entries(&mut out, candidates);
    out.push_str(",\n  \"targets\": ");
    write_targets(&mut out, targets);
    out.push_str("\n}\n");
    out
}

fn write_entries(out: &mut String, results: &[EntryResult]) {
    if results.is_empty() {
        out.push_str("[]");
        return;
    }
    out.push_str("[\n");
    for (index, result) in results.iter().enumerate() {
        write_entry(out, result);
        if index + 1 != results.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("  ]");
}

fn write_entry(out: &mut String, result: &EntryResult) {
    out.push_str("    {\n");
    field(out, 6, "entry", &json::quote(&result.entry), true);
    field(out, 6, "kind", &json::quote(result.kind.label()), true);
    field(out, 6, "host", &json::quote(&result.host), true);
    field(out, 6, "port", &result.port.to_string(), true);
    field(
        out,
        6,
        "credentialed",
        if result.credentialed { "true" } else { "false" },
        true,
    );

    out.push_str("      \"dns\": {\n");
    field(
        out,
        8,
        "source",
        &json::quote(result.lookup.source.label()),
        true,
    );
    match result.lookup.rcode {
        Some(rcode) => field(out, 8, "rcode", &json::quote(rcode.label()), true),
        None => field(out, 8, "rcode", "null", true),
    }
    field(out, 8, "a", &string_array(&result.lookup.a), true);
    field(out, 8, "aaaa", &string_array(&result.lookup.aaaa), true);
    field(
        out,
        8,
        "cnames",
        &string_array(&result.lookup.cnames),
        result.lookup.note.is_some(),
    );
    if let Some(note) = &result.lookup.note {
        field(out, 8, "note", &json::quote(note), false);
    }
    out.push_str("      },\n");

    out.push_str("      \"addresses\": [");
    if result.addresses.is_empty() {
        out.push_str("],\n");
    } else {
        out.push('\n');
        for (index, address) in result.addresses.iter().enumerate() {
            write_address(out, address);
            if index + 1 != result.addresses.len() {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("      ],\n");
    }

    field(
        out,
        6,
        "answered",
        if result.answered() { "true" } else { "false" },
        false,
    );
    out.push_str("    }");
}

fn write_address(out: &mut String, address: &AddressResult) {
    let mut fields = vec![
        ("family".to_string(), json::quote(address.family.label())),
        (
            "address".to_string(),
            json::quote(&address.address.to_string()),
        ),
        ("outcome".to_string(), json::quote(address.outcome.label())),
    ];
    fields.extend(outcome_fields(&address.outcome));
    write_object(out, 8, &fields);
}

fn write_targets(out: &mut String, targets: &[TargetResult]) {
    if targets.is_empty() {
        out.push_str("[]");
        return;
    }
    out.push_str("[\n");
    for (index, target) in targets.iter().enumerate() {
        write_target(out, target);
        if index + 1 != targets.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("  ]");
}

fn write_target(out: &mut String, target: &TargetResult) {
    let mut fields = vec![
        ("name".to_string(), json::quote(&target.name)),
        (
            "url".to_string(),
            target
                .url
                .as_ref()
                .map(|url| json::quote(url))
                .unwrap_or_else(|| "null".to_string()),
        ),
        (
            "skipped".to_string(),
            target
                .skipped
                .as_ref()
                .map(|reason| json::quote(reason))
                .unwrap_or_else(|| "null".to_string()),
        ),
    ];
    if let Some(outcome) = &target.outcome {
        fields.push(("outcome".to_string(), json::quote(outcome.label())));
        fields.extend(outcome_fields(outcome));
    }
    write_object(out, 4, &fields);
}

fn outcome_fields(outcome: &Outcome) -> Vec<(String, String)> {
    let optional = |value: &Option<String>| {
        value
            .as_ref()
            .map(|text| json::quote(text))
            .unwrap_or_else(|| "null".to_string())
    };

    let mut fields = Vec::new();
    match outcome {
        Outcome::Ok {
            mapped, software, ..
        } => {
            fields.push(("mapped".to_string(), optional(mapped)));
            fields.push(("software".to_string(), optional(software)));
        }
        Outcome::Relayed {
            relayed, software, ..
        } => {
            fields.push(("relayed".to_string(), optional(relayed)));
            fields.push(("software".to_string(), optional(software)));
        }
        Outcome::Error { code, reason, .. } | Outcome::Rejected { code, reason, .. } => {
            fields.push(("error_code".to_string(), code.to_string()));
            fields.push(("reason".to_string(), json::quote(reason)));
        }
        Outcome::Timeout { attempts } => {
            fields.push(("attempts".to_string(), attempts.to_string()));
        }
        Outcome::Garbage { bytes, detail } => {
            fields.push(("bytes".to_string(), bytes.to_string()));
            fields.push(("detail".to_string(), json::quote(detail)));
        }
        Outcome::Unreachable { detail }
        | Outcome::SendFailed { detail }
        | Outcome::Bogon { detail } => {
            fields.push(("detail".to_string(), json::quote(detail)));
        }
        Outcome::Refused => {}
    }

    if let Some(rtt) = outcome.rtt_ms() {
        fields.push(("rtt_ms".to_string(), format!("{rtt:.1}")));
    }
    fields
}

fn write_object(out: &mut String, indent: usize, fields: &[(String, String)]) {
    out.push_str(&" ".repeat(indent));
    out.push_str("{\n");
    for (index, (key, value)) in fields.iter().enumerate() {
        out.push_str(&" ".repeat(indent + 2));
        out.push_str(&json::quote(key));
        out.push_str(": ");
        out.push_str(value);
        if index + 1 != fields.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str(&" ".repeat(indent));
    out.push('}');
}

fn field(out: &mut String, indent: usize, key: &str, value: &str, comma: bool) {
    out.push_str(&" ".repeat(indent));
    out.push_str(&json::quote(key));
    out.push_str(": ");
    out.push_str(value);
    if comma {
        out.push(',');
    }
    out.push('\n');
}

fn string_array<T: ToString>(items: &[T]) -> String {
    let quoted: Vec<String> = items
        .iter()
        .map(|item| json::quote(&item.to_string()))
        .collect();
    format!("[{}]", quoted.join(", "))
}

pub fn suggest(results: &[EntryResult]) -> String {
    let entries: Vec<String> = results
        .iter()
        .filter(|result| result.answered())
        .map(|result| result.entry.clone())
        .collect();
    let mut out = String::from("[\n");
    for (index, entry) in entries.iter().enumerate() {
        out.push_str("  ");
        out.push_str(&json::quote(entry));
        if index + 1 != entries.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("]\n");
    out
}

fn generated_at() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    rfc3339(seconds)
}

fn rfc3339(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let remainder = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        remainder / 3600,
        (remainder % 3600) / 60,
        remainder % 60
    )
}

/// Howard Hinnant's days-to-civil algorithm, so the report carries a date
/// without a date crate.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = (shifted - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_position = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_position + 2) / 5 + 1) as u32;
    let month = if month_position < 10 {
        month_position + 3
    } else {
        month_position - 9
    } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

fn bogon_label(address: IpAddr) -> Option<&'static str> {
    match address {
        IpAddr::V4(address) => {
            let value = u32::from(address);
            const RANGES: &[(u32, u8, &str)] = &[
                (0x0000_0000, 8, "the unspecified range"),
                (0x0A00_0000, 8, "a private range"),
                (0x6440_0000, 10, "the carrier-grade NAT range"),
                (0x7F00_0000, 8, "the loopback range"),
                (0xA9FE_0000, 16, "the link-local range"),
                (0xAC10_0000, 12, "a private range"),
                (0xC000_0000, 24, "the IETF protocol range"),
                (0xC000_0200, 24, "the documentation range"),
                (0xC0A8_0000, 16, "a private range"),
                (0xC612_0000, 15, "the benchmarking range"),
                (0xC633_6400, 24, "the documentation range"),
                (0xCB00_7100, 24, "the documentation range"),
                (0xE000_0000, 4, "the multicast range"),
                (0xF000_0000, 4, "the reserved range"),
            ];
            RANGES
                .iter()
                .find(|(network, prefix, _)| {
                    let mask = u32::MAX << (32 - prefix);
                    value & mask == network & mask
                })
                .map(|(_, _, label)| *label)
        }
        IpAddr::V6(address) => {
            let segments = address.segments();
            if address.is_unspecified() {
                Some("the unspecified address")
            } else if address.is_loopback() {
                Some("the loopback address")
            } else if segments[0] & 0xFE00 == 0xFC00 {
                Some("a unique-local range")
            } else if segments[0] & 0xFFC0 == 0xFE80 {
                Some("the link-local range")
            } else if segments[0] == 0x2001 && segments[1] == 0x0DB8 {
                Some("the documentation range")
            } else if segments[0] == 0x0100
                && segments[1] == 0
                && segments[2] == 0
                && segments[3] == 0
            {
                Some("the discard-only range")
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_a_timestamp_without_a_date_crate() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(rfc3339(1_767_225_600), "2026-01-01T00:00:00Z");
    }

    #[test]
    fn spots_documentation_and_private_addresses() {
        assert!(bogon_label("192.0.2.42".parse().unwrap()).is_some());
        assert!(bogon_label("10.1.2.3".parse().unwrap()).is_some());
        assert!(bogon_label("100.100.1.1".parse().unwrap()).is_some());
        assert!(bogon_label("2001:db8::1".parse().unwrap()).is_some());
        assert!(bogon_label("fd7a:115c:a1e0::1".parse().unwrap()).is_some());
        assert!(bogon_label("162.159.207.0".parse().unwrap()).is_none());
        assert!(bogon_label("2606:4700:49::".parse().unwrap()).is_none());
    }

    #[test]
    fn truncates_on_a_character_boundary() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("abcdefghij", 7), "abcd...");
    }
}
