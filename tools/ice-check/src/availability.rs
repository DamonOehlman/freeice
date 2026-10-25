//! A rolling record of whether each proposed server answered.
//!
//! Promotion should be earned over time, not decided by one good afternoon. The
//! ledger keeps per-day counts per entry, one run per record, and answers two
//! questions: has this server been answering lately, and for how much of the
//! window. It is committed to the repository so the history is reviewable and
//! the decision is not a secret held by a CI log.

use crate::json::{self, Value};
use crate::stun::Kind;
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

const VERSION: u32 = 1;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Observation {
    pub checked: u32,
    pub answered: u32,
    pub rtt_ms_total: f64,
    pub last_ok: Option<String>,
    pub last_address: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct Ledger {
    pub days: BTreeMap<String, BTreeMap<String, Observation>>,
}

pub struct Sample {
    pub entry: String,
    pub answered: bool,
    pub rtt_ms: Option<f64>,
    pub address: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Eligible {
    pub entry: String,
    pub checked: u32,
    pub answered: u32,
    pub ratio: f64,
    pub rtt_ms: f64,
    pub address: Option<String>,
}

pub fn load(path: &Path) -> Result<Ledger, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ledger::parse(&text),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Ledger::default()),
        Err(error) => Err(format!("cannot read {}: {error}", path.display())),
    }
}

impl Ledger {
    pub fn record(&mut self, day: &str, now: &str, samples: &[Sample]) {
        let entries = self.days.entry(day.to_string()).or_default();
        for sample in samples {
            let observation = entries.entry(sample.entry.clone()).or_default();
            observation.checked += 1;
            if sample.answered {
                observation.answered += 1;
                observation.last_ok = Some(now.to_string());
                if let Some(rtt) = sample.rtt_ms {
                    observation.rtt_ms_total += rtt;
                }
                if let Some(address) = &sample.address {
                    observation.last_address = Some(address.clone());
                }
            }
        }
    }

    /// Day keys are ISO dates, so the newest are the last keys.
    pub fn prune(&mut self, keep_days: usize) {
        while self.days.len() > keep_days {
            let Some(oldest) = self.days.keys().next().cloned() else {
                break;
            };
            self.days.remove(&oldest);
        }
    }

    pub fn eligible(
        &self,
        window_days: usize,
        threshold: f64,
        min_checks: u32,
        shipped: &HashSet<(String, u16)>,
    ) -> Vec<Eligible> {
        let mut totals: BTreeMap<&str, (u32, u32, f64, Option<String>)> = BTreeMap::new();
        for entries in self.days.values().rev().take(window_days) {
            for (entry, observation) in entries {
                let total = totals.entry(entry.as_str()).or_insert((0, 0, 0.0, None));
                total.0 += observation.checked;
                total.1 += observation.answered;
                total.2 += observation.rtt_ms_total;
                if total.3.is_none() {
                    total.3 = observation.last_address.clone();
                }
            }
        }

        let newest = self.days.values().next_back();
        let mut eligible: Vec<Eligible> = totals
            .into_iter()
            .filter_map(|(entry, (checked, answered, rtt_total, address))| {
                if checked < min_checks || answered == 0 {
                    return None;
                }
                // A server that answered all week and died today is not a
                // promotion, it is a former server.
                let alive_now = newest
                    .and_then(|day| day.get(entry))
                    .map(|observation| observation.answered > 0)
                    .unwrap_or(false);
                if !alive_now {
                    return None;
                }
                let ratio = f64::from(answered) / f64::from(checked);
                if ratio < threshold {
                    return None;
                }
                if let Ok(parsed) = crate::list::parse_entry(Kind::Binding, entry, false) {
                    if shipped.contains(&(parsed.host, parsed.port)) {
                        return None;
                    }
                }
                Some(Eligible {
                    entry: entry.to_string(),
                    checked,
                    answered,
                    ratio,
                    rtt_ms: rtt_total / f64::from(answered),
                    address,
                })
            })
            .collect();

        eligible.sort_by(|left, right| {
            right
                .ratio
                .partial_cmp(&left.ratio)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(
                    left.rtt_ms
                        .partial_cmp(&right.rtt_ms)
                        .unwrap_or(std::cmp::Ordering::Equal),
                )
        });
        eligible
    }

    pub fn to_json(&self, updated: &str) -> String {
        let mut out = String::new();
        out.push_str("{\n");
        out.push_str(&format!("  \"version\": {VERSION},\n"));
        out.push_str(&format!("  \"updated\": {},\n", json::quote(updated)));
        if self.days.is_empty() {
            out.push_str("  \"days\": {}\n}\n");
            return out;
        }

        out.push_str("  \"days\": {\n");
        for (index, (day, entries)) in self.days.iter().enumerate() {
            out.push_str(&format!("    {}: {{\n", json::quote(day)));
            for (entry_index, (entry, observation)) in entries.iter().enumerate() {
                out.push_str(&format!("      {}: {{", json::quote(entry)));
                out.push_str(&format!("\"checked\": {}, ", observation.checked));
                out.push_str(&format!("\"answered\": {}, ", observation.answered));
                out.push_str(&format!(
                    "\"rtt_ms_total\": {:.1}, ",
                    observation.rtt_ms_total
                ));
                match &observation.last_ok {
                    Some(last) => out.push_str(&format!("\"last_ok\": {}", json::quote(last))),
                    None => out.push_str("\"last_ok\": null"),
                }
                out.push_str(", ");
                match &observation.last_address {
                    Some(address) => {
                        out.push_str(&format!("\"last_address\": {}", json::quote(address)))
                    }
                    None => out.push_str("\"last_address\": null"),
                }
                out.push('}');
                if entry_index + 1 != entries.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str("    }");
            if index + 1 != self.days.len() {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("  }\n}\n");
        out
    }

    pub fn parse(text: &str) -> Result<Ledger, String> {
        let value = json::parse(text).map_err(|error| format!("availability: {error}"))?;
        let mut ledger = Ledger::default();

        let Some(days) = value.get("days") else {
            return Ok(ledger);
        };
        let Value::Object(days) = days else {
            return Err("availability: days is not an object".to_string());
        };

        for (day, entries) in days {
            let Value::Object(entries) = entries else {
                return Err(format!("availability: {day} is not an object"));
            };
            let mut observations = BTreeMap::new();
            for (entry, observation) in entries {
                let checked = observation.get("checked").and_then(number).unwrap_or(0.0) as u32;
                let answered = observation.get("answered").and_then(number).unwrap_or(0.0) as u32;
                let rtt_ms_total = observation
                    .get("rtt_ms_total")
                    .and_then(number)
                    .unwrap_or(0.0);
                let last_ok = observation
                    .get("last_ok")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                let last_address = observation
                    .get("last_address")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                observations.insert(
                    entry.clone(),
                    Observation {
                        checked,
                        answered,
                        rtt_ms_total,
                        last_ok,
                        last_address,
                    },
                );
            }
            ledger.days.insert(day.clone(), observations);
        }

        Ok(ledger)
    }
}

fn number(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => Some(*number),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(entry: &str, answered: bool, rtt_ms: Option<f64>) -> Sample {
        Sample {
            entry: entry.to_string(),
            answered,
            rtt_ms,
            address: None,
        }
    }

    #[test]
    fn records_counts_per_day_and_merges_runs() {
        let mut ledger = Ledger::default();
        ledger.record(
            "2026-10-25",
            "2026-10-25T00:00:00Z",
            &[sample("a:3478", true, Some(10.0))],
        );
        ledger.record(
            "2026-10-25",
            "2026-10-25T06:00:00Z",
            &[
                sample("a:3478", false, None),
                sample("b:3478", true, Some(20.0)),
            ],
        );

        let day = &ledger.days["2026-10-25"];
        assert_eq!(day["a:3478"].checked, 2);
        assert_eq!(day["a:3478"].answered, 1);
        assert_eq!(day["a:3478"].rtt_ms_total, 10.0);
        assert_eq!(day["b:3478"].checked, 1);
        assert_eq!(
            day["b:3478"].last_ok.as_deref(),
            Some("2026-10-25T06:00:00Z")
        );
    }

    #[test]
    fn prunes_the_oldest_days() {
        let mut ledger = Ledger::default();
        for day in ["2026-10-23", "2026-10-24", "2026-10-25"] {
            ledger.record(day, "x", &[sample("a:3478", true, None)]);
        }
        ledger.prune(2);
        assert_eq!(
            ledger.days.keys().cloned().collect::<Vec<_>>(),
            vec!["2026-10-24", "2026-10-25"]
        );
    }

    #[test]
    fn eligibility_needs_the_threshold_the_checks_and_an_unshipped_entry() {
        let mut ledger = Ledger::default();
        for day in ["2026-10-24", "2026-10-25"] {
            ledger.record(
                day,
                "x",
                &[
                    sample("good:3478", true, Some(20.0)),
                    sample("flaky:3478", true, Some(30.0)),
                    sample("dead:3478", false, None),
                    sample("shipped:3478", true, Some(10.0)),
                ],
            );
            ledger.record(day, "x", &[sample("flaky:3478", false, None)]);
        }

        let mut shipped = HashSet::new();
        shipped.insert(("shipped".to_string(), 3478));

        let eligible = ledger.eligible(2, 0.95, 2, &shipped);
        let names: Vec<&str> = eligible.iter().map(|item| item.entry.as_str()).collect();
        assert_eq!(names, vec!["good:3478"]);
        assert_eq!(eligible[0].checked, 2);
        assert_eq!(eligible[0].answered, 2);
        assert_eq!(eligible[0].rtt_ms, 20.0);
    }

    #[test]
    fn ignores_days_outside_the_window() {
        let mut ledger = Ledger::default();
        ledger.record("2026-10-01", "x", &[sample("old:3478", true, None)]);
        ledger.record("2026-10-25", "x", &[sample("new:3478", true, None)]);

        let eligible = ledger.eligible(1, 0.5, 1, &HashSet::new());
        let names: Vec<&str> = eligible.iter().map(|item| item.entry.as_str()).collect();
        assert_eq!(names, vec!["new:3478"]);
    }

    #[test]
    fn a_candidate_that_died_today_is_not_eligible() {
        let mut ledger = Ledger::default();
        ledger.record(
            "2026-10-24",
            "x",
            &[
                sample("was:3478", true, None),
                sample("was:3478", true, None),
            ],
        );
        ledger.record("2026-10-25", "x", &[sample("was:3478", false, None)]);

        assert!(ledger.eligible(2, 0.5, 3, &HashSet::new()).is_empty());
    }

    #[test]
    fn round_trips_through_json() {
        let mut ledger = Ledger::default();
        ledger.record(
            "2026-10-25",
            "2026-10-25T06:00:00Z",
            &[sample("a:3478", true, Some(12.5))],
        );
        let parsed = Ledger::parse(&ledger.to_json("2026-10-25T06:00:00Z")).unwrap();
        assert_eq!(parsed.days, ledger.days);
    }
}
