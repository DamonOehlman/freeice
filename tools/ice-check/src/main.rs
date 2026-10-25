//! Freeice's server-list checker.
//!
//! `freeice` ships a list of free STUN servers, and the list rots: an operator
//! retires a host, a domain becomes a null route, a name stops resolving. This
//! probes each entry the way a browser would, per address and per family, and
//! says which entries still answer and how much genuine diversity the list has.
//!
//! It has no dependencies on purpose. The reason a list checker exists is that
//! things outside this repository change; a tool that itself stops building is
//! not much use.

mod candidates;
mod cli;
mod dns;
mod json;
mod list;
mod probe;
mod report;
mod stun;

use std::collections::HashSet;
use std::process::ExitCode;

fn main() -> ExitCode {
    match cli::parse(std::env::args().skip(1)) {
        Err(error) => {
            eprintln!("ice-check: {error}\n\n{}", cli::USAGE);
            ExitCode::from(2)
        }
        Ok(cli::Command::Help) => {
            println!("{}", cli::USAGE);
            ExitCode::SUCCESS
        }
        Ok(cli::Command::Version) => {
            println!("ice-check {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Ok(cli::Command::Run(options)) => run(options),
    }
}

fn run(options: cli::Options) -> ExitCode {
    let mut entries = Vec::new();
    for (file, kind) in [
        ("stun.json", stun::Kind::Binding),
        ("turn.json", stun::Kind::Allocate),
    ] {
        match list::load(&options.root, file, kind) {
            Ok(mut loaded) => entries.append(&mut loaded),
            Err(error) => {
                eprintln!("ice-check: {error}");
                return ExitCode::from(2);
            }
        }
    }

    if let Some(base) = &options.base {
        let mut known: HashSet<String> = HashSet::new();
        for (file, kind) in [
            ("stun.json", stun::Kind::Binding),
            ("turn.json", stun::Kind::Allocate),
        ] {
            match list::load_optional(base, file, kind) {
                Ok(loaded) => known.extend(loaded.into_iter().map(|entry| entry.raw)),
                Err(error) => {
                    eprintln!("ice-check: {error}");
                    return ExitCode::from(2);
                }
            }
        }
        entries.retain(|entry| !known.contains(&entry.raw));

        if entries.is_empty() {
            println!("no entries added since {}", base.display());
            return ExitCode::SUCCESS;
        }
    } else if entries.is_empty() {
        eprintln!(
            "ice-check: no servers in the lists under {}",
            options.root.display()
        );
        return ExitCode::from(2);
    }

    let candidate_entries: Vec<list::Entry> = if options.candidates {
        candidates::CANDIDATES
            .iter()
            .filter_map(
                |raw| match list::parse_entry(stun::Kind::Binding, raw, false) {
                    Ok(entry) => Some(entry),
                    Err(error) => {
                        eprintln!("ice-check: skipping candidate {raw}: {error}");
                        None
                    }
                },
            )
            .collect()
    } else {
        Vec::new()
    };

    let servers = dns::servers();
    let results = report::check_all(
        &entries,
        &servers,
        options.timeout,
        options.attempts,
        options.families,
    );
    let candidate_results = report::check_all(
        &candidate_entries,
        &servers,
        options.timeout,
        options.attempts,
        options.families,
    );

    report::print(&results, &candidate_results, &options);

    if let Some(path) = &options.json {
        let document = report::to_json(&results, &candidate_results, options.base.as_deref());
        if let Err(error) = std::fs::write(path, document) {
            eprintln!("ice-check: cannot write {}: {error}", path.display());
            return ExitCode::from(2);
        }
        if !options.quiet {
            println!("wrote {}", path.display());
        }
    }

    if options.suggest {
        print!("{}", report::suggest(&results));
    }

    if results.iter().any(|result| !result.answered()) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
