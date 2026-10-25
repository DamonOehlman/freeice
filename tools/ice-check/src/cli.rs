//! Arguments, parsed by hand so the tool keeps its empty dependency list.

use std::path::PathBuf;
use std::time::Duration;

pub const USAGE: &str = "\
ice-check - probe the STUN/TURN servers freeice ships

Usage: ice-check [options]

Options:
  --root <dir>      checkout holding stun.json and turn.json
                    (default: search upward from the working directory)
  --candidates      also probe the candidate list in src/candidates.rs
  --base <dir>      only probe entries added since the lists in <dir>, for a
                    pull request that proposes a server
  --turn-targets <path>
                    probe credentialed TURN endpoints listed in <path>; a
                    target names the environment variables holding its
                    username and credential
  --env-file <path> read KEY=VALUE pairs from <path> for --turn-targets
  --json <path>     write the full result as JSON
  --suggest         print the entries that answered, as a JSON array
  --timeout-ms <n>  per-attempt timeout in milliseconds (default: 750)
  --attempts <n>    retransmits per address (default: 4)
  --family <f>      v4, v6 or both (default: both)
  -q, --quiet       tables only, no summary
  -h, --help        print this text
  -V, --version     print the version

Exit status: 0 when every shipped entry answered, 1 when one did not,
2 when the lists could not be read. A TURN server that replies 401 counts as
answered: it is telling you it wants credentials, which is the point.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Families {
    pub v4: bool,
    pub v6: bool,
}

pub struct Options {
    pub root: PathBuf,
    pub base: Option<PathBuf>,
    pub turn_targets: Option<PathBuf>,
    pub env_file: Option<PathBuf>,
    pub candidates: bool,
    pub json: Option<PathBuf>,
    pub suggest: bool,
    pub timeout: Duration,
    pub attempts: u32,
    pub families: Families,
    pub quiet: bool,
}

pub enum Command {
    Run(Options),
    Help,
    Version,
}

pub fn parse<I>(args: I) -> Result<Command, String>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter();
    let mut options = Options {
        root: PathBuf::new(),
        base: None,
        turn_targets: None,
        env_file: None,
        candidates: false,
        json: None,
        suggest: false,
        timeout: Duration::from_millis(750),
        attempts: 4,
        families: Families { v4: true, v6: true },
        quiet: false,
    };
    let mut root_given = false;

    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--root" => {
                options.root = PathBuf::from(value(&mut args, "--root")?);
                root_given = true;
            }
            "--candidates" => options.candidates = true,
            "--base" => options.base = Some(PathBuf::from(value(&mut args, "--base")?)),
            "--turn-targets" => {
                options.turn_targets = Some(PathBuf::from(value(&mut args, "--turn-targets")?))
            }
            "--env-file" => options.env_file = Some(PathBuf::from(value(&mut args, "--env-file")?)),
            "--json" => options.json = Some(PathBuf::from(value(&mut args, "--json")?)),
            "--suggest" => options.suggest = true,
            "--timeout-ms" => {
                let text = value(&mut args, "--timeout-ms")?;
                let milliseconds: u64 = text
                    .parse()
                    .map_err(|_| format!("{text} is not a timeout in milliseconds"))?;
                if milliseconds == 0 {
                    return Err("--timeout-ms must be at least 1".to_string());
                }
                options.timeout = Duration::from_millis(milliseconds);
            }
            "--attempts" => {
                let text = value(&mut args, "--attempts")?;
                let attempts: u32 = text
                    .parse()
                    .map_err(|_| format!("{text} is not a number of attempts"))?;
                if attempts == 0 {
                    return Err("--attempts must be at least 1".to_string());
                }
                options.attempts = attempts;
            }
            "--family" => {
                options.families = match value(&mut args, "--family")?.as_str() {
                    "v4" => Families {
                        v4: true,
                        v6: false,
                    },
                    "v6" => Families {
                        v4: false,
                        v6: true,
                    },
                    "both" => Families { v4: true, v6: true },
                    other => return Err(format!("--family takes v4, v6 or both, not {other}")),
                };
            }
            "-q" | "--quiet" => options.quiet = true,
            "-h" | "--help" => return Ok(Command::Help),
            "-V" | "--version" => return Ok(Command::Version),
            other => return Err(format!("unknown option {other}")),
        }
    }

    if !root_given {
        options.root = discover_root()?;
    }

    Ok(Command::Run(options))
}

fn value<I>(args: &mut I, name: &str) -> Result<String, String>
where
    I: Iterator<Item = String>,
{
    args.next().ok_or_else(|| format!("{name} needs a value"))
}

fn discover_root() -> Result<PathBuf, String> {
    let mut directory = std::env::current_dir()
        .map_err(|error| format!("cannot read the working directory: {error}"))?;
    for _ in 0..8 {
        if directory.join("stun.json").is_file() {
            return Ok(directory);
        }
        if !directory.pop() {
            break;
        }
    }
    Err("cannot find stun.json above the working directory; pass --root".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    #[test]
    fn defaults_to_both_families_and_four_attempts() {
        let Ok(Command::Run(options)) = parse(args(&["--root", "."])) else {
            panic!("expected a run");
        };
        assert!(options.families.v4 && options.families.v6);
        assert_eq!(options.attempts, 4);
        assert_eq!(options.timeout, Duration::from_millis(750));
    }

    #[test]
    fn reads_the_family_selection() {
        let Ok(Command::Run(options)) = parse(args(&["--root", ".", "--family", "v6"])) else {
            panic!("expected a run");
        };
        assert!(!options.families.v4);
        assert!(options.families.v6);
    }

    #[test]
    fn rejects_an_unknown_option() {
        assert!(parse(args(&["--root", ".", "--turbo"])).is_err());
    }

    #[test]
    fn rejects_zero_attempts() {
        assert!(parse(args(&["--root", ".", "--attempts", "0"])).is_err());
    }

    #[test]
    fn help_short_circuits_validation() {
        assert!(matches!(parse(args(&["--help"])), Ok(Command::Help)));
    }
}
