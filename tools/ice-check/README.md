# ice-check

Probes every server in `stun.json` and `turn.json` and reports what answered.
The lists rot: an operator retires a host, a domain becomes a null route, a
name stops resolving. This is the tool that notices.

```sh
cargo run --manifest-path tools/ice-check/Cargo.toml -- --candidates
```

`--candidates` also probes the servers in `src/candidates.rs`, which are worth
measuring before deciding the shipped list needs them. Nothing there is
endorsed: check the operator's terms first.

## What it checks

- **DNS, asked directly.** A and AAAA are queried of the nameserver in
  `/etc/resolv.conf`, so a machine without global IPv6 can still tell whether an
  entry publishes IPv6. NXDOMAIN and a CNAME chain pointing at a dead host are
  different answers, and both are reported as such.
- **Addresses that cannot answer.** A name resolving into a documentation
  prefix, a private range or a discard prefix is reported as `bogon` rather than
  being probed and reported as a timeout.
- **Every address, per family.** A Binding request over UDP, with retransmits,
  reporting the mapped address, the server's `SOFTWARE` attribute and the
  round-trip time. A refused port, silence, and "no route from this host" are
  three different results.
- **TURN reachability.** An Allocate request without credentials: a live server
  answers 401, which counts as answered. Whether a credential works is not this
  tool's job.
- **Diversity.** How many entries collapse onto one address, which entries share
  a netblock, and which publish no AAAA. A list of ten names that resolves to one
  address has ten entries and one point of failure.

`--family v4` on an IPv4-only machine keeps the IPv6 rows out of the table; the
AAAA records are still counted as published addresses.

## A pull request that proposes a server

`--base` probes only the entries that are not in the base revision, so a pull
request is judged on what it adds rather than on a server that died last month:

```sh
mkdir -p .tmp/base
git show origin/master:stun.json > .tmp/base/stun.json
git show origin/master:turn.json > .tmp/base/turn.json
cargo run --manifest-path tools/ice-check/Cargo.toml -- --base .tmp/base
```

A missing base list counts as empty, and a pull request that adds no servers
exits 0 without probing anything. The workflow in
`.github/workflows/ice-check.yaml` does exactly this.

## Output

A table, a summary, and optionally JSON:

```sh
cargo run --manifest-path tools/ice-check/Cargo.toml -- --json report.json --suggest
```

`--suggest` prints the entries that answered as a JSON array, ready to paste
into `stun.json`.

Exit status is 0 when every shipped entry answered, 1 when one did not, and 2
when the lists could not be read.

## Why it has no dependencies

The tool exists because things outside this repository change. A tool that
itself stops building is not much use, so it builds offline with any recent
stable Rust and nothing else. `cargo test` runs the codec and DNS tests against
captured packets and needs no network.
