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
- **TURN reachability.** An Allocate request: a live server answers 401. With
  credentials it goes further — the 401's realm and nonce are answered with a
  MESSAGE-INTEGRITY attribute, and the tool reports the relay address it was
  given, which proves the credential works, not just that the endpoint is up.
- **Diversity.** How many entries collapse onto one address, which entries share
  a netblock, and which publish no AAAA. A list of ten names that resolves to one
  address has ten entries and one point of failure.

`--family v4` on an IPv4-only machine keeps the IPv6 rows out of the table; the
AAAA records are still counted as published addresses.

## Proposing servers from a published list

`--candidates-file` takes any `host:port`-per-line list and probes it as
candidates, skipping entries that are already shipped:

```sh
curl -o .tmp/always-online.txt https://raw.githubusercontent.com/pradt2/always-online-stun/master/valid_hosts.txt
cargo run --manifest-path tools/ice-check/Cargo.toml -- \
    --candidates-file .tmp/always-online.txt
```

[always-online-stun](https://github.com/pradt2/always-online-stun) (MIT)
republishes its checked list hourly. It is a discovery source, not something to
mirror into `stun.json`: promote a handful that answer, and prefer entries that
add a netblock the list does not already have.

## Earning promotion over time

One good afternoon should not put a server in `stun.json`. `--record` keeps a
per-day ledger of every candidate, and `--availability` reports what has stayed
up across a window:

```sh
cargo run --manifest-path tools/ice-check/Cargo.toml -- \
    --candidates-file .tmp/always-online.txt --record data/availability.json

cargo run --manifest-path tools/ice-check/Cargo.toml -- \
    --availability data/availability.json \
    --threshold 95 --min-checks 20 --window-days 7
```

The ledger lives in the workflow cache rather than in git: the scheduled run
restores `.tmp/availability.json`, records this pass, and saves it back under a
per-run key, with a copy uploaded as an artifact so the recent history is
downloadable. Nothing is committed.

Cache is not durable storage. GitHub evicts caches that go unused, and a lost
ledger only resets the window — it cannot promote a server that has not been
answering — so the failure mode is a delay, not a bad list. The workflow runs
every six hours, which gives 28 checks in the seven-day window, and promotes at
90% so one lost packet does not disqualify a good server.

Per day and per entry the ledger records `checked`, `answered`, `rtt_ms_total`,
`last_ok` and `last_address`; days older than twice the window are pruned when
it is written.

Promotion is a report, not an edit: the tool never writes `stun.json`. A
candidate is listed when it answered at least `--threshold` percent of the
checks in the window, has at least `--min-checks` of them, and is not already
shipped.

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

## Credentialed TURN

The shipped lists never carry credentials. A target file names the environment
variables instead:

```json
[
  {
    "name": "cloudflare-3478",
    "urls": "turn:turn.cloudflare.com:3478?transport=udp",
    "username_env": "TURN_CF_USERNAME",
    "credential_env": "TURN_CF_CREDENTIAL"
  }
]
```

```sh
cargo run --manifest-path tools/ice-check/Cargo.toml -- \
    --turn-targets tools/ice-check/turn-targets.json \
    --env-file .env
```

`--env-file` is for a laptop; CI exports the variables. The environment wins
over the file. Only UDP URLs are probed: `turns:` and `?transport=tcp` are
skipped, because this tool has no TLS or TCP transport. A target whose
variables are unset is reported as skipped, not failed, so a checkout without
secrets still runs cleanly.

The workflow mints Cloudflare credentials from `TURN_TOKEN_ID` and
`TURN_API_TOKEN` before the run. Other providers with static usernames and
passwords need only the two secrets; Twilio and Cloudflare mint short-lived
credentials, so their workflows call the provider first.

## Why it has so few dependencies

The tool exists because things outside this repository change, so it must not
be fragile itself. It has no async runtime, no HTTP client and no CLI or JSON
crate: arguments, the report and the DNS queries are all std. The three
exceptions are `md-5`, `sha1` and `hmac`, which are what TURN's
MESSAGE-INTEGRITY is defined in terms of; a hand-rolled digest would be the one
part of this worth not improvising.

`cargo test` runs the codec, DNS and crypto tests against captured packets and
published vectors, and needs no network.
