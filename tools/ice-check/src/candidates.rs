//! Servers worth measuring before deciding the shipped list needs them.
//!
//! Nothing here is endorsed. Each entry is a question - does this operator
//! answer better than what `stun.json` already ships? - and the answer belongs
//! to whoever maintains the list. Most were chosen because they are run
//! deliberately by an operator that publishes STUN as part of a service, which
//! is a different thing from the hobby servers this list grew up around.
//!
//! Check the operator's terms before promoting one into `stun.json`; the
//! README already promises that homework was done.

pub const CANDIDATES: &[&str] = &[
    // Anycast, heavily provisioned. Published by Cloudflare for their Realtime
    // service rather than as a public utility, so this is a policy question.
    "stun.cloudflare.com:3478",
    // UDP/443 slips past filters that block 3478 and 19302. Intended for
    // Nextcloud Talk deployments.
    "stun.nextcloud.com:443",
    // Long-lived, independent of Google.
    "stun.sipgate.net:3478",
    "stun.hot-chilli.net:3478",
    "stun.voipgate.com:3478",
    // Regional: useful to list only if the list wants a Chinese vantage point.
    "stun.miwifi.com:3478",
    // Twilio publishes this one openly, though they would rather you bought
    // Network Traversal Service.
    "global.stun.twilio.com:3478",
    // Answers ICMP port unreachable: the host is up, nothing is listening.
    "stun.antisip.com:3478",
    // Points into TEST-NET-1 (192.0.2.42), a deliberate null route.
    "stun.syncthing.net:3478",
    // The free relay this used to name no longer resolves.
    "turn:openrelay.metered.ca:80",
];
