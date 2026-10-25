//! One probe of one address, classified rather than merely failed.

use crate::stun::{self, Kind};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug)]
pub enum Outcome {
    Ok {
        rtt: Duration,
        mapped: Option<String>,
        software: Option<String>,
    },
    /// A TURN allocation succeeded: the server is reachable *and* accepted the
    /// credentials it was given.
    Relayed {
        rtt: Duration,
        relayed: Option<String>,
        software: Option<String>,
    },
    Error {
        rtt: Duration,
        code: u16,
        reason: String,
    },
    /// The server spoke and refused the credentials.
    Rejected {
        rtt: Duration,
        code: u16,
        reason: String,
    },
    Refused,
    Timeout {
        attempts: u32,
    },
    Unreachable {
        detail: String,
    },
    Garbage {
        bytes: usize,
        detail: String,
    },
    SendFailed {
        detail: String,
    },
    /// The name resolved into a range that cannot answer: a null route, a
    /// documentation prefix, or a private address leaked into a public list.
    Bogon {
        detail: String,
    },
}

impl Outcome {
    /// Whether the server spoke STUN, whatever it said.
    pub fn answered(&self) -> bool {
        matches!(
            self,
            Outcome::Ok { .. }
                | Outcome::Relayed { .. }
                | Outcome::Error { .. }
                | Outcome::Rejected { .. }
        )
    }

    pub fn relayed(&self) -> bool {
        matches!(self, Outcome::Relayed { .. })
    }

    pub fn label(&self) -> &'static str {
        match self {
            Outcome::Ok { .. } => "ok",
            Outcome::Relayed { .. } => "relayed",
            Outcome::Error { .. } => "error",
            Outcome::Rejected { .. } => "denied",
            Outcome::Refused => "refused",
            Outcome::Timeout { .. } => "timeout",
            Outcome::Unreachable { .. } => "no route",
            Outcome::Garbage { .. } => "garbage",
            Outcome::SendFailed { .. } => "send failed",
            Outcome::Bogon { .. } => "bogon",
        }
    }

    pub fn detail(&self) -> String {
        match self {
            Outcome::Ok {
                mapped, software, ..
            } => {
                let mut detail = mapped
                    .clone()
                    .unwrap_or_else(|| "no mapped address".to_string());
                if let Some(software) = software {
                    detail.push_str(&format!("  [{software}]"));
                }
                detail
            }
            Outcome::Relayed {
                relayed, software, ..
            } => {
                let mut detail = match relayed {
                    Some(address) => format!("relay {address}"),
                    None => "allocated without a relayed address".to_string(),
                };
                if let Some(software) = software {
                    detail.push_str(&format!("  [{software}]"));
                }
                detail
            }
            Outcome::Error { code, reason, .. } | Outcome::Rejected { code, reason, .. } => {
                if reason.is_empty() {
                    format!("{code}")
                } else {
                    format!("{code} {reason}")
                }
            }
            Outcome::Refused => "ICMP port unreachable".to_string(),
            Outcome::Timeout { attempts } => format!("no reply after {attempts} attempts"),
            Outcome::Unreachable { detail } => detail.clone(),
            Outcome::Garbage { bytes, detail } => format!("{bytes} bytes: {detail}"),
            Outcome::SendFailed { detail } => detail.clone(),
            Outcome::Bogon { detail } => detail.clone(),
        }
    }

    pub fn rtt_ms(&self) -> Option<f64> {
        let rtt = match self {
            Outcome::Ok { rtt, .. }
            | Outcome::Relayed { rtt, .. }
            | Outcome::Error { rtt, .. }
            | Outcome::Rejected { rtt, .. } => *rtt,
            _ => return None,
        };
        Some((rtt.as_secs_f64() * 1000.0 * 10.0).round() / 10.0)
    }
}

pub fn probe(address: SocketAddr, kind: Kind, timeout: Duration, attempts: u32) -> Outcome {
    match kind {
        Kind::Binding => probe_binding(address, timeout, attempts),
        Kind::Allocate => probe_turn(address, timeout, attempts, None),
    }
}

fn probe_binding(address: SocketAddr, timeout: Duration, attempts: u32) -> Outcome {
    let socket = match connect(address, timeout) {
        Ok(socket) => socket,
        Err(outcome) => return outcome,
    };

    let request = stun::request(Kind::Binding);
    let (reply, rtt) = match exchange(&socket, &request.bytes, &request.transaction_id, attempts) {
        Ok(pair) => pair,
        Err(outcome) => return outcome,
    };
    let message = match decode(&reply) {
        Ok(message) => message,
        Err(outcome) => return outcome,
    };

    if stun::class(message.message_type) == 2 {
        return Outcome::Ok {
            rtt,
            mapped: stun::mapped_address(&message),
            software: stun::software(&message),
        };
    }
    let (code, reason) = stun::error_code(&message).unwrap_or((0, String::new()));
    Outcome::Error { rtt, code, reason }
}

pub fn probe_turn(
    address: SocketAddr,
    timeout: Duration,
    attempts: u32,
    credentials: Option<&Credentials>,
) -> Outcome {
    let socket = match connect(address, timeout) {
        Ok(socket) => socket,
        Err(outcome) => return outcome,
    };

    // An unauthenticated Allocate is the cheapest way to learn that the server
    // is alive and to collect its realm and nonce.
    let request = stun::request(Kind::Allocate);
    let (reply, rtt) = match exchange(&socket, &request.bytes, &request.transaction_id, attempts) {
        Ok(pair) => pair,
        Err(outcome) => return outcome,
    };
    let message = match decode(&reply) {
        Ok(message) => message,
        Err(outcome) => return outcome,
    };

    if stun::class(message.message_type) == 2 {
        return Outcome::Relayed {
            rtt,
            relayed: stun::relayed_address(&message),
            software: stun::software(&message),
        };
    }

    let (code, reason) = stun::error_code(&message).unwrap_or((0, String::new()));
    let Some(credentials) = credentials else {
        return Outcome::Error { rtt, code, reason };
    };
    if code != 401 && code != 438 {
        return Outcome::Error { rtt, code, reason };
    }
    let Some(mut challenge) = stun::challenge(&message) else {
        return Outcome::Error { rtt, code, reason };
    };

    // A stale nonce (438) carries a fresh one, so one retry is allowed.
    for _ in 0..2 {
        let authenticated =
            stun::authenticated_allocate(&challenge, &credentials.username, &credentials.password);
        let (reply, rtt) = match exchange(
            &socket,
            &authenticated.bytes,
            &authenticated.transaction_id,
            attempts,
        ) {
            Ok(pair) => pair,
            Err(outcome) => return outcome,
        };
        let message = match decode(&reply) {
            Ok(message) => message,
            Err(outcome) => return outcome,
        };

        if stun::class(message.message_type) == 2 {
            return Outcome::Relayed {
                rtt,
                relayed: stun::relayed_address(&message),
                software: stun::software(&message),
            };
        }

        let (code, reason) = stun::error_code(&message).unwrap_or((0, String::new()));
        if code == 438 {
            if let Some(fresh) = stun::challenge(&message) {
                challenge = fresh;
                continue;
            }
        }
        return Outcome::Rejected { rtt, code, reason };
    }

    Outcome::Rejected {
        rtt: Duration::ZERO,
        code: 438,
        reason: "stale nonce twice".to_string(),
    }
}

fn connect(address: SocketAddr, timeout: Duration) -> Result<UdpSocket, Outcome> {
    let bind = if address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).map_err(|error| Outcome::Unreachable {
        detail: format!("cannot open a socket: {error}"),
    })?;
    socket
        .connect(address)
        .map_err(|error| Outcome::Unreachable {
            detail: format!("cannot reach {address}: {error}"),
        })?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|error| Outcome::Unreachable {
            detail: format!("cannot set a read timeout: {error}"),
        })?;
    Ok(socket)
}

fn exchange(
    socket: &UdpSocket,
    request: &[u8],
    transaction_id: &[u8; 12],
    attempts: u32,
) -> Result<(Vec<u8>, Duration), Outcome> {
    let attempts = attempts.max(1);
    let mut buffer = [0u8; 1500];
    let started = Instant::now();

    for _ in 0..attempts {
        if let Err(error) = socket.send(request) {
            return Err(match error.kind() {
                io::ErrorKind::ConnectionRefused => Outcome::Refused,
                io::ErrorKind::HostUnreachable | io::ErrorKind::NetworkUnreachable => {
                    Outcome::Unreachable {
                        detail: error.to_string(),
                    }
                }
                _ => Outcome::SendFailed {
                    detail: error.to_string(),
                },
            });
        }

        match socket.recv(&mut buffer) {
            Ok(length) => {
                if length >= 20 && &buffer[8..20] == transaction_id {
                    return Ok((buffer[..length].to_vec(), started.elapsed()));
                }
            }
            Err(error) => match error.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => continue,
                io::ErrorKind::ConnectionRefused => return Err(Outcome::Refused),
                _ => {
                    return Err(Outcome::Unreachable {
                        detail: error.to_string(),
                    })
                }
            },
        }
    }

    Err(Outcome::Timeout { attempts })
}

fn decode(reply: &[u8]) -> Result<stun::Message<'_>, Outcome> {
    stun::decode(reply).map_err(|error| Outcome::Garbage {
        bytes: reply.len(),
        detail: error.to_string(),
    })
}
