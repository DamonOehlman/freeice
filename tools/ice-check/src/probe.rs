//! One probe of one address, classified rather than merely failed.

use crate::stun::{self, Kind};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub enum Outcome {
    Ok {
        rtt: Duration,
        mapped: Option<String>,
        software: Option<String>,
    },
    Error {
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
    /// Whether the server spoke STUN, whatever it said. A TURN server that
    /// answers Allocate with 401 has answered.
    pub fn answered(&self) -> bool {
        matches!(self, Outcome::Ok { .. } | Outcome::Error { .. })
    }

    pub fn label(&self) -> &'static str {
        match self {
            Outcome::Ok { .. } => "ok",
            Outcome::Error { .. } => "error",
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
            Outcome::Error { code, reason, .. } => {
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
        match self {
            Outcome::Ok { rtt, .. } | Outcome::Error { rtt, .. } => {
                Some((rtt.as_secs_f64() * 1000.0 * 10.0).round() / 10.0)
            }
            _ => None,
        }
    }
}

pub fn probe(address: SocketAddr, kind: Kind, timeout: Duration, attempts: u32) -> Outcome {
    let bind = if address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = match UdpSocket::bind(bind) {
        Ok(socket) => socket,
        Err(error) => {
            return Outcome::Unreachable {
                detail: format!("cannot open a socket: {error}"),
            }
        }
    };
    if let Err(error) = socket.connect(address) {
        return Outcome::Unreachable {
            detail: format!("cannot reach {address}: {error}"),
        };
    }
    if let Err(error) = socket.set_read_timeout(Some(timeout)) {
        return Outcome::Unreachable {
            detail: format!("cannot set a read timeout: {error}"),
        };
    }

    let request = stun::request(kind);
    let attempts = attempts.max(1);
    let started = Instant::now();
    let mut buffer = [0u8; 1500];

    for _ in 0..attempts {
        if let Err(error) = socket.send(&request.bytes) {
            return match error.kind() {
                io::ErrorKind::ConnectionRefused => Outcome::Refused,
                _ => Outcome::SendFailed {
                    detail: error.to_string(),
                },
            };
        }

        match socket.recv(&mut buffer) {
            Ok(length) => {
                let rtt = started.elapsed();
                let message = match stun::decode(&buffer[..length]) {
                    Ok(message) => message,
                    Err(error) => {
                        return Outcome::Garbage {
                            bytes: length,
                            detail: error.to_string(),
                        }
                    }
                };
                if message.transaction_id != request.transaction_id {
                    continue;
                }
                if stun::class(message.message_type) == 2 {
                    return Outcome::Ok {
                        rtt,
                        mapped: stun::mapped_address(&message),
                        software: stun::software(&message),
                    };
                }
                let (code, reason) = stun::error_code(&message).unwrap_or((0, String::new()));
                return Outcome::Error { rtt, code, reason };
            }
            Err(error) => match error.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => continue,
                io::ErrorKind::ConnectionRefused => return Outcome::Refused,
                _ => {
                    return Outcome::Unreachable {
                        detail: error.to_string(),
                    }
                }
            },
        }
    }

    Outcome::Timeout { attempts }
}
