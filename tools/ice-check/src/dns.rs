//! The A and AAAA lookups the checker needs, asked directly.
//!
//! `getaddrinfo` answers with the address families this host is configured to
//! use, so on a machine without global IPv6 it drops AAAA records. A checker
//! built on it cannot tell "this operator publishes no IPv6" from "this host
//! cannot see IPv6", and that distinction is the point of the diversity report.
//! These are the queries needed to make it, and nothing else.

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
const MAX_SERVERS: usize = 3;
const QUERY_ATTEMPTS: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rcode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
    Unknown(u8),
}

impl Rcode {
    fn from_bits(bits: u8) -> Self {
        match bits {
            0 => Rcode::NoError,
            1 => Rcode::FormatError,
            2 => Rcode::ServerFailure,
            3 => Rcode::NameError,
            4 => Rcode::NotImplemented,
            5 => Rcode::Refused,
            other => Rcode::Unknown(other),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Rcode::NoError => "NOERROR",
            Rcode::FormatError => "FORMERR",
            Rcode::ServerFailure => "SERVFAIL",
            Rcode::NameError => "NXDOMAIN",
            Rcode::NotImplemented => "NOTIMP",
            Rcode::Refused => "REFUSED",
            Rcode::Unknown(_) => "RCODE",
        }
    }

    pub fn detail(self) -> String {
        match self {
            Rcode::Unknown(bits) => format!("rcode {bits}"),
            other => other.label().to_string(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// Queried directly, so both families are visible whatever this host uses.
    Resolver,
    /// The platform's own resolution, used when the resolver could not be read
    /// or reached. AAAA records may be missing for local reasons.
    System,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Source::Resolver => "resolver",
            Source::System => "system",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Lookup {
    pub a: Vec<Ipv4Addr>,
    pub aaaa: Vec<Ipv6Addr>,
    pub cnames: Vec<String>,
    pub rcode: Option<Rcode>,
    pub source: Source,
    pub note: Option<String>,
    /// Whether the corresponding query was actually answered. Without this,
    /// "no AAAA" and "could not ask for AAAA" become the same claim.
    pub a_answered: bool,
    pub aaaa_answered: bool,
}

impl Default for Lookup {
    fn default() -> Self {
        Lookup {
            a: Vec::new(),
            aaaa: Vec::new(),
            cnames: Vec::new(),
            rcode: None,
            source: Source::System,
            note: None,
            a_answered: false,
            aaaa_answered: false,
        }
    }
}

impl Lookup {
    pub fn addresses(&self) -> Vec<IpAddr> {
        let mut out: Vec<IpAddr> = self.a.iter().map(|address| IpAddr::V4(*address)).collect();
        out.extend(self.aaaa.iter().map(|address| IpAddr::V6(*address)));
        out
    }

    pub fn is_empty(&self) -> bool {
        self.a.is_empty() && self.aaaa.is_empty()
    }
}

pub fn lookup(host: &str, servers: &[SocketAddr], timeout: Duration) -> Lookup {
    if let Ok(address) = host.parse::<IpAddr>() {
        let mut answer = Lookup {
            source: Source::Resolver,
            note: Some("literal address".to_string()),
            ..Lookup::default()
        };
        match address {
            IpAddr::V4(address) => {
                answer.a.push(address);
                answer.a_answered = true;
            }
            IpAddr::V6(address) => {
                answer.aaaa.push(address);
                answer.aaaa_answered = true;
            }
        }
        return answer;
    }

    if servers.is_empty() {
        return system_lookup(host, "no nameserver in /etc/resolv.conf");
    }

    let mut answer = Lookup {
        source: Source::Resolver,
        ..Lookup::default()
    };
    let mut failures = Vec::new();

    for query_type in [TYPE_A, TYPE_AAAA] {
        match query(host, query_type, servers, timeout) {
            Ok(response) => {
                if answer.rcode.is_none() {
                    answer.rcode = response.rcode;
                }
                answer.a.extend(response.a);
                answer.aaaa.extend(response.aaaa);
                answer.cnames.extend(response.cnames);
                if query_type == TYPE_A {
                    answer.a_answered = true;
                } else {
                    answer.aaaa_answered = true;
                }
                if response.rcode == Some(Rcode::NameError) {
                    // NXDOMAIN answers for every type at once.
                    answer.a_answered = true;
                    answer.aaaa_answered = true;
                    break;
                }
            }
            Err(error) => failures.push(error),
        }
    }

    // A transport failure on A leaves us unable to say whether the host has an
    // address at all; the system resolver is a better answer than "no address".
    if answer.a.is_empty() && !answer.a_answered {
        return system_lookup(host, &failures.join("; "));
    }
    if !failures.is_empty() {
        answer.note = Some(failures.join("; "));
    }

    dedupe(&mut answer);
    answer
}

/// The nameservers from `/etc/resolv.conf`, in order.
pub fn servers() -> Vec<SocketAddr> {
    let mut out = Vec::new();
    let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") else {
        return out;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let mut parts = line.split_whitespace();
        if parts.next() != Some("nameserver") {
            continue;
        }
        if let Some(value) = parts.next() {
            if let Ok(address) = value.parse::<IpAddr>() {
                out.push(SocketAddr::new(address, 53));
            }
        }
        if out.len() >= MAX_SERVERS {
            break;
        }
    }
    out
}

fn dedupe(answer: &mut Lookup) {
    answer.a.dedup();
    answer.aaaa.dedup();
    answer.cnames.dedup();
}

fn system_lookup(host: &str, note: &str) -> Lookup {
    let mut answer = Lookup {
        source: Source::System,
        note: Some(note.to_string()),
        a_answered: true,
        // The system resolver only reports the families this host can use, so
        // an absent AAAA here says nothing about the operator.
        aaaa_answered: false,
        ..Lookup::default()
    };
    match (host, 3478u16).to_socket_addrs() {
        Ok(addresses) => {
            for address in addresses {
                match address.ip() {
                    IpAddr::V4(address) => {
                        if !answer.a.contains(&address) {
                            answer.a.push(address);
                        }
                    }
                    IpAddr::V6(address) => {
                        if !answer.aaaa.contains(&address) {
                            answer.aaaa.push(address);
                        }
                    }
                }
            }
        }
        Err(error) => {
            let _ = write!(
                answer.note.get_or_insert_with(String::new),
                "; system resolver: {error}"
            );
        }
    }
    answer
}

fn query(
    host: &str,
    query_type: u16,
    servers: &[SocketAddr],
    timeout: Duration,
) -> Result<Lookup, String> {
    let transaction_id = u16::from_be_bytes([random_byte(), random_byte()]);
    let packet = build_query(transaction_id, host, query_type)?;
    let mut last_error = String::from("no nameserver answered");

    for server in servers {
        let bind = if server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let Ok(socket) = UdpSocket::bind(bind) else {
            last_error = format!("cannot bind a socket for {server}");
            continue;
        };
        if socket.set_read_timeout(Some(timeout)).is_err() {
            continue;
        }
        for _ in 0..QUERY_ATTEMPTS {
            if let Err(error) = socket.send_to(&packet, server) {
                last_error = format!("cannot query {server}: {error}");
                break;
            }
            let mut buffer = [0u8; 1500];
            match socket.recv_from(&mut buffer) {
                Ok((length, from)) if from.ip() == server.ip() => {
                    return parse_response(&buffer[..length], transaction_id);
                }
                Ok(_) => continue,
                Err(error) => {
                    last_error = format!("no answer from {server}: {error}");
                }
            }
        }
    }

    Err(last_error)
}

fn build_query(transaction_id: u16, host: &str, query_type: u16) -> Result<Vec<u8>, String> {
    let name = host.trim_end_matches('.');
    let mut encoded = Vec::with_capacity(name.len() + 2);
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("{host} is not a valid DNS name"));
        }
        encoded.push(label.len() as u8);
        encoded.extend_from_slice(label.as_bytes());
    }
    encoded.push(0);

    let mut packet = Vec::with_capacity(12 + encoded.len() + 4);
    packet.extend_from_slice(&transaction_id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes()); // recursion desired
    packet.extend_from_slice(&1u16.to_be_bytes()); // questions
    packet.extend_from_slice(&0u16.to_be_bytes()); // answers
    packet.extend_from_slice(&0u16.to_be_bytes()); // authority
    packet.extend_from_slice(&0u16.to_be_bytes()); // additional
    packet.extend_from_slice(&encoded);
    packet.extend_from_slice(&query_type.to_be_bytes());
    packet.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(packet)
}

fn parse_response(bytes: &[u8], transaction_id: u16) -> Result<Lookup, String> {
    if bytes.len() < 12 {
        return Err("DNS response shorter than a header".to_string());
    }
    let id = u16::from_be_bytes([bytes[0], bytes[1]]);
    if id != transaction_id {
        return Err("DNS response carries another transaction id".to_string());
    }
    let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
    if flags & 0x8000 == 0 {
        return Err("DNS packet is not a response".to_string());
    }

    let rcode = Rcode::from_bits((flags & 0x000F) as u8);
    let questions = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    let answers = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;

    let mut offset = 12;
    for _ in 0..questions {
        read_name(bytes, &mut offset)?;
        if offset + 4 > bytes.len() {
            return Err("truncated question".to_string());
        }
        offset += 4;
    }

    let mut answer = Lookup {
        rcode: Some(rcode),
        source: Source::Resolver,
        ..Lookup::default()
    };

    for _ in 0..answers {
        read_name(bytes, &mut offset)?;
        if offset + 10 > bytes.len() {
            return Err("truncated answer header".to_string());
        }
        let kind = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        let class = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]);
        let length = u16::from_be_bytes([bytes[offset + 8], bytes[offset + 9]]) as usize;
        let data = offset + 10;
        if data + length > bytes.len() {
            return Err("truncated answer data".to_string());
        }

        if class == CLASS_IN {
            match kind {
                TYPE_A if length == 4 => {
                    let mut octets = [0u8; 4];
                    octets.copy_from_slice(&bytes[data..data + 4]);
                    answer.a.push(Ipv4Addr::from(octets));
                }
                TYPE_AAAA if length == 16 => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&bytes[data..data + 16]);
                    answer.aaaa.push(Ipv6Addr::from(octets));
                }
                TYPE_CNAME => {
                    let mut cursor = data;
                    if let Ok(name) = read_name(bytes, &mut cursor) {
                        answer.cnames.push(name);
                    }
                }
                _ => {}
            }
        }

        offset = data + length;
    }

    Ok(answer)
}

fn read_name(bytes: &[u8], offset: &mut usize) -> Result<String, String> {
    let mut labels = Vec::new();
    let mut position = *offset;
    let mut jumped = false;
    let mut jumps = 0;

    loop {
        let Some(&length) = bytes.get(position) else {
            return Err("truncated DNS name".to_string());
        };
        if length == 0 {
            position += 1;
            if !jumped {
                *offset = position;
            }
            break;
        }
        if length & 0xC0 == 0xC0 {
            let Some(&second) = bytes.get(position + 1) else {
                return Err("truncated compression pointer".to_string());
            };
            let target = ((usize::from(length & 0x3F)) << 8) | usize::from(second);
            if !jumped {
                *offset = position + 2;
            }
            jumped = true;
            jumps += 1;
            if jumps > 16 {
                return Err("compression pointer loop".to_string());
            }
            position = target;
            continue;
        }
        if length & 0xC0 != 0 {
            return Err("unsupported DNS label type".to_string());
        }
        let start = position + 1;
        let end = start + usize::from(length);
        if end > bytes.len() {
            return Err("truncated DNS label".to_string());
        }
        labels.push(String::from_utf8_lossy(&bytes[start..end]).into_owned());
        position = end;
    }

    Ok(labels.join("."))
}

fn random_byte() -> u8 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u8(0);
    hasher.finish() as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn follows_a_cname_chain_to_its_addresses() {
        // Captured from a recursive resolver on 2026-10-25, query stun.ekiga.net A.
        let bytes = unhex(concat!(
            "a1ea81800001000500000000047374756e05656b696761036e65740000010001",
            "c00c00050001000141790016047374756e0b636f756e7465727061746803636f6d00",
            "c02c000500010000011c000603777777c031",
            "c04e000500010000011c0002c031",
            "c03100010001000000ae00048dc1d515",
            "c03100010001000000ae00048dc1d514"
        ));
        let lookup = parse_response(&bytes, 0xA1EA).unwrap();
        assert_eq!(lookup.rcode, Some(Rcode::NoError));
        assert_eq!(
            lookup.cnames,
            vec![
                "stun.counterpath.com".to_string(),
                "www.counterpath.com".to_string(),
                "counterpath.com".to_string(),
            ]
        );
        assert_eq!(
            lookup.a,
            vec![
                Ipv4Addr::new(141, 193, 213, 21),
                Ipv4Addr::new(141, 193, 213, 20)
            ]
        );
    }

    #[test]
    fn reads_nxdomain_as_an_answer_not_a_failure() {
        // Captured on 2026-10-25, query stun.stunprotocol.org A.
        let bytes = unhex(concat!(
            "c57581830001000000000000047374756e0c7374756e70726f746f636f6c",
            "036f72670000010001"
        ));
        let lookup = parse_response(&bytes, 0xC575).unwrap();
        assert_eq!(lookup.rcode, Some(Rcode::NameError));
        assert!(lookup.is_empty());
    }

    #[test]
    fn reads_an_address_behind_a_compression_pointer() {
        // Captured on 2026-10-25, query stun.cloudflare.com A.
        let bytes = unhex(concat!(
            "424381800001000100000000047374756e0a636c6f7564666c61726503636f6d",
            "0000010001c00c000100010000a7a80004a29fcf00"
        ));
        let lookup = parse_response(&bytes, 0x4243).unwrap();
        assert_eq!(lookup.rcode, Some(Rcode::NoError));
        assert_eq!(lookup.a, vec![Ipv4Addr::new(162, 159, 207, 0)]);
    }

    #[test]
    fn ignores_a_response_with_another_id() {
        let bytes = unhex("424381800001000100000000047374756e0a636c6f7564666c61726503636f6d0000010001c00c000100010000a7a80004a29fcf00");
        assert!(parse_response(&bytes, 0x4244).is_err());
    }

    #[test]
    fn builds_a_query_for_the_name_in_the_list() {
        let packet = build_query(0x1234, "stun.example.org", TYPE_A).unwrap();
        assert_eq!(&packet[0..2], &[0x12, 0x34]);
        assert_eq!(&packet[4..6], &[0x00, 0x01]);
        assert_eq!(&packet[12..30], b"\x04stun\x07example\x03org\x00");
        assert_eq!(&packet[30..32], &[0x00, 0x01]);
        assert_eq!(&packet[32..34], &[0x00, 0x01]);
    }
}
