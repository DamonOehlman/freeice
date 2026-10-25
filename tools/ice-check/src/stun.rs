//! RFC 5389 messages, and the RFC 5766 Allocate request used to prove a TURN
//! server is alive without credentials.

use std::collections::hash_map::RandomState;
use std::fmt;
use std::hash::{BuildHasher, Hasher};
use std::net::{Ipv4Addr, Ipv6Addr};

use hmac::{Hmac, KeyInit, Mac};
use md5::{Digest, Md5};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

pub const MAGIC: u32 = 0x2112_A442;

const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_USERNAME: u16 = 0x0006;
const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
const ATTR_ERROR_CODE: u16 = 0x0009;
const ATTR_REALM: u16 = 0x0014;
const ATTR_NONCE: u16 = 0x0015;
const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_SOFTWARE: u16 = 0x8022;

const REQUESTED_TRANSPORT_UDP: u32 = 17 << 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Binding,
    Allocate,
}

impl Kind {
    fn request_type(self) -> u16 {
        match self {
            Kind::Binding => 0x0001,
            Kind::Allocate => 0x0003,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Kind::Binding => "stun",
            Kind::Allocate => "turn",
        }
    }
}

#[derive(Debug)]
pub struct Request {
    pub bytes: Vec<u8>,
    pub transaction_id: [u8; 12],
}

#[derive(Debug)]
pub struct Attribute<'a> {
    pub kind: u16,
    pub value: &'a [u8],
}

#[derive(Debug)]
pub struct Message<'a> {
    pub message_type: u16,
    pub transaction_id: [u8; 12],
    pub attributes: Vec<Attribute<'a>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    TooShort,
    BadCookie,
    TruncatedAttribute,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::TooShort => formatter.write_str("shorter than a STUN header"),
            DecodeError::BadCookie => formatter.write_str("magic cookie missing"),
            DecodeError::TruncatedAttribute => formatter.write_str("truncated attribute"),
        }
    }
}

pub fn request(kind: Kind) -> Request {
    let transaction_id = random_transaction_id();
    let mut attributes = Vec::new();
    if kind == Kind::Allocate {
        // REQUESTED-TRANSPORT: 17 (UDP) in the first octet.
        attributes.extend_from_slice(&ATTR_REQUESTED_TRANSPORT.to_be_bytes());
        attributes.extend_from_slice(&4u16.to_be_bytes());
        attributes.extend_from_slice(&REQUESTED_TRANSPORT_UDP.to_be_bytes());
    }

    let mut bytes = Vec::with_capacity(20 + attributes.len());
    bytes.extend_from_slice(&kind.request_type().to_be_bytes());
    bytes.extend_from_slice(&(attributes.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&MAGIC.to_be_bytes());
    bytes.extend_from_slice(&transaction_id);
    bytes.extend_from_slice(&attributes);

    Request {
        bytes,
        transaction_id,
    }
}

pub fn decode(bytes: &[u8]) -> Result<Message<'_>, DecodeError> {
    if bytes.len() < 20 {
        return Err(DecodeError::TooShort);
    }
    let message_type = u16::from_be_bytes([bytes[0], bytes[1]]);
    let length = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    let cookie = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if cookie != MAGIC {
        return Err(DecodeError::BadCookie);
    }

    let mut transaction_id = [0u8; 12];
    transaction_id.copy_from_slice(&bytes[8..20]);

    let end = 20 + length;
    if end > bytes.len() {
        return Err(DecodeError::TruncatedAttribute);
    }

    let body = &bytes[20..end];
    let mut attributes = Vec::new();
    let mut offset = 0;
    while offset + 4 <= body.len() {
        let kind = u16::from_be_bytes([body[offset], body[offset + 1]]);
        let value_length = u16::from_be_bytes([body[offset + 2], body[offset + 3]]) as usize;
        let start = offset + 4;
        let finish = start + value_length;
        if finish > body.len() {
            return Err(DecodeError::TruncatedAttribute);
        }
        attributes.push(Attribute {
            kind,
            value: &body[start..finish],
        });
        offset = finish + ((4 - value_length % 4) % 4);
    }

    Ok(Message {
        message_type,
        transaction_id,
        attributes,
    })
}

/// The message class: 0 request, 1 indication, 2 success, 3 error.
pub fn class(message_type: u16) -> u8 {
    (((message_type >> 4) & 1) | ((message_type >> 7) & 2)) as u8
}

pub struct Challenge {
    pub realm: String,
    pub nonce: String,
}

pub fn challenge(message: &Message<'_>) -> Option<Challenge> {
    Some(Challenge {
        realm: string_attribute(message, ATTR_REALM)?,
        nonce: string_attribute(message, ATTR_NONCE)?,
    })
}

/// A TURN Allocate authenticated with long-term credentials (RFC 5389 section
/// 15.4): MD5 over `username:realm:password` keys an HMAC-SHA1 over the message
/// so far, with the header length already counting the attribute being added.
pub fn authenticated_allocate(challenge: &Challenge, username: &str, password: &str) -> Request {
    let transaction_id = random_transaction_id();

    let mut attributes = Vec::new();
    attributes.extend_from_slice(&ATTR_REQUESTED_TRANSPORT.to_be_bytes());
    attributes.extend_from_slice(&4u16.to_be_bytes());
    attributes.extend_from_slice(&REQUESTED_TRANSPORT_UDP.to_be_bytes());
    push_string(&mut attributes, ATTR_USERNAME, username);
    push_string(&mut attributes, ATTR_REALM, &challenge.realm);
    push_string(&mut attributes, ATTR_NONCE, &challenge.nonce);

    // MESSAGE-INTEGRITY is 4 bytes of header and 20 of value, and the length
    // field must already include it when the digest is computed.
    let length = attributes.len() + 24;
    let mut bytes = Vec::with_capacity(20 + length);
    bytes.extend_from_slice(&Kind::Allocate.request_type().to_be_bytes());
    bytes.extend_from_slice(&(length as u16).to_be_bytes());
    bytes.extend_from_slice(&MAGIC.to_be_bytes());
    bytes.extend_from_slice(&transaction_id);
    bytes.extend_from_slice(&attributes);

    let integrity = message_integrity(username, &challenge.realm, password, &bytes);
    bytes.extend_from_slice(&ATTR_MESSAGE_INTEGRITY.to_be_bytes());
    bytes.extend_from_slice(&20u16.to_be_bytes());
    bytes.extend_from_slice(&integrity);

    Request {
        bytes,
        transaction_id,
    }
}

pub fn message_integrity(username: &str, realm: &str, password: &str, message: &[u8]) -> [u8; 20] {
    let mut digest = Md5::new();
    digest.update(username.as_bytes());
    digest.update(b":");
    digest.update(realm.as_bytes());
    digest.update(b":");
    digest.update(password.as_bytes());
    let key = digest.finalize();

    let mut mac = HmacSha1::new_from_slice(&key).expect("HMAC accepts any key length");
    mac.update(message);
    let mut out = [0u8; 20];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

fn push_string(out: &mut Vec<u8>, kind: u16, value: &str) {
    let bytes = value.as_bytes();
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
    out.resize(out.len() + (4 - bytes.len() % 4) % 4, 0);
}

fn string_attribute(message: &Message<'_>, kind: u16) -> Option<String> {
    let attribute = message
        .attributes
        .iter()
        .find(|attribute| attribute.kind == kind)?;
    Some(String::from_utf8_lossy(attribute.value).into_owned())
}

pub fn relayed_address(message: &Message<'_>) -> Option<String> {
    for attribute in &message.attributes {
        let xored = match attribute.kind {
            ATTR_XOR_RELAYED_ADDRESS => true,
            ATTR_MAPPED_ADDRESS => false,
            _ => continue,
        };
        if let Some(address) = decode_address(attribute.value, xored, &message.transaction_id) {
            return Some(address);
        }
    }
    None
}

pub fn mapped_address(message: &Message<'_>) -> Option<String> {
    for attribute in &message.attributes {
        let xored = match attribute.kind {
            ATTR_XOR_MAPPED_ADDRESS => true,
            ATTR_MAPPED_ADDRESS => false,
            _ => continue,
        };
        if let Some(address) = decode_address(attribute.value, xored, &message.transaction_id) {
            return Some(address);
        }
    }
    None
}

pub fn error_code(message: &Message<'_>) -> Option<(u16, String)> {
    let attribute = message
        .attributes
        .iter()
        .find(|attribute| attribute.kind == ATTR_ERROR_CODE)?;
    if attribute.value.len() < 4 {
        return None;
    }
    let class = u16::from(attribute.value[2] & 0x07);
    let number = u16::from(attribute.value[3]);
    let reason = String::from_utf8_lossy(&attribute.value[4..]).into_owned();
    Some((class * 100 + number, reason))
}

pub fn software(message: &Message<'_>) -> Option<String> {
    let attribute = message
        .attributes
        .iter()
        .find(|attribute| attribute.kind == ATTR_SOFTWARE)?;
    Some(String::from_utf8_lossy(attribute.value).into_owned())
}

fn decode_address(value: &[u8], xored: bool, transaction_id: &[u8; 12]) -> Option<String> {
    if value.len() < 4 {
        return None;
    }
    let family = value[1];
    let mut port = u16::from_be_bytes([value[2], value[3]]);
    if xored {
        port ^= (MAGIC >> 16) as u16;
    }

    match family {
        0x01 if value.len() >= 8 => {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&value[4..8]);
            if xored {
                for (byte, key) in bytes.iter_mut().zip(MAGIC.to_be_bytes()) {
                    *byte ^= key;
                }
            }
            Some(format!("{}:{}", Ipv4Addr::from(bytes), port))
        }
        0x02 if value.len() >= 20 => {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&value[4..20]);
            if xored {
                for (byte, key) in bytes.iter_mut().zip(MAGIC.to_be_bytes()) {
                    *byte ^= key;
                }
                for (byte, key) in bytes[4..].iter_mut().zip(transaction_id) {
                    *byte ^= key;
                }
            }
            Some(format!("[{}]:{}", Ipv6Addr::from(bytes), port))
        }
        _ => None,
    }
}

/// A transaction id that is unique per request. RFC 5389 asks for random; what
/// matters here is that a stale reply cannot be mistaken for this one, and
/// `RandomState` is seeded from the OS without pulling in a random-number crate.
fn random_transaction_id() -> [u8; 12] {
    let mut out = [0u8; 12];
    let mut offset = 0;
    while offset < out.len() {
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_usize(offset);
        let value = hasher.finish().to_be_bytes();
        let take = (out.len() - offset).min(value.len());
        out[offset..offset + take].copy_from_slice(&value[..take]);
        offset += take;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_bits_follow_the_wire_format() {
        assert_eq!(class(0x0001), 0);
        assert_eq!(class(0x0101), 2);
        assert_eq!(class(0x0111), 3);
    }

    #[test]
    fn binding_request_has_a_header_and_no_attributes() {
        let request = request(Kind::Binding);
        assert_eq!(request.bytes.len(), 20);
        assert_eq!(&request.bytes[0..2], &[0x00, 0x01]);
        assert_eq!(&request.bytes[2..4], &[0x00, 0x00]);
        assert_eq!(&request.bytes[4..8], &MAGIC.to_be_bytes());
        assert_eq!(&request.bytes[8..20], &request.transaction_id);
    }

    #[test]
    fn allocate_request_asks_for_udp() {
        let request = request(Kind::Allocate);
        assert_eq!(&request.bytes[0..2], &[0x00, 0x03]);
        assert_eq!(&request.bytes[2..4], &[0x00, 0x08]);
        assert_eq!(&request.bytes[20..22], &[0x00, 0x19]);
        assert_eq!(&request.bytes[24..28], &[0x11, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn decodes_the_rfc5389_xor_mapped_address_example() {
        // RFC 5389 section 15.2: 192.0.2.1:32853.
        let transaction_id = [
            0xB7, 0xE7, 0xA7, 0x01, 0xBC, 0x34, 0xD6, 0x86, 0xFA, 0x87, 0xDF, 0xAE,
        ];
        let value = [0x00, 0x01, 0xA1, 0x47, 0xE1, 0x12, 0xA6, 0x43];
        assert_eq!(
            decode_address(&value, true, &transaction_id),
            Some("192.0.2.1:32853".to_string())
        );
    }

    #[test]
    fn decodes_a_plain_mapped_address() {
        let value = [0x00, 0x01, 0x1F, 0x90, 0xC0, 0x00, 0x02, 0x7F];
        assert_eq!(
            decode_address(&value, false, &[0u8; 12]),
            Some("192.0.2.127:8080".to_string())
        );
    }

    #[test]
    fn rejects_a_truncated_attribute() {
        let mut bytes = request(Kind::Binding).bytes;
        bytes[2..4].copy_from_slice(&8u16.to_be_bytes());
        bytes.extend_from_slice(&[0x00, 0x01, 0x00, 0x20]);
        assert!(matches!(
            decode(&bytes),
            Err(DecodeError::TruncatedAttribute)
        ));
    }

    #[test]
    fn rejects_a_message_without_the_cookie() {
        let mut bytes = request(Kind::Binding).bytes;
        bytes[4] = 0;
        assert!(matches!(decode(&bytes), Err(DecodeError::BadCookie)));
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn message_integrity_matches_a_cross_checked_vector() {
        // key = md5("user:realm:pass"), mac = hmac-sha1(key, "hello"), computed
        // independently with Python's hashlib and hmac.
        assert_eq!(
            hex(&message_integrity("user", "realm", "pass", b"hello")),
            "bcacc0e0d91a6a7b1a3a73dc7b1e2f76ed4c84b5"
        );
    }

    #[test]
    fn authenticated_allocate_counts_the_integrity_attribute() {
        let challenge = Challenge {
            realm: "example.org".to_string(),
            nonce: "nonce".to_string(),
        };
        let request = authenticated_allocate(&challenge, "user", "pass");
        let declared = u16::from_be_bytes([request.bytes[2], request.bytes[3]]) as usize;
        assert_eq!(declared, request.bytes.len() - 20);
        let tail = &request.bytes[request.bytes.len() - 24..];
        assert_eq!(&tail[0..2], &ATTR_MESSAGE_INTEGRITY.to_be_bytes());
        assert_eq!(&tail[2..4], &[0x00, 0x14]);
    }

    #[test]
    fn reads_the_realm_and_nonce_from_a_challenge() {
        let realm = b"example.org";
        let nonce = b"abcdef";
        let message = Message {
            message_type: 0x0113,
            transaction_id: [0u8; 12],
            attributes: vec![
                Attribute {
                    kind: ATTR_REALM,
                    value: realm,
                },
                Attribute {
                    kind: ATTR_NONCE,
                    value: nonce,
                },
            ],
        };
        let challenge = challenge(&message).unwrap();
        assert_eq!(challenge.realm, "example.org");
        assert_eq!(challenge.nonce, "abcdef");
    }

    #[test]
    fn reads_the_error_code_as_class_times_a_hundred() {
        let mut value = vec![0x00, 0x00, 0x04, 0x01];
        value.extend_from_slice(b"Unauthorized");
        let message = Message {
            message_type: 0x0111,
            transaction_id: [0u8; 12],
            attributes: vec![Attribute {
                kind: ATTR_ERROR_CODE,
                value: &value,
            }],
        };
        assert_eq!(
            error_code(&message),
            Some((401, "Unauthorized".to_string()))
        );
    }
}
