//! The smallest JSON reader and writer this checker needs.
//!
//! The server lists are JSON, and `turn.json` may hold credentialed objects as
//! well as strings, so the reader understands both. The writer is hand-rolled
//! for the report: one serialisation crate for one document would cost more
//! than it saves in a tool that deliberately has no dependencies.

use std::fmt::Write as _;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(fields) => fields
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(text) => Some(text),
            _ => None,
        }
    }
}

pub fn parse(input: &str) -> Result<Value, String> {
    let mut parser = Parser {
        bytes: input.as_bytes(),
        offset: 0,
    };
    let value = parser.value()?;
    parser.whitespace();
    if parser.offset != parser.bytes.len() {
        return Err(format!("trailing content at byte {}", parser.offset));
    }
    Ok(value)
}

pub fn quote(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 2);
    out.push('"');
    for character in input.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            character if (character as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", character as u32);
            }
            character => out.push(character),
        }
    }
    out.push('"');
    out
}

struct Parser<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Parser<'a> {
    fn whitespace(&mut self) {
        while let Some(byte) = self.bytes.get(self.offset) {
            if matches!(byte, b' ' | b'\t' | b'\n' | b'\r') {
                self.offset += 1;
            } else {
                break;
            }
        }
    }

    fn value(&mut self) -> Result<Value, String> {
        self.whitespace();
        match self.bytes.get(self.offset) {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b't') => {
                self.literal("true")?;
                Ok(Value::Bool(true))
            }
            Some(b'f') => {
                self.literal("false")?;
                Ok(Value::Bool(false))
            }
            Some(b'n') => {
                self.literal("null")?;
                Ok(Value::Null)
            }
            Some(byte) if *byte == b'-' || byte.is_ascii_digit() => self.number(),
            Some(_) => Err(format!("unexpected byte at {}", self.offset)),
            None => Err("unexpected end of input".to_string()),
        }
    }

    fn literal(&mut self, expected: &str) -> Result<(), String> {
        if self.bytes[self.offset..].starts_with(expected.as_bytes()) {
            self.offset += expected.len();
            Ok(())
        } else {
            Err(format!("expected {expected} at byte {}", self.offset))
        }
    }

    fn string(&mut self) -> Result<String, String> {
        if self.bytes.get(self.offset) != Some(&b'"') {
            return Err(format!("expected a string at byte {}", self.offset));
        }
        self.offset += 1;
        let mut out = String::new();
        loop {
            let byte = *self
                .bytes
                .get(self.offset)
                .ok_or_else(|| "unterminated string".to_string())?;
            match byte {
                b'"' => {
                    self.offset += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.offset += 1;
                    let escape = *self
                        .bytes
                        .get(self.offset)
                        .ok_or_else(|| "unterminated escape".to_string())?;
                    self.offset += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.unicode_escape()?),
                        other => return Err(format!("unknown escape \\{}", other as char)),
                    }
                }
                _ => {
                    let rest = std::str::from_utf8(&self.bytes[self.offset..])
                        .map_err(|_| format!("invalid UTF-8 at byte {}", self.offset))?;
                    let character = rest
                        .chars()
                        .next()
                        .ok_or_else(|| "unterminated string".to_string())?;
                    out.push(character);
                    self.offset += character.len_utf8();
                }
            }
        }
    }

    fn unicode_escape(&mut self) -> Result<char, String> {
        let first = self.hex4()?;
        if (0xD800..0xDC00).contains(&first) {
            if !self.bytes[self.offset..].starts_with(b"\\u") {
                return Err("lone high surrogate".to_string());
            }
            self.offset += 2;
            let second = self.hex4()?;
            if !(0xDC00..0xE000).contains(&second) {
                return Err("bad low surrogate".to_string());
            }
            let combined = 0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00);
            return char::from_u32(combined).ok_or_else(|| "invalid code point".to_string());
        }
        char::from_u32(first).ok_or_else(|| "invalid code point".to_string())
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let end = self.offset + 4;
        if end > self.bytes.len() {
            return Err("truncated \\u escape".to_string());
        }
        let text = std::str::from_utf8(&self.bytes[self.offset..end])
            .map_err(|_| "invalid \\u escape".to_string())?;
        let value = u32::from_str_radix(text, 16).map_err(|_| "invalid \\u escape".to_string())?;
        self.offset = end;
        Ok(value)
    }

    fn number(&mut self) -> Result<Value, String> {
        let start = self.offset;
        if self.bytes.get(self.offset) == Some(&b'-') {
            self.offset += 1;
        }
        while let Some(byte) = self.bytes.get(self.offset) {
            if byte.is_ascii_digit() || matches!(byte, b'.' | b'e' | b'E' | b'+' | b'-') {
                self.offset += 1;
            } else {
                break;
            }
        }
        let text = std::str::from_utf8(&self.bytes[start..self.offset])
            .map_err(|_| "invalid number".to_string())?;
        text.parse::<f64>()
            .map(Value::Number)
            .map_err(|_| format!("invalid number {text}"))
    }

    fn array(&mut self) -> Result<Value, String> {
        self.offset += 1;
        let mut items = Vec::new();
        self.whitespace();
        if self.bytes.get(self.offset) == Some(&b']') {
            self.offset += 1;
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.value()?);
            self.whitespace();
            match self.bytes.get(self.offset) {
                Some(b',') => self.offset += 1,
                Some(b']') => {
                    self.offset += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(format!("expected ',' or ']' at byte {}", self.offset)),
            }
        }
    }

    fn object(&mut self) -> Result<Value, String> {
        self.offset += 1;
        let mut fields = Vec::new();
        self.whitespace();
        if self.bytes.get(self.offset) == Some(&b'}') {
            self.offset += 1;
            return Ok(Value::Object(fields));
        }
        loop {
            self.whitespace();
            let key = self.string()?;
            self.whitespace();
            if self.bytes.get(self.offset) != Some(&b':') {
                return Err(format!("expected ':' at byte {}", self.offset));
            }
            self.offset += 1;
            fields.push((key, self.value()?));
            self.whitespace();
            match self.bytes.get(self.offset) {
                Some(b',') => self.offset += 1,
                Some(b'}') => {
                    self.offset += 1;
                    return Ok(Value::Object(fields));
                }
                _ => return Err(format!("expected ',' or '}}' at byte {}", self.offset)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_server_list() {
        let value = parse(r#"["stun.example.org:3478", "stun.other.org"]"#).unwrap();
        assert_eq!(
            value,
            Value::Array(vec![
                Value::String("stun.example.org:3478".to_string()),
                Value::String("stun.other.org".to_string()),
            ])
        );
    }

    #[test]
    fn reads_a_turn_object() {
        let value = parse(
            r#"[{"urls": ["turn:one.example:3478?transport=udp"], "username": "u", "credential": "p"}]"#,
        )
        .unwrap();
        let Value::Array(items) = value else {
            panic!("expected an array");
        };
        assert_eq!(items[0].get("username").and_then(Value::as_str), Some("u"));
    }

    #[test]
    fn rejects_trailing_content() {
        assert!(parse("[] []").is_err());
    }

    #[test]
    fn reads_escapes() {
        assert_eq!(
            parse(r#""a\"b\\c\u0041""#).unwrap(),
            Value::String("a\"b\\cA".to_string())
        );
    }

    #[test]
    fn quotes_what_it_parses() {
        let original = "stun.example.org\t\"odd\"";
        let quoted = quote(original);
        assert_eq!(parse(&quoted).unwrap(), Value::String(original.to_string()));
    }
}
