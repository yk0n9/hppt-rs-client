use anyhow::{Result, bail};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionBytes {
    pub session_id: i32,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Message {
    pub sessions: Vec<SessionBytes>,
    pub commands: Vec<String>,
}

pub fn encode_bytes_list(bytes: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for item in bytes {
        put_bytes(1, item, &mut out);
    }
    out
}

pub fn decode_bytes_list(input: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut fields = Fields::new(input);
    let mut result = Vec::new();
    while let Some((number, wire)) = fields.next_tag()? {
        match (number, wire) {
            (1, 2) => result.push(fields.read_bytes()?.to_vec()),
            _ => fields.skip(wire)?,
        }
    }
    Ok(result)
}

pub fn encode_message(message: &Message) -> Vec<u8> {
    let mut out = Vec::new();
    for session in &message.sessions {
        let mut encoded = Vec::new();
        put_bytes(1, &session.bytes, &mut encoded);
        if session.session_id != 0 {
            put_varint((2 << 3) as u64, &mut encoded);
            put_varint(session.session_id as i64 as u64, &mut encoded);
        }
        put_bytes(1, &encoded, &mut out);
    }
    for command in &message.commands {
        put_bytes(2, command.as_bytes(), &mut out);
    }
    out
}

pub fn decode_message(input: &[u8]) -> Result<Message> {
    let mut fields = Fields::new(input);
    let mut message = Message::default();
    while let Some((number, wire)) = fields.next_tag()? {
        match (number, wire) {
            (1, 2) => message.sessions.push(decode_session(fields.read_bytes()?)?),
            (2, 2) => message
                .commands
                .push(std::str::from_utf8(fields.read_bytes()?)?.to_owned()),
            _ => fields.skip(wire)?,
        }
    }
    Ok(message)
}

fn decode_session(input: &[u8]) -> Result<SessionBytes> {
    let mut fields = Fields::new(input);
    let mut session = SessionBytes {
        session_id: 0,
        bytes: Vec::new(),
    };
    while let Some((number, wire)) = fields.next_tag()? {
        match (number, wire) {
            (1, 2) => session.bytes = fields.read_bytes()?.to_vec(),
            (2, 0) => session.session_id = fields.read_varint()? as i32,
            _ => fields.skip(wire)?,
        }
    }
    Ok(session)
}

fn put_bytes(field: u64, bytes: &[u8], out: &mut Vec<u8>) {
    put_varint((field << 3) | 2, out);
    put_varint(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}

fn put_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

struct Fields<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Fields<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn next_tag(&mut self) -> Result<Option<(u64, u8)>> {
        if self.offset == self.input.len() {
            return Ok(None);
        }
        let tag = self.read_varint()?;
        if tag >> 3 == 0 {
            bail!("protobuf field number cannot be zero");
        }
        Ok(Some((tag >> 3, (tag & 7) as u8)))
    }

    fn read_varint(&mut self) -> Result<u64> {
        let mut value = 0_u64;
        for shift in (0..70).step_by(7) {
            let byte = *self
                .input
                .get(self.offset)
                .ok_or_else(|| anyhow::anyhow!("truncated protobuf varint"))?;
            self.offset += 1;
            if shift == 63 && byte > 1 {
                bail!("protobuf varint overflow");
            }
            value |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        bail!("protobuf varint overflow")
    }

    fn read_bytes(&mut self) -> Result<&'a [u8]> {
        let length = usize::try_from(self.read_varint()?)?;
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| anyhow::anyhow!("protobuf length overflow"))?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or_else(|| anyhow::anyhow!("truncated protobuf bytes field"))?;
        self.offset = end;
        Ok(bytes)
    }

    fn skip(&mut self, wire: u8) -> Result<()> {
        match wire {
            0 => {
                self.read_varint()?;
            }
            1 => self.advance(8)?,
            2 => {
                self.read_bytes()?;
            }
            5 => self.advance(4)?,
            _ => bail!("unsupported protobuf wire type {wire}"),
        }
        Ok(())
    }

    fn advance(&mut self, count: usize) -> Result<()> {
        self.offset = self
            .offset
            .checked_add(count)
            .filter(|end| *end <= self.input.len())
            .ok_or_else(|| anyhow::anyhow!("truncated protobuf fixed-width field"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_encoding_matches_protobuf_wire_format() {
        let message = Message {
            sessions: vec![SessionBytes {
                session_id: 150,
                bytes: vec![0xaa, 0xbb],
            }],
            commands: vec!["03:123".to_owned()],
        };
        let expected = [
            0x0a, 0x07, 0x0a, 0x02, 0xaa, 0xbb, 0x10, 0x96, 0x01, 0x12, 0x06, b'0', b'3', b':',
            b'1', b'2', b'3',
        ];
        assert_eq!(encode_message(&message), expected);
        assert_eq!(decode_message(&expected).unwrap(), message);
    }

    #[test]
    fn bytes_list_matches_java_wrapper() {
        let encoded = encode_bytes_list(&[vec![1, 2], vec![3]]);
        assert_eq!(encoded, [0x0a, 0x02, 1, 2, 0x0a, 0x01, 3]);
        assert_eq!(decode_bytes_list(&encoded).unwrap(), [vec![1, 2], vec![3]]);
    }
}
