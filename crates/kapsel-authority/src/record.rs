//! Private fixed-order record framing for grants and receipt trust.

#[derive(Clone, Copy, Debug)]
pub(super) enum FrameError {
    Length,
    LengthConversion,
    Header,
    HeaderConversion,
    Order,
}

pub(super) fn push(
    output: &mut Vec<u8>,
    tag: u8,
    value: &[u8],
    maximum_bytes: usize,
) -> Result<(), FrameError> {
    let length = u32::try_from(value.len()).map_err(|_| FrameError::Length)?;
    if output
        .len()
        .checked_add(5)
        .and_then(|length| length.checked_add(value.len()))
        .is_none_or(|length| length > maximum_bytes)
    {
        return Err(FrameError::Length);
    }
    output.push(tag);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

#[derive(Debug)]
pub(super) struct Records<'a> {
    bytes: &'a [u8],
    offset: usize,
    next_tag: u8,
}

impl<'a> Records<'a> {
    pub(super) fn new(bytes: &'a [u8], magic: &[u8]) -> Result<Self, FrameError> {
        if !bytes.starts_with(magic) {
            return Err(FrameError::Header);
        }
        Ok(Self {
            bytes,
            offset: magic.len(),
            next_tag: 1,
        })
    }

    pub(super) fn take(&mut self, expected_tag: u8) -> Result<&'a [u8], FrameError> {
        if expected_tag != self.next_tag {
            return Err(FrameError::Order);
        }
        let header_end = self.offset.checked_add(5).ok_or(FrameError::Length)?;
        if header_end > self.bytes.len() || self.bytes[self.offset] != expected_tag {
            return Err(FrameError::Header);
        }
        let length = u32::from_be_bytes(
            self.bytes[self.offset + 1..header_end]
                .try_into()
                .map_err(|_| FrameError::HeaderConversion)?,
        );
        let length = usize::try_from(length).map_err(|_| FrameError::LengthConversion)?;
        let value_end = header_end.checked_add(length).ok_or(FrameError::Length)?;
        if value_end > self.bytes.len() {
            return Err(FrameError::Header);
        }
        self.offset = value_end;
        self.next_tag = self.next_tag.checked_add(1).ok_or(FrameError::Order)?;
        Ok(&self.bytes[header_end..value_end])
    }

    pub(super) fn finish(self) -> Result<(), FrameError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(FrameError::Header)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_rejects_incomplete_and_out_of_order_records() {
        let magic = b"MAGIC\0";
        let mut bytes = magic.to_vec();
        push(&mut bytes, 1, b"a", 12).unwrap();
        assert_eq!(bytes.len(), 12);
        assert!(matches!(
            push(&mut bytes, 2, b"b", 12),
            Err(FrameError::Length)
        ));
        let mut records = Records::new(&bytes, magic).unwrap();
        assert!(matches!(records.take(2), Err(FrameError::Order)));
        assert_eq!(records.take(1).unwrap(), b"a");
        assert!(records.finish().is_ok());

        for truncated in [magic.len() + 1, magic.len() + 4, bytes.len() - 1] {
            let mut records = Records::new(&bytes[..truncated], magic).unwrap();
            assert!(matches!(records.take(1), Err(FrameError::Header)));
        }
        let mut oversized = bytes.clone();
        oversized[magic.len() + 1..magic.len() + 5].copy_from_slice(&u32::MAX.to_be_bytes());
        let mut records = Records::new(&oversized, magic).unwrap();
        assert!(matches!(records.take(1), Err(FrameError::Header)));
        assert!(matches!(
            Records::new(&bytes, b"WRONG"),
            Err(FrameError::Header)
        ));
        let mut trailing = bytes.clone();
        trailing.push(0);
        let mut records = Records::new(&trailing, magic).unwrap();
        records.take(1).unwrap();
        assert!(matches!(records.finish(), Err(FrameError::Header)));
    }
}
