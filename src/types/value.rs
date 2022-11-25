use anyhow::{anyhow, bail};
use std::convert::TryFrom;
use std::fmt;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum SimpleworksValueType {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    Address([u8; 63]),
    Record([u8; 63], u64),
}

impl TryFrom<&String> for SimpleworksValueType {
    type Error = anyhow::Error;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        if value.ends_with("u8") {
            let v = value.trim_end_matches("u8");
            let value_int = v.parse::<u8>().map_err(|e| anyhow!("{}", e))?;
            return Ok(SimpleworksValueType::U8(value_int));
        } else if value.ends_with("u16") {
            let v = value.trim_end_matches("u16");
            let value_int = v.parse::<u16>().map_err(|e| anyhow!("{}", e))?;
            return Ok(SimpleworksValueType::U16(value_int));
        } else if value.ends_with("u32") {
            let v = value.trim_end_matches("u32");
            let value_int = v.parse::<u32>().map_err(|e| anyhow!("{}", e))?;
            return Ok(SimpleworksValueType::U32(value_int));
        } else if value.ends_with("u64") {
            let v = value.trim_end_matches("u64");
            let value_int = v.parse::<u64>().map_err(|e| anyhow!("{}", e))?;
            return Ok(SimpleworksValueType::U64(value_int));
        } else if value.ends_with("u128") {
            let v = value.trim_end_matches("u128");
            let value_int = v.parse::<u128>().map_err(|e| anyhow!("{}", e))?;
            return Ok(SimpleworksValueType::U128(value_int));
        } else if value.starts_with("aleo1") {
            let v = value.trim_start_matches("aleo1");
            let mut address = [0_u8; 63];
            for (sender_address_byte, address_string_byte) in address.iter_mut().zip(v.as_bytes()) {
                *sender_address_byte = *address_string_byte;
            }
            return Ok(SimpleworksValueType::Address(address));
        }
        bail!("Unknown type")
    }
}

impl fmt::Display for SimpleworksValueType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SimpleworksValueType::U8(v) => write!(f, "{v}u8"),
            SimpleworksValueType::U16(v) => write!(f, "{v}u16"),
            SimpleworksValueType::U32(v) => write!(f, "{v}u32"),
            SimpleworksValueType::U64(v) => write!(f, "{v}u64"),
            SimpleworksValueType::U128(v) => write!(f, "{v}u128"),
            SimpleworksValueType::Address(v) => write!(f, "{:?}", v),
            SimpleworksValueType::Record(o, g) => write!(f, "Record {{ owner: {:?}, gates: {} }}", o, g)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SimpleworksValueType;

    #[test]
    fn display_value() {
        let v = SimpleworksValueType::U8(2);
        let out = format!("{v}");
        assert_eq!(out, "2u8");
        let v = SimpleworksValueType::U16(3);
        let out = format!("{v}");
        assert_eq!(out, "3u16");
        let v = SimpleworksValueType::U32(4);
        let out = format!("{v}");
        assert_eq!(out, "4u32");
        let v = SimpleworksValueType::U64(5);
        let out = format!("{v}");
        assert_eq!(out, "5u64");
        let v = SimpleworksValueType::U128(6);
        let out = format!("{v}");
        assert_eq!(out, "6u128");
        // Address
        let mut address = [0_u8; 63];
        let address_str = "aleo1ecw94zggphqkpdsjhfjutr9p33nn9tk2d34tz23t29awtejupugq4vne6m";
        for (sender_address_byte, address_string_byte) in
            address.iter_mut().zip(address_str.as_bytes())
        {
            *sender_address_byte = *address_string_byte;
        }
        let v = SimpleworksValueType::Address(address);
        let out = format!("{v}");
        assert_eq!(out, format!("{:?}", address));
        // Record
        let mut address = [0_u8; 63];
        let address_str = "aleo1ecw94zggphqkpdsjhfjutr9p33nn9tk2d34tz23t29awtejupugq4vne6m";
        for (sender_address_byte, address_string_byte) in
            address.iter_mut().zip(address_str.as_bytes())
        {
            *sender_address_byte = *address_string_byte;
        }
        let gates = 1_u64;
        let v = SimpleworksValueType::Record(address, gates);
        let out = format!("{v}");
        assert_eq!(out, format!("Record {{ owner: {:?}, gates: {} }}", address, gates));
    }
}
