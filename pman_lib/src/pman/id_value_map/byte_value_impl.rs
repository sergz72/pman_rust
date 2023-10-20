use std::io::{Error, ErrorKind};
use crate::error_builders::build_corrupted_data_error;
use crate::pman::id_value_map::id_value_map::ByteValue;

impl ByteValue for Vec<u8> {
    fn from_bytes(source: Vec<u8>) -> Result<Box<Vec<u8>>, Error> {
        Ok(Box::new(source))
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.clone()
    }
}

impl ByteValue for String {
    fn from_bytes(source: Vec<u8>) -> Result<Box<String>, Error> {
        String::from_utf8(source)
            .map(|v|Box::new(v))
            .map_err(|e|Error::new(ErrorKind::InvalidData, e.to_string()))
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl ByteValue for Vec<u32> {
    fn from_bytes(source: Vec<u8>) -> Result<Box<Vec<u32>>, Error> {
        if source.len() % 4 != 0 {
            return Err(build_corrupted_data_error())
        }
        let mut buffer32 = [0u8; 4];
        let mut result = Vec::new();
        for idx in (0..source.len()).step_by(4) {
            buffer32.copy_from_slice(&source[idx..idx+4]);
            let v = u32::from_le_bytes(buffer32);
            result.push(v);
        }
        Ok(Box::new(result))
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        for v in self {
            let buffer = v.to_le_bytes();
            result.extend_from_slice(&buffer);
        }
        result
    }
}
