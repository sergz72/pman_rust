use std::io::{Error, ErrorKind};
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
