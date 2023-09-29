use std::collections::HashMap;
use std::io::Error;
use crate::pman::id_value_map::ByteValue;

pub struct HeaderEntity {
    // map property name id (in names file) -> property value id (in passwords file)
    history: Vec<HashMap<u32, u32>>
}

impl ByteValue for HeaderEntity {
    fn from_bytes(source: Vec<u8>) -> Result<Box<HeaderEntity>, Error> {
        todo!()
    }

    fn to_bytes(&self) -> Vec<u8> {
        todo!()
    }
}

impl HeaderEntity {
    pub fn new(properties: HashMap<u32, u32>) -> HeaderEntity {
        HeaderEntity{history: vec![properties]}
    }

    pub fn update(&mut self, properties: HashMap<u32, u32>) {
        self.history.push(properties);
    }
}