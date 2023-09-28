use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use rand::RngCore;
use rand::rngs::OsRng;
use uniffi::deps::bytes::BufMut;
use crate::pman::crypto::CryptoProcessor;

const ENCODED_SIZE: usize = 64;
const MAX_LENGTH: usize = ENCODED_SIZE - 2;

const CORRUPTED_DATA_ERROR: Error = Error::new(ErrorKind::InvalidData, "corrupted data");

type Encoded = [u8;ENCODED_SIZE];

pub struct IdNameMap {
    next_id: u32,
    map: HashMap<u32, Encoded>,
    processor: Box<dyn CryptoProcessor>
}

impl IdNameMap {
    pub fn new(processor: Box<dyn CryptoProcessor>) -> IdNameMap {
        IdNameMap{next_id: 1, map: HashMap::new(), processor}
    }

    pub fn add(&mut self, value: String) -> Result<(), Error> {
        let v = self.build_value(value)?;
        self.map.insert(self.next_id, v);
        self.next_id += 1;
        Ok(())
    }

    pub fn set(&mut self, id: u32, value: String) -> Result<(), Error> {
        self.exists(id)?;
        let v = self.build_value(value)?;
        self.map.insert(id, v);
        Ok(())
    }

    pub fn remove(&mut self, id: u32) -> Result<(), Error> {
        self.exists(id)?;
        self.map.remove(&id);
        Ok(())
    }

    fn exists(&self, id: u32) -> Result<(), Error> {
        if !self.map.contains_key(&id) {
            return Err(Error::new(ErrorKind::InvalidInput, "not found"));
        }
        Ok(())
    }

    pub fn get(&self, id: u32) -> Result<String, Error> {
        self.exists(id)?;
        let v = self.map.get(&id).unwrap();
        self.decode_value(v)
    }

    fn build_value(&self, value: String) -> Result<Encoded, Error> {
        let bytes = value.as_bytes();
        let l = bytes.len();
        if value.len() > MAX_LENGTH {
            return Err(Error::new(ErrorKind::InvalidInput, "string is too long"))
        }
        let mut v = [0u8;ENCODED_SIZE];
        OsRng.fill_bytes(&mut v);
        let mut idx = 0;
        v[idx] = l as u8;
        idx += 1;
        while idx <= l {
            v[idx] = bytes[idx-1];
            idx += 1;
        }
        Ok(self.processor.encode(v))
    }

    fn decode_value(&self, value: &Encoded) -> Result<String, Error> {
        let v = self.processor.decode(value);
        let l = v[0] as usize;
        if l > MAX_LENGTH {
            return Err(CORRUPTED_DATA_ERROR);
        }
        String::from_utf8(v[1..l+1].iter().map(|e|*e).collect())
            .map_err(|e|Error::new(ErrorKind::InvalidData, e.to_string()))
    }

    pub fn save(&self, output: &mut Vec<u8>) {
        output.put_u32_le(self.map.len() as u32);
        for (key, value) in &self.map {
            output.put_u32_le(*key);
            output.put_slice(value);
        }
    }

    pub fn load(&mut self, source: &Vec<u8>, offset: usize) -> Result<(), Error> {
        if !self.map.is_empty() {
            return Err(Error::new(ErrorKind::PermissionDenied, "map is not empty"))
        }
        let sl = source.len();
        if offset + 4 > sl {
            return Err(CORRUPTED_DATA_ERROR);
        }
        let mut buffer32 = [0u8; 4];
        let mut encoded = [0u8; ENCODED_SIZE];
        let s = source.as_slice();
        let mut idx = offset;
        buffer32.copy_from_slice(&s[idx..idx + 4]);
        let l = u32::from_le_bytes(buffer32);
        idx += 4;
        while l > 0 {
            if idx + 4 + ENCODED_SIZE > sl {
                return Err(CORRUPTED_DATA_ERROR);
            }
            buffer32.copy_from_slice(&s[idx..idx + 4]);
            let key = u32::from_le_bytes(buffer32);
            if self.map.contains_key(&key) {
                return Err(CORRUPTED_DATA_ERROR);
            }
            if key >= self.next_id {
                self.next_id = key + 1;
            }
            idx += 4;
            encoded.copy_from_slice(&s[idx..idx + ENCODED_SIZE])
            idx += ENCODED_SIZE;
            self.map.insert(key, encoded);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::pman::id_name_map::IdNameMap;

    #[test]
    fn test_id_name_map() {
        let mut map = IdNameMap::new();
    }
}