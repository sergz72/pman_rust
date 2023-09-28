use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use rand::RngCore;
use rand::rngs::OsRng;
use uniffi::deps::bytes::BufMut;
use crate::crypto::CryptoProcessor;

const ENCODED_SIZE: usize = 64;
const MAX_LENGTH: usize = ENCODED_SIZE - 17;

type Encoded = [u8;ENCODED_SIZE];

fn build_corrupted_data_error() -> Error {
    Error::new(ErrorKind::InvalidData, "corrupted data")
}

pub struct IdNameMap {
    next_id: u32,
    map: HashMap<u32, Encoded>,
    processor: Box<dyn CryptoProcessor>
}

impl IdNameMap {
    pub fn new(processor: Box<dyn CryptoProcessor>) -> IdNameMap {
        IdNameMap{next_id: 1, map: HashMap::new(), processor}
    }

    pub fn add(&mut self, value: String) -> Result<u32, Error> {
        let v = self.build_value(value)?;
        let id = self.next_id;
        self.map.insert(id, v);
        self.next_id += 1;
        Ok(id)
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
        let mut idx = 8;
        v[idx] = l as u8;
        idx += 1;
        let mut idx2 = 0;
        while idx2 < l {
            v[idx] = bytes[idx2];
            idx += 1;
            idx2 += 1;
        }
        Ok(self.processor.encode(v))
    }

    fn decode_value(&self, value: &Encoded) -> Result<String, Error> {
        let v = self.processor.decode(value);
        let l = v[8] as usize;
        if l > MAX_LENGTH {
            return Err(build_corrupted_data_error());
        }
        String::from_utf8(v[9..l+9].iter().map(|e|*e).collect())
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
            return Err(build_corrupted_data_error());
        }
        let mut buffer32 = [0u8; 4];
        let mut encoded = [0u8; ENCODED_SIZE];
        let s = source.as_slice();
        let mut idx = offset;
        buffer32.copy_from_slice(&s[idx..idx + 4]);
        let mut l = u32::from_le_bytes(buffer32);
        idx += 4;
        while l > 0 {
            if idx + 4 + ENCODED_SIZE > sl {
                return Err(build_corrupted_data_error());
            }
            buffer32.copy_from_slice(&s[idx..idx + 4]);
            let key = u32::from_le_bytes(buffer32);
            if self.map.contains_key(&key) {
                return Err(build_corrupted_data_error());
            }
            if key >= self.next_id {
                self.next_id = key + 1;
            }
            idx += 4;
            encoded.copy_from_slice(&s[idx..idx + ENCODED_SIZE]);
            idx += ENCODED_SIZE;
            self.map.insert(key, encoded);
            l -= 1;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Error;
    use rand::RngCore;
    use rand::rngs::OsRng;
    use crate::crypto::AesProcessor;
    use crate::pman::id_name_map::IdNameMap;

    #[test]
    fn test_id_name_map() -> Result<(), Error> {
        let mut key = [0u8;32];
        OsRng.fill_bytes(&mut key);
        let mut iv = [0u8;16];
        OsRng.fill_bytes(&mut iv);
        let mut map = IdNameMap::new(AesProcessor::new(key, iv));
        let idx = map.add("test".to_string())?;
        map.set(idx, "test2".to_string())?;
        map.remove(idx)?;
        let idx2 = map.add("test2".to_string())?;
        let idx3 = map.add("test3".to_string())?;
        let mut v = Vec::new();
        map.save(&mut v);
        let mut map2 = IdNameMap::new(AesProcessor::new(key, iv));
        map2.load(&v, 0)?;
        assert_eq!(map2.map.len(), map.map.len());
        assert_eq!(map2.next_id, map.next_id);
        let v2 = map2.get(idx2)?;
        assert_eq!(v2, "test2".to_string());
        let v3 = map2.get(idx3)?;
        assert_eq!(v3, "test3".to_string());
        Ok(())
    }
}