use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::marker::PhantomData;
use std::sync::Arc;
use uniffi::deps::bytes::BufMut;
use crate::crypto::{build_corrupted_data_error, CryptoProcessor};

pub trait ByteValue {
    fn from_bytes(source: Vec<u8>) -> Result<Box<Self>, Error>;
    fn to_bytes(&self) -> Vec<u8>;
}

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

pub struct IdValueMap<T> {
    next_id: u32,
    map: HashMap<u32, Vec<u8>>,
    processor: Arc<dyn CryptoProcessor>,
    phantom: PhantomData<T>
}

impl<T: ByteValue> IdValueMap<T> {
    pub fn new(processor: Arc<dyn CryptoProcessor>) -> IdValueMap<T> {
        IdValueMap{next_id: 1, map: HashMap::new(), processor, phantom: Default::default()}
    }

    pub fn add(&mut self, value: T) -> u32 {
        let v = self.processor.encode(value.to_bytes());
        let id = self.next_id;
        self.map.insert(id, v);
        self.next_id += 1;
        id
    }

    pub fn add_with_id(&mut self, id: u32, value: T) -> Result<(), Error> {
        if self.map.contains_key(&id) {
            return Err(Error::new(ErrorKind::InvalidInput, "record already exists"));
        }
        let v = self.processor.encode(value.to_bytes());
        self.map.insert(id, v);
        if id >= self.next_id {
            self.next_id = id + 1;
        }
        Ok(())
    }

    pub fn set(&mut self, id: u32, value: T) -> Result<(), Error> {
        self.exists(id)?;
        let v = self.processor.encode(value.to_bytes());
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

    pub fn get(&self, id: u32) -> Result<T, Error> {
        self.exists(id)?;
        let v = self.map.get(&id).unwrap();
        let decoded = self.processor.decode(v)?;
        let value = T::from_bytes(decoded)?;
        Ok(*value)
    }

    pub fn save(&self, output: &mut Vec<u8>) {
        output.put_u32_le(self.map.len() as u32);
        for (key, value) in &self.map {
            output.put_u32_le(*key);
            output.put_u32_le(value.len() as u32);
            output.put_slice(value);
        }
    }

    pub fn load(&mut self, source: &Vec<u8>, offset: usize) -> Result<usize, Error> {
        if !self.map.is_empty() {
            return Err(Error::new(ErrorKind::PermissionDenied, "map is not empty"))
        }
        let sl = source.len();
        if offset + 4 > sl {
            return Err(build_corrupted_data_error());
        }
        // reading map length
        let mut buffer32 = [0u8; 4];
        let mut idx = offset;
        buffer32.copy_from_slice(&source[idx..idx + 4]);
        let mut l = u32::from_le_bytes(buffer32);
        idx += 4;
        while l > 0 {
            if idx + 8 > sl { // 4 for key + 4 for value length
                return Err(build_corrupted_data_error());
            }
            //reading key
            buffer32.copy_from_slice(&source[idx..idx + 4]);
            idx += 4;
            let key = u32::from_le_bytes(buffer32);
            if self.map.contains_key(&key) {
                return Err(build_corrupted_data_error());
            }
            // reading value length
            buffer32.copy_from_slice(&source[idx..idx + 4]);
            idx += 4;
            let value_length = u32::from_le_bytes(buffer32) as usize;
            if idx + value_length > sl {
                return Err(build_corrupted_data_error());
            }
            // reading value
            let value = source[idx..idx+value_length].to_vec();
            idx += value_length;
            self.map.insert(key, value);
            if key >= self.next_id {
                self.next_id = key + 1;
            }
            l -= 1;
        }
        Ok(idx)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Error;
    use rand::RngCore;
    use rand::rngs::OsRng;
    use crate::crypto::AesProcessor;
    use crate::pman::id_value_map::IdValueMap;

    #[test]
    fn test_id_name_map() -> Result<(), Error> {
        let mut key = [0u8;32];
        OsRng.fill_bytes(&mut key);
        let mut map: IdValueMap<String> = IdValueMap::new(AesProcessor::new(key));
        let idx = map.add("test".to_string());
        map.set(idx, "test2".to_string())?;
        map.remove(idx)?;
        let s2 = "test2".to_string();
        let s3 = "test3dmbfjsdhfgjsdgdfjsdgfjdsagfjsdgfjsguweyrtq  uieydhz`kjvbadfkulghewiurthkghfvkzjxviugrthiertfbdert".to_string();
        let idx2 = map.add(s2.clone());
        let idx3 = map.add(s3.clone());
        let mut v = Vec::new();
        map.save(&mut v);
        let mut map2: IdValueMap<String> = IdValueMap::new(AesProcessor::new(key));
        let end = map2.load(&v, 0)?;
        assert_eq!(end, v.len());
        assert_eq!(map2.map.len(), map.map.len());
        assert_eq!(map2.next_id, map.next_id);
        let v2 = map2.get(idx2)?;
        assert_eq!(v2, s2);
        let v3 = map2.get(idx3)?;
        assert_eq!(v3, s3);
        Ok(())
    }
}